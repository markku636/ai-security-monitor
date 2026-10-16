//! Linux 套件查 OSV（https://osv.dev，Google 維護，涵蓋 Debian／Ubuntu／Alpine／Rocky／Alma 公告）。
//! querybatch 只回漏洞 id，再取 id 的細節（CVE 別名、嚴重度）；結果快取 24 小時，`asa watch` 不會每 10 分鐘打一次。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::inventory::{Inventory, OsInfo};
use crate::error::{AppError, AppResult};
use crate::store;

pub const API: &str = "https://api.osv.dev/v1";
pub const CACHE_FILE: &str = "vuln/osv-result.json";
pub const CACHE_HOURS: i64 = 24;
pub const MAX_DETAILS: usize = 300;

/// os-release → OSV ecosystem 名稱；不支援的發行版回 None。
pub fn ecosystem(os: &OsInfo) -> Option<String> {
    let ver = os.distro_version.clone().unwrap_or_default();
    let major = ver.split('.').next().unwrap_or("").to_string();
    match os.distro.as_deref()? {
        "debian" if !major.is_empty() => Some(format!("Debian:{major}")),
        "ubuntu" if !ver.is_empty() => {
            // 偶數年的 .04 是 LTS
            let lts = ver.ends_with(".04")
                && ver
                    .split('.')
                    .next()
                    .and_then(|y| y.parse::<u32>().ok())
                    .map(|y| y % 2 == 0)
                    .unwrap_or(false);
            Some(if lts {
                format!("Ubuntu:{ver}:LTS")
            } else {
                format!("Ubuntu:{ver}")
            })
        }
        "alpine" => {
            let mm: Vec<&str> = ver.split('.').take(2).collect();
            (mm.len() == 2).then(|| format!("Alpine:v{}", mm.join(".")))
        }
        "rocky" if !major.is_empty() => Some(format!("Rocky Linux:{major}")),
        "almalinux" if !major.is_empty() => Some(format!("AlmaLinux:{major}")),
        _ => None,
    }
}

/// 要查的 (名稱, 版本)：dpkg 用原始碼套件，去重。
pub fn queries(inv: &Inventory) -> Vec<(String, String)> {
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();
    for p in &inv.packages {
        let (n, v) = match (&p.source, &p.source_version) {
            (Some(s), Some(sv)) => (s.clone(), sv.clone()),
            (Some(s), None) => (s.clone(), p.version.clone()),
            _ => (p.name.clone(), p.version.clone()),
        };
        set.insert((n, v));
    }
    set.into_iter().collect()
}

pub fn parse_batch(v: &Value) -> Vec<Vec<String>> {
    v["results"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|r| {
                    r["vulns"]
                        .as_array()
                        .map(|vs| vs.iter().filter_map(|x| x["id"].as_str().map(String::from)).collect())
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VulnInfo {
    pub cves: Vec<String>,
    pub summary: String,
    /// critical | high | medium | low
    pub severity: String,
}

/// 由 OSV 漏洞 JSON 取 CVE 別名與粗略嚴重度。
pub fn parse_vuln(v: &Value) -> VulnInfo {
    let mut cves: Vec<String> = v["aliases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a.as_str())
        .filter(|a| a.starts_with("CVE-"))
        .map(String::from)
        .collect();
    if let Some(id) = v["id"].as_str().filter(|i| i.starts_with("CVE-")) {
        cves.push(id.to_string());
    }
    cves.sort();
    cves.dedup();
    let mut sev = v["database_specific"]["severity"]
        .as_str()
        .map(|s| s.to_ascii_lowercase());
    for s in v["severity"].as_array().into_iter().flatten() {
        let score = s["score"].as_str().unwrap_or("");
        match s["type"].as_str() {
            Some("Ubuntu") => sev = Some(score.to_ascii_lowercase()),
            Some(t) if t.starts_with("CVSS") && sev.is_none() => {
                // 網路可達、免權限、免互動且影響機密或完整性 → 高
                let net = score.contains("AV:N") && score.contains("PR:N");
                let impact = score.contains("C:H") || score.contains("I:H");
                sev = Some(if net && impact { "high" } else { "medium" }.into());
            }
            _ => {}
        }
    }
    let severity = match sev.as_deref() {
        Some("critical") => "critical",
        Some("high") => "high",
        Some("low") | Some("negligible") | Some("untriaged") => "low",
        _ => "medium",
    };
    VulnInfo {
        cves,
        summary: crate::util::text::clip(v["summary"].as_str().or(v["details"].as_str()).unwrap_or(""), 200),
        severity: severity.into(),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvPackage {
    pub name: String,
    pub version: String,
    pub ids: Vec<String>,
    pub cves: Vec<String>,
    pub severity: String,
    #[serde(default)]
    pub kev: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OsvResult {
    pub ecosystem: String,
    pub queried: u32,
    pub at: Option<DateTime<Utc>>,
    pub key: String,
    pub packages: Vec<OsvPackage>,
    #[serde(default)]
    pub notes: Vec<String>,
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn cache_key(eco: &str, qs: &[(String, String)]) -> String {
    let joined: String = qs.iter().map(|(n, v)| format!("{n}={v};")).collect();
    crate::util::hash::sha256_hex(format!("{eco}|{joined}").as_bytes())[..16].to_string()
}

/// 查（或用快取）。網路錯誤回 Err，呼叫端轉成 warning。
pub async fn scan(
    config_dir: &Path,
    inv: &Inventory,
    base: &str,
    is_kev: &(dyn Fn(&str) -> bool + Sync),
) -> AppResult<Option<OsvResult>> {
    let Some(eco) = ecosystem(&inv.os) else { return Ok(None) };
    let qs = queries(inv);
    if qs.is_empty() {
        return Ok(None);
    }
    let key = cache_key(&eco, &qs);
    if let Ok(Some(c)) = store::read_json_opt::<OsvResult>(config_dir, CACHE_FILE) {
        if c.key == key
            && c.at
                .map(|t| (Utc::now() - t).num_hours() < CACHE_HOURS)
                .unwrap_or(false)
        {
            return Ok(Some(c));
        }
    }
    let http = reqwest::Client::builder()
        .user_agent(format!("asa/{}", crate::VERSION))
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError::External(e.to_string()))?;
    let mut ids_per: Vec<Vec<String>> = Vec::new();
    for chunk in qs.chunks(1000) {
        let body = json!({ "queries": chunk.iter().map(|(n, v)| json!({ "package": { "name": n, "ecosystem": eco }, "version": v })).collect::<Vec<_>>() });
        let r = http
            .post(format!("{base}/querybatch"))
            .json(&body)
            .send()
            .await
            .map_err(|e| AppError::External(tf!("OSV 查詢失敗：{e}", e = e)))?;
        if !r.status().is_success() {
            return Err(AppError::External(tf!(
                "OSV 回應 HTTP {status}",
                status = r.status().as_u16()
            )));
        }
        let v: Value = r.json().await.map_err(|e| AppError::External(e.to_string()))?;
        ids_per.extend(parse_batch(&v));
    }
    // 細節（CVE、嚴重度），去重後最多 MAX_DETAILS 筆
    let mut uniq: Vec<String> = ids_per
        .iter()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut notes = Vec::new();
    if uniq.len() > MAX_DETAILS {
        notes.push(format!(
            "{} OSV advisories; details fetched for the first {MAX_DETAILS}",
            uniq.len()
        ));
        uniq.truncate(MAX_DETAILS);
    }
    let mut details: HashMap<String, VulnInfo> = HashMap::new();
    // 一次 8 個併發
    for chunk in uniq.chunks(8) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|id| {
                let http = http.clone();
                let url = format!("{base}/vulns/{id}");
                let id = id.clone();
                tokio::spawn(async move {
                    let v: Option<Value> = match http.get(url).send().await {
                        Ok(r) if r.status().is_success() => r.json().await.ok(),
                        _ => None,
                    };
                    (id, v.map(|v| parse_vuln(&v)))
                })
            })
            .collect();
        for h in handles {
            if let Ok((id, Some(info))) = h.await {
                details.insert(id, info);
            }
        }
    }
    let mut packages: Vec<OsvPackage> = Vec::new();
    for ((name, version), ids) in qs.iter().zip(ids_per.iter()) {
        if ids.is_empty() {
            continue;
        }
        let mut cves: BTreeSet<String> = BTreeSet::new();
        let mut sev = "low".to_string();
        let mut summary = String::new();
        for id in ids {
            if let Some(d) = details.get(id) {
                cves.extend(d.cves.iter().cloned());
                if sev_rank(&d.severity) > sev_rank(&sev) {
                    sev = d.severity.clone();
                    summary = d.summary.clone();
                }
            } else if sev_rank("medium") > sev_rank(&sev) {
                sev = "medium".into();
            }
        }
        let kev: Vec<String> = cves.iter().filter(|c| is_kev(c)).cloned().collect();
        if !kev.is_empty() {
            sev = "critical".into();
        }
        packages.push(OsvPackage {
            name: name.clone(),
            version: version.clone(),
            ids: ids.clone(),
            cves: cves.into_iter().collect(),
            severity: sev,
            kev,
            summary,
        });
    }
    packages.sort_by(|a, b| {
        sev_rank(&b.severity)
            .cmp(&sev_rank(&a.severity))
            .then(b.ids.len().cmp(&a.ids.len()))
            .then(a.name.cmp(&b.name))
    });
    let res = OsvResult {
        ecosystem: eco,
        queried: qs.len() as u32,
        at: Some(Utc::now()),
        key,
        packages,
        notes,
    };
    store::ensure_dir(&config_dir.join("vuln"))?;
    let _ = store::write_json_compact_in(config_dir, CACHE_FILE, &res);
    Ok(Some(res))
}

/// 依嚴重度分組計數（摘要用）。
pub fn counts(r: &OsvResult) -> BTreeMap<String, u32> {
    let mut m = BTreeMap::new();
    for p in &r.packages {
        *m.entry(p.severity.clone()).or_default() += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(id: &str, ver: &str) -> OsInfo {
        OsInfo {
            family: "linux".into(),
            distro: Some(id.into()),
            distro_version: Some(ver.into()),
            ..Default::default()
        }
    }

    #[test]
    fn ecosystems() {
        assert_eq!(ecosystem(&os("ubuntu", "24.04")).as_deref(), Some("Ubuntu:24.04:LTS"));
        assert_eq!(ecosystem(&os("ubuntu", "25.04")).as_deref(), Some("Ubuntu:25.04"));
        assert_eq!(ecosystem(&os("debian", "12")).as_deref(), Some("Debian:12"));
        assert_eq!(ecosystem(&os("alpine", "3.20.3")).as_deref(), Some("Alpine:v3.20"));
        assert_eq!(ecosystem(&os("rocky", "9.4")).as_deref(), Some("Rocky Linux:9"));
        assert_eq!(ecosystem(&os("arch", "rolling")), None);
    }

    #[test]
    fn parses_batch_and_vulns() {
        let b = json!({ "results": [ { "vulns": [ { "id": "USN-1" }, { "id": "CVE-2024-1" } ] }, {} ] });
        assert_eq!(
            parse_batch(&b),
            vec![vec!["USN-1".to_string(), "CVE-2024-1".into()], vec![]]
        );
        let v = parse_vuln(
            &json!({ "id": "USN-7000-1", "aliases": ["CVE-2024-6387", "GHSA-x"], "summary": "openssh regression", "severity": [{ "type": "Ubuntu", "score": "high" }] }),
        );
        assert_eq!(
            v,
            VulnInfo {
                cves: vec!["CVE-2024-6387".into()],
                summary: "openssh regression".into(),
                severity: "high".into()
            }
        );
        let c = parse_vuln(
            &json!({ "id": "CVE-2023-1", "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }),
        );
        assert_eq!((c.cves.len(), c.severity.as_str()), (1, "high"));
        assert_eq!(parse_vuln(&json!({ "id": "DSA-1" })).severity, "medium");
    }

    #[test]
    fn scan_uses_the_api_and_caches() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (url, cap) = crate::hub::test_server::serve(vec![
                // 查詢依名稱排序：bash 在前、openssh 在後
                (200, r#"{"results":[{},{"vulns":[{"id":"USN-1"}]}]}"#.into()),
                (200, r#"{"id":"USN-1","aliases":["CVE-2024-6387"],"summary":"regreSSHion","severity":[{"type":"Ubuntu","score":"high"}]}"#.into()),
            ])
            .await;
            let d = tempfile::tempdir().unwrap();
            let inv = Inventory {
                os: os("ubuntu", "24.04"),
                packages: super::super::inventory::parse_dpkg("openssh-server\t1:9.6p1-3ubuntu13\topenssh\t1:9.6p1-3ubuntu13\nbash\t5.2-1\tbash\t5.2-1\n"),
                ..Default::default()
            };
            let r = scan(d.path(), &inv, &url, &|c| c == "CVE-2024-6387").await.unwrap().unwrap();
            assert_eq!(r.ecosystem, "Ubuntu:24.04:LTS");
            assert_eq!(r.packages.len(), 1);
            assert_eq!(r.packages[0].name, "openssh");
            assert_eq!(r.packages[0].severity, "critical");
            assert_eq!(r.packages[0].kev, vec!["CVE-2024-6387".to_string()]);
            let reqs = cap.lock().unwrap().clone();
            assert!(reqs[0].head.starts_with("POST /querybatch"));
            let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
            assert_eq!(body["queries"][0]["package"]["ecosystem"], "Ubuntu:24.04:LTS");
            // 第二次：用快取，不再打網路（測試伺服器已經沒有回應可給）
            let again = scan(d.path(), &inv, &url, &|_| false).await.unwrap().unwrap();
            assert_eq!(again.packages[0].kev.len(), 1);
        });
    }
}

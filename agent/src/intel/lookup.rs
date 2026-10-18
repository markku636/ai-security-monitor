//! 線上名譽查詢（需使用者自備 API key，預設不啟用）：AbuseIPDB、GreyNoise Community、CrowdSec CTI。
//! 結果快取 24 小時（`<config>/state/reputation-cache.json`），並有每日呼叫上限避免燒光免費額度。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::registry::Registry;
use crate::error::{AppError, AppResult};
use crate::secrets::SecretStore;
use crate::store;

pub const CACHE_FILE: &str = "state/reputation-cache.json";
const TTL_SECS: i64 = 24 * 3600;
const KEEP_SECS: i64 = 7 * 24 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Reputation {
    pub provider: String,
    /// 0–100，越高越惡意。
    pub score: u8,
    pub detail: String,
}

pub struct Provider {
    pub id: &'static str,
    pub url: &'static str,
    pub key_header: &'static str,
    pub daily_quota: u32,
    pub parse: fn(&Value) -> Option<Reputation>,
}

pub fn parse_abuseipdb(v: &Value) -> Option<Reputation> {
    let d = &v["data"];
    let score = d["abuseConfidenceScore"].as_u64()?.min(100) as u8;
    Some(Reputation {
        provider: "abuseipdb".into(),
        score,
        detail: format!(
            "reports={} isp={} usage={} country={}",
            d["totalReports"].as_u64().unwrap_or(0),
            d["isp"].as_str().unwrap_or("-"),
            d["usageType"].as_str().unwrap_or("-"),
            d["countryCode"].as_str().unwrap_or("-")
        ),
    })
}

pub fn parse_greynoise(v: &Value) -> Option<Reputation> {
    let class = v["classification"].as_str().unwrap_or("unknown");
    let riot = v["riot"].as_bool().unwrap_or(false);
    let noise = v["noise"].as_bool().unwrap_or(false);
    let score = match class {
        "malicious" => 90,
        "benign" => 0,
        _ if riot => 0,
        _ if noise => 45,
        _ => 20,
    };
    Some(Reputation {
        provider: "greynoise-community".into(),
        score,
        detail: format!(
            "classification={class} noise={noise} riot={riot} name={}",
            v["name"].as_str().unwrap_or("-")
        ),
    })
}

pub fn parse_crowdsec(v: &Value) -> Option<Reputation> {
    let rep = v["reputation"].as_str()?;
    let score = match rep {
        "malicious" => 85,
        "suspicious" => 55,
        "known" => 30,
        "safe" | "benign" => 0,
        _ => return None,
    };
    let behaviors: Vec<&str> = v["behaviors"]
        .as_array()
        .map(|a| a.iter().filter_map(|b| b["label"].as_str()).take(4).collect())
        .unwrap_or_default();
    Some(Reputation {
        provider: "crowdsec-cti".into(),
        score,
        detail: format!("reputation={rep} behaviors={}", behaviors.join(",")),
    })
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "abuseipdb",
        url: "https://api.abuseipdb.com/api/v2/check",
        key_header: "Key",
        daily_quota: 900,
        parse: parse_abuseipdb,
    },
    Provider {
        id: "greynoise-community",
        url: "https://api.greynoise.io/v3/community/{ip}",
        key_header: "key",
        daily_quota: 45,
        parse: parse_greynoise,
    },
    Provider {
        id: "crowdsec-cti",
        url: "https://cti.api.crowdsec.net/v2/smoke/{ip}",
        key_header: "x-api-key",
        daily_quota: 45,
        parse: parse_crowdsec,
    },
];

/// API key：環境變數（registry 的 `requires_api_key`）＞ 密鑰庫 `intel.<id>`。
pub fn api_key(config_dir: &Path, reg: &Registry, id: &str) -> Option<String> {
    // 免費版只限非商業用途的服務（AbuseIPDB、GreyNoise…）：商用情境不查
    let entry = reg.get(id).filter(|e| reg.license_ok(e))?;
    if let Some(env) = &entry.requires_api_key {
        if let Ok(v) = std::env::var(env) {
            if !v.trim().is_empty() {
                return Some(v.trim().to_string());
            }
        }
    }
    SecretStore::open(config_dir).get(&format!("intel.{id}")).ok().flatten()
}

pub fn configured_providers(config_dir: &Path, reg: &Registry) -> Vec<&'static str> {
    PROVIDERS
        .iter()
        .filter(|p| api_key(config_dir, reg, p.id).is_some())
        .map(|p| p.id)
        .collect()
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Cached {
    at: i64,
    rep: Option<Reputation>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RepCache {
    #[serde(default)]
    entries: BTreeMap<String, Cached>,
    #[serde(default)]
    quota: BTreeMap<String, u32>,
}

async fn query(client: &reqwest::Client, p: &Provider, key: &str, ip: IpAddr) -> AppResult<Option<Reputation>> {
    let url = p.url.replace("{ip}", &ip.to_string());
    let mut req = client
        .get(&url)
        .header(p.key_header, key)
        .header("Accept", "application/json");
    if p.id == "abuseipdb" {
        req = req.query(&[("ipAddress", ip.to_string()), ("maxAgeInDays", "90".to_string())]);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| AppError::Intel(tf!("{provider} 查詢失敗：{e}", provider = p.id, e = e)))?;
    match resp.status().as_u16() {
        404 => return Ok(None),
        401 | 403 => return Err(AppError::Intel(tf!("{provider} 拒絕了 API key", provider = p.id))),
        429 => return Err(AppError::Intel(tf!("{provider} 已達呼叫上限", provider = p.id))),
        s if !(200..300).contains(&s) => {
            return Err(AppError::Intel(tf!(
                "{provider} 回應 HTTP {status}",
                provider = p.id,
                status = s
            )))
        }
        _ => {}
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| AppError::Intel(tf!("{provider} 回應格式錯誤：{e}", provider = p.id, e = e)))?;
    Ok((p.parse)(&v))
}

/// 查一個 IP 的線上名譽（只用已設定 key 的服務）。回傳 (結果, 警告)。
pub async fn lookup_ip(config_dir: &Path, reg: &Registry, ip: IpAddr) -> (Vec<Reputation>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    let providers: Vec<(&Provider, String)> = PROVIDERS
        .iter()
        .filter_map(|p| api_key(config_dir, reg, p.id).map(|k| (p, k)))
        .collect();
    if providers.is_empty() {
        return (out, warnings);
    }
    let client = match super::fetch::http_client() {
        Ok(c) => c,
        Err(e) => {
            warnings.push(e.message());
            return (out, warnings);
        }
    };
    let mut cache: RepCache = store::read_json_in(config_dir, CACHE_FILE).unwrap_or_default();
    let now = Utc::now();
    let today = now.format("%Y-%m-%d").to_string();
    for (p, key) in providers {
        let ck = format!("{}|{ip}", p.id);
        if let Some(c) = cache.entries.get(&ck) {
            if now.timestamp() - c.at < TTL_SECS {
                if let Some(r) = &c.rep {
                    out.push(r.clone());
                }
                continue;
            }
        }
        let qk = format!("{}|{today}", p.id);
        let used = cache.quota.get(&qk).copied().unwrap_or(0);
        if used >= p.daily_quota {
            warnings.push(tf!("{provider} 今日查詢額度已用完（{n}）", provider = p.id, n = used));
            continue;
        }
        match query(&client, p, &key, ip).await {
            Ok(rep) => {
                *cache.quota.entry(qk).or_insert(0) += 1;
                if let Some(r) = &rep {
                    out.push(r.clone());
                }
                cache.entries.insert(
                    ck,
                    Cached {
                        at: now.timestamp(),
                        rep,
                    },
                );
            }
            Err(e) => warnings.push(e.message()),
        }
    }
    cache.entries.retain(|_, c| now.timestamp() - c.at < KEEP_SECS);
    cache.quota.retain(|k, _| k.ends_with(&today));
    let _ = store::ensure_dir(&config_dir.join("state"));
    let _ = store::write_json_compact_in(config_dir, CACHE_FILE, &cache);
    (out, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_provider_payloads() {
        let a = parse_abuseipdb(&json!({"data":{"abuseConfidenceScore":87,"totalReports":42,"isp":"Evil ISP","usageType":"Data Center","countryCode":"NL"}})).unwrap();
        assert_eq!(a.score, 87);
        assert!(a.detail.contains("reports=42"));
        assert_eq!(
            parse_greynoise(&json!({"classification":"malicious","noise":true,"riot":false,"name":"x"}))
                .unwrap()
                .score,
            90
        );
        assert_eq!(
            parse_greynoise(&json!({"classification":"unknown","noise":false,"riot":true}))
                .unwrap()
                .score,
            0
        );
        assert_eq!(
            parse_crowdsec(&json!({"reputation":"suspicious","behaviors":[{"label":"SSH Bruteforce"}]}))
                .unwrap()
                .score,
            55
        );
        assert!(parse_crowdsec(&json!({"reputation":"unknown"})).is_none());
        assert!(parse_abuseipdb(&json!({"errors":[]})).is_none());
    }

    #[tokio::test]
    async fn no_keys_means_no_calls() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(crate::secrets::ENV_BACKEND, "file");
        let reg = Registry::load(dir.path()).unwrap();
        let (r, w) = lookup_ip(dir.path(), &reg, "8.8.8.8".parse().unwrap()).await;
        assert!(r.is_empty() && w.is_empty());
        assert!(configured_providers(dir.path(), &reg).is_empty());
    }
}

//! 自動更新：查 GitHub Release（或 `ASA_UPDATE_URL` 指定的鏡像），下載這個平台的執行檔，
//! 比對 `SHA256SUMS` 後原地替換。Windows 正在執行的 exe 不能覆寫，但可以改名：舊檔改成 `asa.exe.old-<時間>`，下次更新時清掉。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};

pub const RELEASES_API: &str = "https://api.github.com/repos/markku636/ai-security-agent/releases";
pub const ENV_UPDATE_URL: &str = "ASA_UPDATE_URL";
pub const SUMS_FILE: &str = "SHA256SUMS";
/// 執行檔大小上限（防止鏡像給錯檔）。
pub const MAX_BINARY: usize = 200 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Release {
    pub tag: String,
    pub version: String,
    pub html_url: String,
    pub published_at: Option<String>,
    pub assets: Vec<Asset>,
}

pub fn base_url() -> String {
    std::env::var(ENV_UPDATE_URL)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
        .unwrap_or_else(|| RELEASES_API.to_string())
}

/// Release 資產的平台後綴（與 release.yml 的命名一致）。
pub fn target_suffix(os: &str, arch: &str) -> Option<&'static str> {
    Some(match (os, arch) {
        ("windows", "x86_64") => "windows-x64.exe",
        ("windows", "aarch64") => "windows-arm64.exe",
        ("macos", "aarch64") => "macos-arm64",
        ("macos", "x86_64") => "macos-x64",
        ("linux", "x86_64") => "linux-x64",
        ("linux", "aarch64") => "linux-arm64",
        _ => return None,
    })
}

pub fn asset_name(version: &str, os: &str, arch: &str) -> Option<String> {
    target_suffix(os, arch).map(|s| format!("asa-{version}-{s}"))
}

pub fn parse_release(v: &Value) -> Option<Release> {
    let tag = v["tag_name"].as_str()?.to_string();
    Some(Release {
        version: tag.trim_start_matches('v').to_string(),
        tag,
        html_url: v["html_url"].as_str().unwrap_or("").to_string(),
        published_at: v["published_at"].as_str().map(str::to_string),
        assets: v["assets"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        Some(Asset {
                            name: x["name"].as_str()?.to_string(),
                            url: x["browser_download_url"].as_str()?.to_string(),
                            size: x["size"].as_u64().unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// `sha256sum` 格式：`<hex>  <name>` 或 `<hex> *<name>`。
pub fn parse_sums(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let hash = it.next()?;
            let name = it.next()?.trim_start_matches('*');
            (hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()))
                .then(|| (name.to_string(), hash.to_ascii_lowercase()))
        })
        .collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// latest 比 current 新（rc／beta 視為較舊）。
pub fn is_newer(latest: &str, current: &str) -> bool {
    crate::vuln::version::compare(latest, current) == std::cmp::Ordering::Greater
}

fn http() -> AppResult<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("asa/{}", crate::VERSION))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| AppError::Update(e.to_string()))
}

async fn get(client: &reqwest::Client, url: &str, max: usize) -> AppResult<Vec<u8>> {
    match get_status(client, url, max).await? {
        (200..=299, b) => Ok(b),
        (status, _) => Err(AppError::Update(format!("{url}: HTTP {status}"))),
    }
}

async fn get_status(client: &reqwest::Client, url: &str, max: usize) -> AppResult<(u16, Vec<u8>)> {
    let r = client
        .get(url)
        .header(
            "accept",
            "application/vnd.github+json, application/octet-stream;q=0.9, */*;q=0.8",
        )
        .send()
        .await
        .map_err(|e| AppError::Update(format!("{url}: {e}")))?;
    let status = r.status().as_u16();
    let bytes = r.bytes().await.map_err(|e| AppError::Update(format!("{url}: {e}")))?;
    if bytes.len() > max {
        return Err(AppError::Update(tf!("{url} 超過大小上限", url = url)));
    }
    Ok((status, bytes.to_vec()))
}

/// 最新版（或指定版本）的 Release。
pub async fn fetch_release(base: &str, version: Option<&str>) -> AppResult<Release> {
    let url = match version {
        Some(v) => format!("{base}/tags/v{}", v.trim_start_matches('v')),
        None => format!("{base}/latest"),
    };
    let body = match get_status(&http()?, &url, 4 * 1024 * 1024).await? {
        (200..=299, b) => b,
        (404, _) => {
            return Err(AppError::Update(match version {
                Some(v) => tf!("找不到版本 {v}（{url}）", v = v, url = url),
                None => tf!("還沒有發佈任何版本（{url}）", url = url),
            }))
        }
        (status, _) => return Err(AppError::Update(format!("{url}: HTTP {status}"))),
    };
    let v: Value = serde_json::from_slice(&body).map_err(|e| AppError::Update(format!("{url}: {e}")))?;
    parse_release(&v).ok_or_else(|| AppError::Update(tf!("{url} 不是 Release 資料", url = url)))
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub current: String,
    pub latest: String,
    pub newer: bool,
    pub asset: Option<Asset>,
    pub release_url: String,
}

pub fn check_release(r: &Release, current: &str) -> UpdateCheck {
    let name = asset_name(&r.version, std::env::consts::OS, std::env::consts::ARCH);
    UpdateCheck {
        current: current.to_string(),
        latest: r.version.clone(),
        newer: is_newer(&r.version, current),
        asset: name.and_then(|n| r.assets.iter().find(|a| a.name == n).cloned()),
        release_url: r.html_url.clone(),
    }
}

/// 下載並驗證這個平台的執行檔；回傳內容與 SHA256。
pub async fn download_verified(r: &Release, asset: &Asset) -> AppResult<(Vec<u8>, String)> {
    let client = http()?;
    let sums = r
        .assets
        .iter()
        .find(|a| a.name == SUMS_FILE)
        .ok_or_else(|| AppError::Update(tf!("Release {tag} 沒有 SHA256SUMS，拒絕更新", tag = r.tag)))?;
    let sums = parse_sums(&String::from_utf8_lossy(&get(&client, &sums.url, 1024 * 1024).await?));
    let expected = sums
        .get(&asset.name)
        .ok_or_else(|| AppError::Update(tf!("SHA256SUMS 裡沒有 {name}", name = asset.name)))?;
    let bytes = get(&client, &asset.url, MAX_BINARY).await?;
    let actual = sha256_hex(&bytes);
    if &actual != expected {
        return Err(AppError::Update(tf!(
            "{name} 的 SHA256 不符（預期 {expected}，實際 {actual}），已放棄",
            name = asset.name,
            expected = expected,
            actual = actual
        )));
    }
    Ok((bytes, actual))
}

/// 以新內容取代執行檔；Windows 回傳改名後的舊檔路徑。
pub fn replace_exe(exe: &Path, bytes: &[u8]) -> AppResult<Option<PathBuf>> {
    let dir = exe
        .parent()
        .ok_or_else(|| AppError::Update(exe.display().to_string()))?;
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "asa".into());
    let tmp = dir.join(format!(".{name}.update-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&tmp, bytes).map_err(|e| {
        AppError::Update(tf!(
            "無法寫入 {dir}（{e}）；請用有權限的身分執行（例如 sudo asa self-update）",
            dir = dir.display(),
            e = e
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
        if let Err(e) = std::fs::rename(&tmp, exe) {
            let _ = std::fs::remove_file(&tmp);
            return Err(AppError::Update(e.to_string()));
        }
        Ok(None)
    }
    #[cfg(not(unix))]
    {
        let old = dir.join(format!("{name}.old-{}", chrono::Utc::now().format("%Y%m%d%H%M%S")));
        if let Err(e) = std::fs::rename(exe, &old) {
            let _ = std::fs::remove_file(&tmp);
            return Err(AppError::Update(e.to_string()));
        }
        if let Err(e) = std::fs::rename(&tmp, exe) {
            let _ = std::fs::rename(&old, exe);
            let _ = std::fs::remove_file(&tmp);
            return Err(AppError::Update(e.to_string()));
        }
        Ok(Some(old))
    }
}

/// 清掉之前更新留下的 `<exe>.old-*`（Windows；還在執行的會刪不掉，下次再試）。
pub fn cleanup_old(exe: &Path) -> usize {
    let (Some(dir), Some(name)) = (exe.parent(), exe.file_name()) else {
        return 0;
    };
    let prefix = format!("{}.old-", name.to_string_lossy());
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                .filter(|e| std::fs::remove_file(e.path()).is_ok())
                .count()
        })
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateOutcome {
    pub from: String,
    pub to: String,
    pub exe: PathBuf,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_file: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release_json(base: &str) -> String {
        let name =
            asset_name("0.9.0", std::env::consts::OS, std::env::consts::ARCH).unwrap_or_else(|| "asa-0.9.0-x".into());
        format!(
            r#"{{"tag_name":"v0.9.0","html_url":"https://github.com/markku636/ai-security-agent/releases/tag/v0.9.0","published_at":"2026-10-20T00:00:00Z",
               "assets":[{{"name":"{name}","browser_download_url":"{base}/dl/{name}","size":11}},{{"name":"SHA256SUMS","browser_download_url":"{base}/dl/SHA256SUMS","size":100}}]}}"#
        )
    }

    #[test]
    fn names_versions_and_sums() {
        assert_eq!(
            asset_name("0.2.0", "windows", "x86_64").as_deref(),
            Some("asa-0.2.0-windows-x64.exe")
        );
        assert_eq!(
            asset_name("0.2.0", "linux", "aarch64").as_deref(),
            Some("asa-0.2.0-linux-arm64")
        );
        assert!(asset_name("0.2.0", "freebsd", "x86_64").is_none());
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("0.10.0", "0.9.3"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.2.0-rc1", "0.2.0"));
        let sums = parse_sums("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  asa-0.2.0-linux-x64\nBAD line\n0000000000000000000000000000000000000000000000000000000000000000 *asa.exe\n");
        assert_eq!(sums.len(), 2);
        assert_eq!(sums["asa.exe"].len(), 64);
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn replace_and_cleanup() {
        let d = tempfile::tempdir().unwrap();
        let exe = d.path().join(if cfg!(windows) { "asa.exe" } else { "asa" });
        std::fs::write(&exe, b"old").unwrap();
        let old = replace_exe(&exe, b"new binary").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new binary");
        if cfg!(windows) {
            let old = old.unwrap();
            assert_eq!(std::fs::read(&old).unwrap(), b"old");
            assert_eq!(cleanup_old(&exe), 1);
            assert!(!old.exists());
        } else {
            assert!(old.is_none());
        }
        // 沒有殘留暫存檔
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn fetch_check_and_verify() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // 測試伺服器不看路徑、依序回應：Release JSON → SHA256SUMS → 執行檔
            let body = "new binary!";
            let name = asset_name("0.9.0", std::env::consts::OS, std::env::consts::ARCH)
                .unwrap_or_else(|| "asa-0.9.0-x".into());
            let sums = format!("{}  {name}\n", sha256_hex(body.as_bytes()));
            let (url, cap) = crate::hub::test_server::serve(vec![
                (200, release_json("BASE")),
                (200, sums.clone()),
                (200, body.to_string()),
            ])
            .await;
            let r = parse_release(&serde_json::from_str(&release_json(&url)).unwrap()).unwrap();
            let fetched = fetch_release(&url, None).await.unwrap();
            assert_eq!(fetched.version, "0.9.0");
            assert!(cap.lock().unwrap()[0].head.starts_with("GET /latest "));
            let c = check_release(&fetched, "0.1.0");
            assert!(c.newer);
            if target_suffix(std::env::consts::OS, std::env::consts::ARCH).is_none() {
                return;
            }
            assert_eq!(c.asset.as_ref().unwrap().name, name);
            let asset = r.assets.iter().find(|a| a.name == name).unwrap().clone();
            let (bytes, sha) = download_verified(&r, &asset).await.unwrap();
            assert_eq!(bytes, body.as_bytes());
            assert_eq!(sha, sha256_hex(body.as_bytes()));

            // 雜湊不符 → 拒絕
            let (url2, _) = crate::hub::test_server::serve(vec![
                (200, format!("{}  {name}\n", "0".repeat(64))),
                (200, body.to_string()),
            ])
            .await;
            let r2 = parse_release(&serde_json::from_str(&release_json(&url2)).unwrap()).unwrap();
            let a2 = r2.assets.iter().find(|a| a.name == name).unwrap().clone();
            assert!(download_verified(&r2, &a2)
                .await
                .unwrap_err()
                .message()
                .contains("SHA256"));
        });
    }
}

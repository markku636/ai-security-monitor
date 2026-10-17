//! 區網相關：這台電腦有沒有跑 Hub（有的話可以讓背景服務在區網廣播它）、立即掃描並上傳到 Hub。

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use asa_lib::config;
use asa_lib::hub::identity;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};

use crate::{err, AppState, CmdResult};

/// 這台電腦上的 Hub 常用的 port：docker compose 的 8088、開發用的 3000。
const LOCAL_PORTS: &[u16] = &[8088, 3000, 8090];

/// 私有網段的 IPv4（10/8、172.16/12、192.168/16），排除 loopback、link-local。
fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_private() && !ip.is_loopback() && !ip.is_link_local()
}

/// 推薦的區網 IP：192.168.x 優先，其次 10.x，最後 172.16–31（常是 Docker／WSL 的虛擬網卡）。
pub fn primary_lan_ip(ips: &[IpAddr]) -> Option<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = ips
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) if is_private_v4(v4) => Some(*v4),
            _ => None,
        })
        .collect();
    v.sort_by_key(|ip| match ip.octets() {
        [192, 168, ..] => 0,
        [10, ..] => 1,
        _ => 2,
    });
    v.first().copied()
}

/// 這台電腦有沒有跑 Hub（127.0.0.1 的身分端點有回應、簽章正確）；建議給區網的網址、背景服務的廣播狀態。
#[tauri::command]
pub async fn local_hub_status(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    let http = identity::http_client(Duration::from_secs(3)).map_err(err)?;
    let mut found: Option<(u16, identity::HubIdentity)> = None;
    for port in LOCAL_PORTS {
        if let Ok(Some(id)) = identity::fetch(&http, &format!("http://127.0.0.1:{port}")).await {
            found = Some((*port, id));
            break;
        }
    }
    let ips = asa_lib::cli::fw_cmd::local_ips();
    let lan = primary_lan_ip(&ips);
    let lan_ips: Vec<String> = ips
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) if is_private_v4(v4) => Some(v4.to_string()),
            _ => None,
        })
        .collect();
    let advertising = asa_lib::hub::advertise::load_state(dir).map(|(info, at)| {
        json!({
            "info": info,
            "at": at,
            // 背景服務每分鐘寫一次；太久沒寫＝背景服務沒在跑
            "stale": chrono::Utc::now() - at > chrono::Duration::minutes(5),
        })
    });
    Ok(json!({
        "found": found.is_some(),
        "port": found.as_ref().map(|f| f.0),
        "name": found.as_ref().map(|f| f.1.name.clone()),
        "fingerprint": found.as_ref().map(|f| f.1.fingerprint.clone()),
        "suggested_url": found.as_ref().zip(lan).map(|((port, _), ip)| format!("http://{ip}:{port}")),
        "lan_ips": lan_ips,
        "advertise_url": cfg.hub_advertise_url,
        "advertising": advertising,
        "background_running": !asa_lib::service::running_watchers(Some(dir)).is_empty(),
    }))
}

/// 開／關「讓區網裡的電腦找到這台的 Hub」：存成 hub.advertise_url，背景服務一分鐘內跟著開始或停止廣播。
/// 開之前先確認這個網址連得到、而且是這台電腦上的同一個 Hub（指紋相同）。
#[tauri::command]
pub async fn set_hub_advertise(state: State<'_, AppState>, url: Option<String>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let mut cfg = config::load_or_init(dir).map_err(err)?;
    let url = url
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty());
    if let Some(u) = &url {
        let http = identity::http_client(Duration::from_secs(5)).map_err(err)?;
        let id = identity::fetch(&http, u)
            .await
            .map_err(|e| {
                format!(
                    "用這個網址連不到 Hub：{}（Hub 只綁 127.0.0.1 的話，區網的電腦也連不到）",
                    e.message()
                )
            })?
            .ok_or_else(|| "這個 Hub 版本太舊，沒有身分端點，不能廣播".to_string())?;
        let mut local = None;
        for port in LOCAL_PORTS {
            if let Ok(Some(l)) = identity::fetch(&http, &format!("http://127.0.0.1:{port}")).await {
                local = Some(l);
                break;
            }
        }
        if let Some(l) = local {
            if !identity::same_fingerprint(&l.fingerprint, &id.fingerprint) {
                return Err(format!(
                    "這個網址的 Hub（指紋 {}）不是這台電腦上的 Hub（{}）",
                    id.fingerprint, l.fingerprint
                ));
            }
        }
    }
    config::set_value(&mut cfg, "hub.advertise_url", url.as_deref().unwrap_or("")).map_err(err)?;
    config::save(dir, &cfg).map_err(err)?;
    Ok(json!({
        "advertise_url": cfg.hub_advertise_url,
        "background_running": !asa_lib::service::running_watchers(Some(dir)).is_empty(),
    }))
}

/// 上次上傳、待重送的報告數（總覽頁）。
#[tauri::command]
pub async fn upload_status(state: State<'_, AppState>) -> CmdResult<Value> {
    let dir = &state.config_dir;
    let cfg = config::load_or_init(dir).map_err(err)?;
    let s = asa_lib::hub::watch::upload_state(dir);
    Ok(json!({
        "enrolled": cfg.hub.is_some(),
        "last_upload_at": s.last_upload_at(),
        "last_report_at": s.last_report_at,
        "last_error": s.last_error,
        "last_error_at": s.last_error_at,
        "pending": asa_lib::hub::outbox::list(dir).len(),
    }))
}

/// 「立即掃描並上傳到 Hub」：補送暫存報告、連線快照、完整掃描與報告、心跳；進度送到視窗的 `upload-progress`。
#[tauri::command]
pub async fn upload_now(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Value> {
    let env = state.env();
    let progress = move |m: &str| {
        let _ = app.emit("upload-progress", m);
    };
    let s = asa_lib::cli::upload_cmd::upload_now(&env, &progress)
        .await
        .map_err(err)?;
    Ok(json!({ "summary": s, "message": asa_lib::cli::upload_cmd::summary_line(&s) }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_a_sensible_lan_ip() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let list = [
            ip("172.17.0.1"),
            ip("127.0.0.1"),
            ip("10.1.2.3"),
            ip("192.168.1.20"),
            ip("8.8.8.8"),
        ];
        assert_eq!(primary_lan_ip(&list), Some("192.168.1.20".parse().unwrap()));
        assert_eq!(
            primary_lan_ip(&[ip("172.17.0.1"), ip("10.0.0.9")]),
            Some("10.0.0.9".parse().unwrap())
        );
        assert_eq!(primary_lan_ip(&[ip("169.254.1.1"), ip("::1")]), None);
    }
}

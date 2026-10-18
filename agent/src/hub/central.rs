//! Hub 集中設定：依主機群組推下來的一小組安全設定（掃描／快照間隔、檔案完整性監控、快照附網域），
//! 存在 `<設定目錄>/central.json`，使用時疊在本機設定上（不寫回 config.json，`config set` 不受影響）。
//!
//! - 來源要可信：Hub 用 Ed25519 身分簽「用途＋這台 agent＋版本＋設定 JSON」，用加入時釘選的 Hub 公鑰驗章；
//!   沒有釘選公鑰、驗不過、格式不對都不套用。
//! - 本機可拒收：`config set central_config false`。
//! - 不接受：效能蒐集、遠端動作、Hub 設定、任何指令（Hub 端也不提供）。

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::AgentConfig;
use crate::error::{AppError, AppResult};
use crate::store;

pub const FILE: &str = "central.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CentralValues {
    pub scan_interval: Option<String>,
    pub snapshot_interval: Option<String>,
    pub dns_names: Option<bool>,
    pub fim_enabled: Option<bool>,
    pub fim_extra_paths: Option<Vec<String>>,
    pub fim_ignore: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Central {
    pub version: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub config: CentralValues,
    pub applied_at: DateTime<Utc>,
}

/// 簽章內容（跟 Hub 的 `configMessage` 一致）。
pub fn message(agent_id: &str, version: &str, config_json: &str) -> String {
    format!("aism-central-config-v1\n{agent_id}\n{version}\n{config_json}")
}

pub fn load(dir: &Path) -> Option<Central> {
    store::read_json_opt(dir, FILE).ok().flatten()
}

pub fn current_version(dir: &Path) -> Option<String> {
    load(dir).map(|c| c.version)
}

fn dur_ok(v: &str, min_secs: u64) -> bool {
    humantime::parse_duration(v)
        .map(|d| d.as_secs() >= min_secs)
        .unwrap_or(false)
}

/// 把集中設定疊到設定上（只動這幾個欄位；不合理的值略過）。
pub fn apply_values(cfg: &mut AgentConfig, v: &CentralValues) {
    if let Some(s) = v.scan_interval.as_deref().filter(|s| dur_ok(s, 300)) {
        cfg.scan.interval = s.to_string();
    }
    if let Some(s) = v.snapshot_interval.as_deref().filter(|s| dur_ok(s, 30)) {
        cfg.scan.snapshot_interval = s.to_string();
    }
    if let Some(b) = v.dns_names {
        cfg.scan.dns_names = b;
    }
    if let Some(b) = v.fim_enabled {
        cfg.fim.enabled = b;
    }
    if let Some(p) = &v.fim_extra_paths {
        cfg.fim.extra_paths = p.iter().take(50).cloned().collect();
    }
    if let Some(p) = &v.fim_ignore {
        cfg.fim.ignore = p.iter().take(100).cloned().collect();
    }
}

/// 使用設定前呼叫：有集中設定、本機也願意收，就疊上去；回傳套用的版本。
pub fn apply(cfg: &mut AgentConfig, dir: &Path) -> Option<String> {
    if !cfg.central_config {
        return None;
    }
    let c = load(dir)?;
    apply_values(cfg, &c.config);
    Some(c.version)
}

/// Hub 回的 `/api/v1/agents/me/config`：驗章後存檔（`version` 是 null＝Hub 已經沒有設定 → 刪掉本機的）。
pub fn accept(dir: &Path, agent_id: &str, public_key: Option<&str>, body: &Value) -> AppResult<Option<Central>> {
    let Some(version) = body["version"].as_str() else {
        let p = dir.join(FILE);
        if p.exists() {
            std::fs::remove_file(p)?;
        }
        return Ok(None);
    };
    let pk = public_key
        .ok_or_else(|| AppError::Hub(t!("沒有釘選 Hub 公鑰，不能驗證集中設定（重新加入 Hub 後就會有）").into()))?;
    let json = body["config_json"].as_str().unwrap_or_default();
    let sig = body["signature"].as_str().unwrap_or_default();
    if !super::identity::verify_signature(pk, &message(agent_id, version, json), sig) {
        return Err(AppError::Hub(t!("集中設定的簽章驗證失敗，不套用").into()));
    }
    let config: CentralValues = serde_json::from_str(json).map_err(|e| AppError::Parse(e.to_string()))?;
    let groups = body["groups"]
        .as_array()
        .map(|a| a.iter().filter_map(|g| g.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let c = Central {
        version: version.to_string(),
        groups,
        config,
        applied_at: Utc::now(),
    };
    store::write_json_compact_in(dir, FILE, &c)?;
    Ok(Some(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn keypair() -> (Ed25519KeyPair, String) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(kp.public_key().as_ref());
        (kp, pk)
    }

    fn body(kp: &Ed25519KeyPair, agent: &str, version: &str, json: &str) -> Value {
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(kp.sign(message(agent, version, json).as_bytes()).as_ref());
        serde_json::json!({ "version": version, "config_json": json, "signature": sig, "groups": ["servers"] })
    }

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("asm-central-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn verifies_saves_and_overlays_without_touching_other_settings() {
        let (kp, pk) = keypair();
        let dir = tmp();
        let json = r#"{"dns_names":false,"fim_ignore":["/tmp"],"scan_interval":"30m"}"#;
        let c = accept(&dir, "agent-1", Some(&pk), &body(&kp, "agent-1", "abc", json))
            .unwrap()
            .unwrap();
        assert_eq!(c.groups, vec!["servers".to_string()]);
        assert_eq!(current_version(&dir).as_deref(), Some("abc"));

        let mut cfg = AgentConfig::default();
        let before = cfg.clone();
        assert_eq!(apply(&mut cfg, &dir).as_deref(), Some("abc"));
        assert_eq!(cfg.scan.interval, "30m");
        assert!(!cfg.scan.dns_names);
        assert_eq!(cfg.fim.ignore, vec!["/tmp".to_string()]);
        assert_eq!(cfg.metrics, before.metrics);
        assert_eq!(cfg.remote_actions, before.remote_actions);

        // 本機拒收
        let mut off = AgentConfig {
            central_config: false,
            ..AgentConfig::default()
        };
        assert_eq!(apply(&mut off, &dir), None);
        assert_eq!(off.scan.interval, before.scan.interval);

        // Hub 拿掉設定 → 刪掉本機檔
        assert_eq!(
            accept(&dir, "agent-1", Some(&pk), &serde_json::json!({ "version": null })).unwrap(),
            None
        );
        assert_eq!(current_version(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_bad_signatures_other_agents_unknown_keys_and_missing_pin() {
        let (kp, pk) = keypair();
        let (_, other_pk) = keypair();
        let dir = tmp();
        let json = r#"{"scan_interval":"30m"}"#;
        assert!(accept(&dir, "agent-1", Some(&other_pk), &body(&kp, "agent-1", "v", json)).is_err());
        assert!(accept(&dir, "agent-2", Some(&pk), &body(&kp, "agent-1", "v", json)).is_err());
        assert!(accept(&dir, "agent-1", None, &body(&kp, "agent-1", "v", json)).is_err());
        // 竄改內容
        let mut b = body(&kp, "agent-1", "v", json);
        b["config_json"] = Value::String(r#"{"scan_interval":"1m"}"#.into());
        assert!(accept(&dir, "agent-1", Some(&pk), &b).is_err());
        // 不認得的欄位（例：想推效能蒐集）整份拒收
        let sneaky = r#"{"metrics_performance":true}"#;
        assert!(accept(&dir, "agent-1", Some(&pk), &body(&kp, "agent-1", "v", sneaky)).is_err());
        assert_eq!(current_version(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignores_out_of_range_intervals() {
        let mut cfg = AgentConfig::default();
        let before = cfg.scan.clone();
        apply_values(
            &mut cfg,
            &CentralValues {
                scan_interval: Some("1m".into()),
                snapshot_interval: Some("5s".into()),
                ..Default::default()
            },
        );
        assert_eq!(cfg.scan.interval, before.interval);
        assert_eq!(cfg.scan.snapshot_interval, before.snapshot_interval);
    }
}

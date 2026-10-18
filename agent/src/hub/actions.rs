//! hub 遠端動作：驗 HMAC token → 檢查（agent id、期限、允許種類、破壞性、目標護欄）→ 防火牆執行 → 回報結果。
//!
//! token＝HMAC-SHA256(action_key, canonical JSON of {action_id, agent_id, kind, params, expires_at})，
//! action_key 只在註冊（且身分已釘選）時由 hub 給出。canonical 規則與 hub `lib/actions/sign.ts` 相同，
//! `contract/action.v1.json` 兩邊都測。

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::config::RemoteActionsConfig;
use crate::connections::classify::KnownGood;
use crate::error::AppResult;
use crate::firewall::plan::{Dir, FwAction};
use crate::model::allowlist::Allowlist;
use crate::store;

pub const DONE_FILE: &str = "state/remote-actions.json";
const DONE_KEEP: usize = 200;

/// hub 派送的動作（`GET /api/v1/agents/me/actions` 的 items）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAction {
    pub action_id: String,
    pub agent_id: String,
    pub kind: String,
    pub params: Value,
    /// 原字串參與簽章，不重新格式化。
    pub expires_at: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub destructive: bool,
    pub token: String,
}

/// 物件 key 排序、無空白；陣列保持原順序。
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", Value::String((*k).clone()), canonical_json(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

pub fn signed_payload(a: &RemoteAction) -> String {
    canonical_json(&json!({
        "action_id": a.action_id,
        "agent_id": a.agent_id,
        "kind": a.kind,
        "params": a.params,
        "expires_at": a.expires_at,
    }))
}

/// 常數時間比對 HMAC。
pub fn verify_token(action_key: &str, a: &RemoteAction) -> bool {
    let Ok(sig) = hex::decode(a.token.trim()) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(action_key.as_bytes()) else {
        return false;
    };
    mac.update(signed_payload(a).as_bytes());
    mac.verify_slice(&sig).is_ok()
}

fn param_str<'a>(a: &'a RemoteAction, k: &str) -> Option<&'a str> {
    a.params.get(k).and_then(Value::as_str)
}

/// 全部檢查通過才回傳要執行的防火牆動作；否則回傳拒絕原因（會回報給 hub）。
pub fn check(
    a: &RemoteAction,
    action_key: &str,
    my_agent_id: &str,
    cfg: &RemoteActionsConfig,
    allowlist: &Allowlist,
    now: DateTime<Utc>,
) -> Result<FwAction, String> {
    if !verify_token(action_key, a) {
        return Err(t!("簽章不符（可能被竄改，或 hub 換了簽署金鑰；請重新註冊）").into());
    }
    if a.agent_id != my_agent_id {
        return Err(t!("這個動作不是給這台 agent 的").into());
    }
    match DateTime::parse_from_rfc3339(&a.expires_at) {
        Ok(t) if t.with_timezone(&Utc) > now => {}
        _ => return Err(t!("動作已過期").into()),
    }
    let allowed: Vec<&str> = if cfg.allowed_kinds.is_empty() {
        vec!["block_ip", "unblock_ip"]
    } else {
        cfg.allowed_kinds.iter().map(String::as_str).collect()
    };
    if !allowed.contains(&a.kind.as_str()) {
        return Err(tf!("本機設定不允許遠端執行 {kind}", kind = a.kind));
    }
    // 是否「破壞性」由本機依種類判斷，不只信 Hub 給的標記（那個欄位不在簽章內）
    let destructive = a.destructive || a.kind == "close_port";
    if destructive && !cfg.allow_destructive {
        return Err(t!("本機設定不允許破壞性的遠端動作").into());
    }
    match a.kind.as_str() {
        "block_ip" | "unblock_ip" => {
            let target = param_str(a, "ip").ok_or_else(|| t!("缺少 ip 參數").to_string())?;
            let nets = crate::cli::fw_cmd::parse_targets(&[target.to_string()], false).map_err(|e| e.message())?;
            if a.kind == "unblock_ip" {
                return Ok(FwAction::Unblock { nets });
            }
            let kg = KnownGood::load();
            for n in &nets {
                if let Some(e) = allowlist.overlaps_net(n) {
                    return Err(tf!("{net} 在本機白名單（{id}），不封鎖", net = n, id = e.id));
                }
                if let Some(list) = kg.overlaps_net(n) {
                    return Err(tf!("{net} 屬於已知良好清單（{list}），不封鎖", net = n, list = list));
                }
            }
            let direction = match param_str(a, "direction").unwrap_or("both") {
                "in" | "inbound" => Dir::In,
                "out" | "outbound" => Dir::Out,
                _ => Dir::Both,
            };
            let reason = param_str(a, "reason").unwrap_or("hub");
            Ok(FwAction::Block {
                nets,
                direction,
                reason: format!("hub:{reason}"),
            })
        }
        "close_port" => {
            let proto = match param_str(a, "proto") {
                Some(p @ ("tcp" | "udp")) => p.to_string(),
                _ => return Err(t!("proto 必須是 tcp 或 udp").into()),
            };
            let port = a
                .params
                .get("port")
                .and_then(Value::as_u64)
                .filter(|p| (1..=65535).contains(p))
                .ok_or_else(|| t!("port 參數錯誤").to_string())?;
            Ok(FwAction::ClosePort {
                proto,
                port: port as u16,
            })
        }
        other => Err(tf!("不支援的動作：{kind}", kind = other)),
    }
}

/// 已處理過的動作與結果（hub 逾時重派時直接回報同一個結果，不重複執行）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoneLog {
    #[serde(default)]
    pub items: BTreeMap<String, DoneItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoneItem {
    pub at: String,
    pub ok: bool,
    pub output: String,
}

impl DoneLog {
    pub fn load(config_dir: &Path) -> Self {
        store::read_json_opt(config_dir, DONE_FILE)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    pub fn record(&mut self, id: &str, ok: bool, output: &str) {
        self.items.insert(
            id.to_string(),
            DoneItem {
                at: crate::util::time::now_iso(),
                ok,
                output: output.to_string(),
            },
        );
        while self.items.len() > DONE_KEEP {
            let oldest = self
                .items
                .iter()
                .min_by(|a, b| a.1.at.cmp(&b.1.at))
                .map(|(k, _)| k.clone());
            match oldest {
                Some(k) => self.items.remove(&k),
                None => break,
            };
        }
    }

    pub fn save(&self, config_dir: &Path) -> AppResult<()> {
        store::ensure_dir(&config_dir.join("state"))?;
        store::write_json_compact_in(config_dir, DONE_FILE, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Value {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contract/action.v1.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn sample() -> (RemoteAction, String) {
        let f = fixture();
        let a: RemoteAction = serde_json::from_value(f["action"].clone()).unwrap();
        (a, f["action_key"].as_str().unwrap().to_string())
    }

    #[test]
    fn canonical_and_token_match_the_hub() {
        let f = fixture();
        let (a, key) = sample();
        assert_eq!(signed_payload(&a), f["canonical"].as_str().unwrap());
        assert!(verify_token(&key, &a));
        assert_eq!(
            canonical_json(&json!({"b": 1, "a": {"d": [3, {"z": 1, "y": 2}], "c": "x\n\"q\""}})),
            r#"{"a":{"c":"x\n\"q\"","d":[3,{"y":2,"z":1}]},"b":1}"#
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (a, key) = sample();
        let mut b = a.clone();
        b.params["ip"] = json!("198.51.100.1");
        assert!(!verify_token(&key, &b));
        let mut c = a.clone();
        c.expires_at = "2099-01-01T00:00:00.000Z".into();
        assert!(!verify_token(&key, &c));
        assert!(!verify_token("other-key", &a));
        let mut d = a.clone();
        d.token = "zz".into();
        assert!(!verify_token(&key, &d));
    }

    #[test]
    fn checks_before_executing() {
        let (a, key) = sample();
        let cfg = RemoteActionsConfig::default();
        let allow = Allowlist::default();
        let before = DateTime::parse_from_rfc3339("2026-10-17T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let after = DateTime::parse_from_rfc3339("2026-10-17T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        match check(&a, &key, &a.agent_id, &cfg, &allow, before) {
            Ok(FwAction::Block {
                nets,
                direction,
                reason,
            }) => {
                assert_eq!(nets[0].to_string(), "203.0.113.66/32");
                assert_eq!(direction, Dir::Both);
                assert_eq!(reason, "hub:abusech-feodo");
            }
            other => panic!("{other:?}"),
        }
        assert!(check(&a, &key, &a.agent_id, &cfg, &allow, after).is_err());
        assert!(check(&a, &key, "another-agent", &cfg, &allow, before).is_err());
        let only_unblock = RemoteActionsConfig {
            accept: true,
            allowed_kinds: vec!["unblock_ip".into()],
            allow_destructive: false,
        };
        assert!(check(&a, &key, &a.agent_id, &only_unblock, &allow, before)
            .unwrap_err()
            .contains("block_ip"));
        let mut listed = Allowlist::default();
        listed
            .add(Some(crate::model::allowlist::AllowKind::Cidr), "203.0.113.0/24", None)
            .unwrap();
        assert!(check(&a, &key, &a.agent_id, &cfg, &listed, before).is_err());
    }

    #[test]
    fn done_log_caps_entries() {
        let d = tempfile::tempdir().unwrap();
        let mut log = DoneLog::default();
        for i in 0..(DONE_KEEP + 5) {
            log.record(&format!("act_{i:04}"), true, "ok");
        }
        assert_eq!(log.items.len(), DONE_KEEP);
        log.save(d.path()).unwrap();
        assert_eq!(DoneLog::load(d.path()).items.len(), DONE_KEEP);
    }
}

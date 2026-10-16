//! 兩段式動作的審查 token（沿用 db-kit `preview_write → execute_write`）：
//! preview 時把計畫存在伺服器端、回 12 碼 token；execute 只收 token（不收新參數），單次有效、15 分鐘過期、最多 32 筆。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::firewall::plan::FwAction;

pub const TOKEN_TTL: Duration = Duration::from_secs(15 * 60);
pub const MAX_PENDING: usize = 32;

#[derive(Debug, Clone)]
pub struct Pending {
    pub action: FwAction,
    pub backend: String,
    pub destructive: bool,
    pub created: Instant,
    pub origin: String,
}

#[derive(Default)]
pub struct PendingStore(Mutex<HashMap<String, Pending>>);

pub fn new_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

impl PendingStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// 存入並回傳 token；滿了就淘汰最舊的。
    pub fn insert(&self, p: Pending) -> String {
        let token = new_token();
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, v| v.created.elapsed() < TOKEN_TTL);
        if m.len() >= MAX_PENDING {
            if let Some(oldest) = m.iter().min_by_key(|(_, v)| v.created).map(|(k, _)| k.clone()) {
                m.remove(&oldest);
            }
        }
        m.insert(token.clone(), p);
        token
    }

    /// 取出（單次）；過期回 None。
    pub fn take(&self, token: &str) -> Option<Pending> {
        let mut m = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let p = m.remove(token)?;
        (p.created.elapsed() < TOKEN_TTL).then_some(p)
    }

    pub fn len(&self) -> usize {
        self.0.lock().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> Pending {
        Pending {
            action: FwAction::Ensure,
            backend: "nft".into(),
            destructive: false,
            created: Instant::now(),
            origin: "mcp".into(),
        }
    }

    #[test]
    fn single_use_and_capacity() {
        let s = PendingStore::new();
        let t = s.insert(p());
        assert_eq!(t.len(), 12);
        assert!(s.take(&t).is_some());
        assert!(s.take(&t).is_none());
        let first = s.insert(p());
        for _ in 0..MAX_PENDING {
            s.insert(p());
        }
        assert_eq!(s.len(), MAX_PENDING);
        assert!(s.take(&first).is_none(), "oldest evicted");
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let s = PendingStore::new();
        let mut old = p();
        old.created = Instant::now() - TOKEN_TTL - Duration::from_secs(1);
        let t = s.insert(old);
        assert!(s.take(&t).is_none());
    }
}

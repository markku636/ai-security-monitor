//! PID → 程式名稱／路徑。DNS 事件只帶 PID，每個 PID 只查一次系統（只刷新那一個行程），
//! 結果快取 10 分鐘（PID 會被重用，不能永久記）。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

const TTL: Duration = Duration::from_secs(600);
const MAX_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcName {
    pub name: String,
    pub exe: Option<String>,
}

pub struct ProcNames {
    sys: System,
    cache: HashMap<u32, (Instant, Option<ProcName>)>,
}

impl Default for ProcNames {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcNames {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            cache: HashMap::new(),
        }
    }

    pub fn get(&mut self, pid: u32) -> Option<ProcName> {
        let now = Instant::now();
        if let Some((at, v)) = self.cache.get(&pid) {
            if now.duration_since(*at) < TTL {
                return v.clone();
            }
        }
        let p = Pid::from_u32(pid);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[p]),
            true,
            ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
        );
        let v = self.sys.process(p).map(|pr| ProcName {
            name: pr.name().to_string_lossy().to_string(),
            exe: pr.exe().map(|e| e.to_string_lossy().to_string()),
        });
        if self.cache.len() >= MAX_ENTRIES {
            self.cache.retain(|_, (at, _)| now.duration_since(*at) < TTL);
            if self.cache.len() >= MAX_ENTRIES {
                self.cache.clear();
            }
        }
        self.cache.insert(pid, (now, v.clone()));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_own_process_and_caches() {
        let mut p = ProcNames::new();
        let me = std::process::id();
        let a = p.get(me).expect("own process");
        assert!(!a.name.is_empty());
        assert_eq!(p.get(me), Some(a));
        assert!(p.get(u32::MAX - 7).is_none());
    }
}

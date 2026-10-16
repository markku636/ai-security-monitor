//! 資料契約：agent 產出、hub 接收、MCP 回傳的同一份 JSON 形狀。

pub mod allowlist;
pub mod baseline;
pub mod connection;
pub mod contract;
pub mod finding;
pub mod report;
pub mod verdict;

pub use connection::{Connection, Direction, Listener, ProcessRef, Reachability};
pub use finding::{ActionKind, Evidence, Finding, IntelHit, ProposedAction, ScannerId, Severity};
pub use report::{AgentInfo, OsInfo, Report, Scores};
pub use verdict::{AnomalyKind, Reason, Verdict, VerdictLevel};

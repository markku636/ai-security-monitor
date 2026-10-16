//! `asa_lib`：AI Security Agent 的核心程式庫。
//!
//! 分層原則（沿用 db-kit）：核心模組不依賴任何介面殼；CLI / MCP / hub client 都是薄轉接。
//! - `model`：Finding / Report / Verdict 等資料契約（hub 以同一份 JSON 接收）。
//! - `scan`：Scanner trait 與 Pipeline，各引擎（connections / intel / firewall …）掛在這裡。
//! - `cli`：clap 樹與子命令處理。

#[macro_use]
pub mod i18n;
pub mod locales;

pub mod actions;
pub mod ai;
pub mod config;
pub mod connections;
pub mod elevate;
pub mod embedded;
pub mod error;
pub mod events;
pub mod firewall;
pub mod hub;
pub mod intel;
pub mod mcp;
pub mod model;
pub mod ports;
pub mod scan;
pub mod secrets;
pub mod store;
pub mod sysmeta;
pub mod traffic;
pub mod util;

pub mod cli;

/// crate 版本（Cargo.toml）。
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// 建置時的 git 短 sha（無 git 時為 `unknown`）。
pub const GIT_SHA: &str = env!("ASA_GIT_SHA");
/// 建置時間（Unix 秒）。
pub const BUILD_UNIX: &str = env!("ASA_BUILD_UNIX");

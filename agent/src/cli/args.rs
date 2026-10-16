//! clap 命令樹。所有 help 文字為繁中字面值，`--lang en` 時由 `locales/en.rs` 執行期覆寫。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::model::allowlist::AllowKind;
use crate::model::finding::ScannerId;

#[derive(Parser, Debug)]
#[command(
    name = "asa",
    version = crate::VERSION,
    about = "AI Security Agent：防禦型資安掃描 agent（連線判定、威脅情資、防火牆、漏洞、硬化、流量、事件、MCP）",
    disable_help_subcommand = true,
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,
    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Args, Debug, Clone, Default)]
pub struct GlobalArgs {
    /// 介面語言（zh-TW / en）
    #[arg(long, global = true, env = "ASA_LANG", value_name = "LANG")]
    pub lang: Option<String>,
    /// 確認執行會改變系統的動作（否則只預演）
    #[arg(short = 'y', long, global = true)]
    pub yes: bool,
    /// 高破壞動作的二次確認
    #[arg(long, global = true)]
    pub force: bool,
    /// 以 JSON 輸出
    #[arg(long, global = true)]
    pub json: bool,
    /// 設定目錄（預設 ASA_CONFIG_DIR 或使用者設定目錄下的 ai-security-agent）
    #[arg(long, global = true, env = "ASA_CONFIG_DIR", value_name = "DIR")]
    pub config_dir: Option<PathBuf>,
    /// 安靜模式（不印進度）
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true, hide = true)]
    pub elevated: bool,
    #[arg(long, global = true, hide = true, value_name = "FILE")]
    pub result_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// 顯示版本；--check 查 GitHub 是否有新版
    Version {
        /// 查詢 GitHub Release 是否有新版
        #[arg(long)]
        check: bool,
    },
    /// 檢查環境：權限、外部工具、情資新鮮度、hub 連線、AI 用戶端
    Doctor,
    /// 執行掃描並輸出報告
    Scan(ScanArgs),
    /// 設定檔
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// 白名單（ip / cidr / 行程路徑 / 網域 / 規則）
    Allowlist {
        #[command(subcommand)]
        cmd: AllowlistCmd,
    },
    /// 基準線：記住目前狀態，之後只標出新增項目
    Baseline {
        #[command(subcommand)]
        cmd: BaselineCmd,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct ScanArgs {
    /// 要跑的掃描器（逗號分隔；預設全部可用）
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    pub scanners: Vec<ScannerId>,
    /// 把報告寫到檔案
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// 掃描後把目前狀態存成基準線
    #[arg(long)]
    pub baseline: bool,
    /// 不做任何線上查詢
    #[arg(long)]
    pub no_online: bool,
    /// 以表格輸出（預設）
    #[arg(long, conflicts_with = "json_out")]
    pub table: bool,
    #[arg(long = "json-out", hide = true)]
    pub json_out: bool,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// 顯示目前設定
    Show,
    /// 設定單一鍵值（例：scan.interval 15m）
    Set {
        /// 鍵名（lang、scan.interval、intel.allow_noncommercial …）
        key: String,
        /// 值
        value: String,
    },
    /// 顯示設定目錄路徑
    Path,
}

#[derive(Subcommand, Debug)]
pub enum AllowlistCmd {
    /// 新增白名單條目（自動推斷種類，或用 --kind 指定）
    Add {
        /// 值：IP、CIDR、行程路徑 glob、網域（*.example.com）、規則（connections.risky_port:3389）
        value: String,
        /// 種類
        #[arg(long, value_enum)]
        kind: Option<AllowKind>,
        /// 備註
        #[arg(long)]
        note: Option<String>,
    },
    /// 移除條目（以 id 或值）
    Remove {
        /// 條目 id 或原值
        entry: String,
    },
    /// 列出全部條目
    List,
}

#[derive(Subcommand, Debug)]
pub enum BaselineCmd {
    /// 以目前狀態建立 / 併入基準線
    Save,
    /// 比對目前狀態與基準線
    Diff,
    /// 顯示基準線內容
    Show,
}

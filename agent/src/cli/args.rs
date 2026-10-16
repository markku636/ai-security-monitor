//! clap 命令樹。所有 help 文字為繁中字面值，`--lang en` 時由 `locales/en.rs` 執行期覆寫。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::model::allowlist::AllowKind;
use crate::model::connection::Direction;
use crate::model::finding::ScannerId;
use crate::model::verdict::VerdictLevel;

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
    /// 列出連線：方向、判定（安全／未知／可疑／危險）、行程、原因
    Connections(ConnectionsArgs),
    /// 威脅情資：更新、狀態、來源、查詢 IP／網域
    Intel {
        #[command(subcommand)]
        cmd: IntelCmd,
    },
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

#[derive(Args, Debug, Clone, Default)]
pub struct ConnectionsArgs {
    /// 只看某方向（outbound / inbound / listening / local）
    #[arg(long, value_enum)]
    pub direction: Option<Direction>,
    /// 只看這些判定（逗號分隔：safe,unknown,suspicious,dangerous）
    #[arg(long, value_delimiter = ',', value_enum)]
    pub verdict: Vec<VerdictLevel>,
    /// 包含本機對本機與 loopback listener
    #[arg(long)]
    pub all: bool,
    /// 持續刷新
    #[arg(long)]
    pub watch: bool,
    /// 刷新間隔（--watch）
    #[arg(long, default_value = "2s", value_name = "DUR")]
    pub interval: String,
    /// 比對威脅情資（需先 asa intel update）
    #[arg(long)]
    pub intel: bool,
}

#[derive(Subcommand, Debug)]
pub enum IntelCmd {
    /// 下載／更新威脅情資（只抓過期的；--force 全部重抓）
    Update {
        /// 只更新這些來源 id
        #[arg(long = "feed", value_name = "ID")]
        feeds: Vec<String>,
        /// 忽略更新間隔，全部重抓
        #[arg(long)]
        force: bool,
    },
    /// 顯示各來源的筆數、更新時間與狀態
    Status,
    /// 列出所有情資來源（廠商、授權、網址）
    Sources,
    /// 查詢 IP 或網域：命中哪些情資、地理位置、判定
    Lookup {
        /// IP 或網域
        indicator: String,
        /// 也查詢已設定 API key 的線上名譽服務
        #[arg(long)]
        online: bool,
    },
    /// 啟用來源
    Enable {
        /// 來源 id
        id: String,
    },
    /// 停用來源
    Disable {
        /// 來源 id
        id: String,
    },
    /// 設定／刪除線上名譽服務的 API key（存進 keychain）
    Key {
        #[command(subcommand)]
        cmd: IntelKeyCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum IntelKeyCmd {
    /// 設定 API key（值為 - 時從標準輸入讀取）
    Set {
        /// 服務 id（abuseipdb、greynoise-community、crowdsec-cti）
        id: String,
        /// API key；- 表示從標準輸入讀取
        value: String,
    },
    /// 刪除 API key
    Delete {
        /// 服務 id（abuseipdb、greynoise-community、crowdsec-cti）
        id: String,
    },
}

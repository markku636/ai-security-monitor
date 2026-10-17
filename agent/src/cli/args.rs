//! clap 命令樹。所有 help 文字為繁中字面值，`--lang en` 時由 `locales/en.rs` 執行期覆寫。

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::model::allowlist::AllowKind;
use crate::model::connection::Direction;
use crate::model::finding::ScannerId;
use crate::model::verdict::VerdictLevel;

/// clap `env = "AI_SECURITY_MONITOR_<X>"` 的 `<X>`；解析前由 `util::env::seed_from_legacy` 從舊名 `ASA_<X>` 補上。
pub const CLAP_ENV: &[&str] = &["LANG", "CONFIG_DIR", "MCP_TOKEN"];

#[derive(Parser, Debug)]
#[command(
    name = "ai-security-monitor",
    version = crate::VERSION,
    about = "AI Security Monitor：防禦型資安監控工具（連線判定、威脅情資、防火牆、漏洞、硬化、流量、事件、MCP）",
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
    #[arg(long, global = true, env = "AI_SECURITY_MONITOR_LANG", value_name = "LANG")]
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
    /// 設定目錄（預設 AI_SECURITY_MONITOR_CONFIG_DIR 或使用者設定目錄下的 ai-security-monitor）
    #[arg(long, global = true, env = "AI_SECURITY_MONITOR_CONFIG_DIR", value_name = "DIR")]
    pub config_dir: Option<PathBuf>,
    /// 安靜模式（不印進度）
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
    #[arg(long, global = true, hide = true)]
    pub elevated: bool,
    #[arg(long, global = true, hide = true, value_name = "FILE")]
    pub result_file: Option<PathBuf>,
    /// 密鑰存放方式（keychain／file；服務模式用 file）
    #[arg(long, global = true, hide = true, value_name = "BACKEND")]
    pub secrets_backend: Option<String>,
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
    /// 更新 ai-security-monitor：下載 GitHub Release 的執行檔，比對 SHA256 後替換，並重新啟動背景服務
    SelfUpdate {
        /// 只檢查有沒有新版
        #[arg(long)]
        check: bool,
        /// 更新（或退回）到指定版本，例：0.2.0
        #[arg(long, value_name = "VER")]
        to: Option<String>,
        /// 更新後不要重新啟動背景服務
        #[arg(long)]
        no_restart: bool,
    },
    /// 執行掃描並輸出報告
    Scan(ScanArgs),
    /// 列出連線：方向、判定（安全／未知／可疑／危險）、行程、原因
    Connections(ConnectionsArgs),
    /// 註冊到 Security Hub：給 --key 用金鑰；不給金鑰就自動尋找 Hub、送出加入申請等管理員核准
    Enroll(EnrollArgs),
    /// 尋找區網／公司 DNS 上的 Security Hub（只列出，不加入）
    Discover(DiscoverArgs),
    /// Security Hub 相關工具（在區網上幫 Hub 廣播）
    Hub {
        #[command(subcommand)]
        cmd: HubCmd,
    },
    /// 取消註冊（刪除 hub 設定與金鑰）
    Unenroll,
    /// 顯示 agent、hub 連線、待重送與最後一次掃描
    Status,
    /// 常駐：定期掃描、上傳報告、連線快照與心跳
    Watch(WatchArgs),
    /// 立即掃描並上傳到 Hub（先補送暫存的報告，再上傳連線快照、掃描報告與心跳）
    Upload,
    /// 開機自動啟動：裝成系統服務（伺服器）或登入時啟動（個人電腦）
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// 防火牆：狀態、稽核、規則、封鎖與情資同步
    Fw {
        #[command(subcommand)]
        cmd: FwCmd,
    },
    /// 對外 port 與可達性；或探測自己網段的主機
    Ports(PortsArgs),
    /// 流量：即時觀察連線（免抓包）或分析 pcap／pcapng 檔
    Traffic(TrafficArgs),
    /// 網路流量統計與效能：各介面與各程式的上傳／下載量；開啟後另有 CPU、記憶體、磁碟、電池
    Metrics(MetricsArgs),
    /// DNS 監看：這台電腦最近查了哪些網域、是哪個程式查的、哪些可疑（--follow 即時看）
    Dns(DnsArgs),
    /// 防護 DNS 伺服器（選用）：給區網用的 DNS，封鎖情資列名的網域、上游走加密 DNS、有快取
    #[cfg(feature = "dns-server")]
    DnsServer(DnsServerArgs),
    /// 檔案完整性與開機自啟：看哪些重要檔案或開機自動執行項目被改過、接受變更、重建基準
    Fim(FimArgs),
    /// 事件與當機原因：藍屏、非預期關機、程式當掉、資安事件（Windows 事件、Linux journal、macOS 當機報告）
    Events(EventsArgs),
    /// 漏洞與更新：作業系統是否仍在支援、多久沒更新、已安裝軟體的已知漏洞（Linux 套件查 OSV）
    Vuln(VulnArgs),
    /// 系統硬化檢查：UAC、Defender、BitLocker、SSH、核心參數、自動更新等，給分數與修正方式
    Harden(HardenArgs),
    /// MCP 伺服器：讓 Claude Code／Codex／Cursor／VS Code 查這台電腦的資安狀態
    Mcp(McpArgs),
    /// 用 Claude Code 或 Codex CLI 分析：問問題、解讀報告、流量與當機
    Ai {
        #[command(subcommand)]
        cmd: AiCmd,
    },
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

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct McpArgs {
    #[command(subcommand)]
    pub cmd: Option<McpCmd>,
    /// 改用 HTTP（例：127.0.0.1:7870）；預設 stdio
    #[arg(long, value_name = "ADDR")]
    pub http: Option<String>,
    /// HTTP 模式的 Bearer token（沒設時只能綁本機）
    #[arg(long, env = "AI_SECURITY_MONITOR_MCP_TOKEN", hide_env_values = true)]
    pub token: Option<String>,
    /// 只開放這些工具（逗號分隔）
    #[arg(long, value_delimiter = ',')]
    pub tools: Vec<String>,
    /// 開放防禦動作（preview_action → 使用者同意 → execute_action）
    #[arg(long)]
    pub allow_actions: bool,
    /// 也開放破壞性動作（關閉 port）
    #[arg(long)]
    pub allow_destructive: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum McpCmd {
    /// 印出給 AI 用戶端的設定片段
    Config {
        /// AI 用戶端
        #[arg(long, value_enum)]
        client: crate::mcp::setup::Client,
        /// 設定裡加上 --allow-actions
        #[arg(long)]
        allow_actions: bool,
    },
    /// 寫入 AI 用戶端設定（需要 --yes；原檔備份為 .bak）
    Install {
        /// AI 用戶端
        #[arg(long, value_enum)]
        client: crate::mcp::setup::Client,
        /// 寫進專案設定（.mcp.json、.vscode/mcp.json…）而不是使用者設定
        #[arg(long, value_name = "DIR")]
        project: Option<PathBuf>,
        /// 設定裡加上 --allow-actions
        #[arg(long)]
        allow_actions: bool,
    },
    /// 從 AI 用戶端設定移除 ai-security-monitor（需要 --yes）
    Uninstall {
        /// AI 用戶端
        #[arg(long, value_enum)]
        client: crate::mcp::setup::Client,
        /// 專案資料夾
        #[arg(long, value_name = "DIR")]
        project: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AiCmd {
    /// 問 AI 一個資安問題（它會透過 ai-security-monitor 的 MCP 工具自己查這台電腦）
    Ask {
        /// 問題
        question: String,
        #[command(flatten)]
        opts: AiOpts,
    },
    /// 請 AI 解讀最新報告；--traffic／--events 改看流量或事件
    Analyze {
        /// 報告檔（預設最新一份）
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,
        /// 改看即時流量（觀察 --duration）
        #[arg(long)]
        traffic: bool,
        /// 改看事件與當機（近 --since）
        #[arg(long)]
        events: bool,
        /// 流量觀察時間
        #[arg(long, default_value = "30s", value_name = "DUR")]
        duration: String,
        /// 事件範圍
        #[arg(long, default_value = "7d", value_name = "DUR")]
        since: String,
        #[command(flatten)]
        opts: AiOpts,
    },
    /// 檢查 Claude Code／Codex CLI 是否安裝與登入
    Status,
}

#[derive(Args, Debug, Clone)]
pub struct AiOpts {
    /// 用哪個 AI（claude／codex；預設找得到哪個用哪個）
    #[arg(long, value_enum)]
    pub provider: Option<crate::ai::Provider>,
    /// 模型名稱（交給 CLI）
    #[arg(long)]
    pub model: Option<String>,
    /// 最多幾回合工具呼叫
    #[arg(long, default_value_t = 12)]
    pub max_turns: u32,
    /// 逾時
    #[arg(long, default_value = "10m", value_name = "DUR")]
    pub timeout: String,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct EventsArgs {
    #[command(subcommand)]
    pub cmd: Option<EventsCmd>,
    /// 看多久以前到現在（例：7d、30d，最多 90d）
    #[arg(long, default_value = "7d", value_name = "DUR")]
    pub since: String,
}

#[derive(Subcommand, Debug, Clone)]
pub enum EventsCmd {
    /// 只看當機：藍屏、非預期關機、程式當掉、服務失敗、磁碟與硬體錯誤
    Crashes {
        /// 看多久以前到現在
        #[arg(long, default_value = "30d", value_name = "DUR")]
        since: String,
    },
    /// 解釋藍屏代碼（例 0x7E）或事件 ID（例 41、4625）
    Explain {
        /// 藍屏代碼或事件 ID
        code: String,
    },
    /// 分析檔案：.evtx（Windows）、journalctl -o json 輸出、macOS .ips／.panic、Windows .dmp
    Analyze {
        /// 檔案路徑
        file: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct HardenArgs {
    /// 列出全部檢查（預設只列未通過）
    #[arg(long)]
    pub all: bool,
    /// 只看這個分類（例：account、remote、kernel、update、encryption）
    #[arg(long, value_name = "NAME")]
    pub category: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct VulnArgs {
    /// 只列出已安裝的軟體清單，不做比對
    #[arg(long)]
    pub inventory_only: bool,
    /// 不連線查 OSV（只用內建規則）
    #[arg(long)]
    pub no_online: bool,
    /// 清單模式下只列名稱含這段文字的軟體
    #[arg(long, value_name = "TEXT")]
    pub filter: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct TrafficArgs {
    #[command(subcommand)]
    pub cmd: Option<TrafficCmd>,
    /// 觀察多久（即時模式）
    #[arg(long, default_value = "30s", value_name = "DUR")]
    pub duration: String,
    /// 多久讀一次連線表
    #[arg(long, default_value = "2s", value_name = "DUR")]
    pub every: String,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub cmd: Option<DnsCmd>,
    /// 看最近多久
    #[arg(long, default_value = "15m", value_name = "DUR")]
    pub since: String,
    /// 只看可疑的（情資命中、像亂數產生的網域、少見頂級網域）
    #[arg(long)]
    pub suspicious: bool,
    /// 只看這個程式（名稱，不分大小寫，例 chrome.exe）
    #[arg(long, value_name = "NAME")]
    pub process: Option<String>,
    /// 最多列幾筆
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    /// 即時顯示新的查詢（Ctrl+C 結束；Windows 以系統管理員執行才看得到是哪個程式）
    #[arg(long)]
    pub follow: bool,
}

#[cfg(feature = "dns-server")]
#[derive(Args, Debug, Clone)]
pub struct DnsServerArgs {
    /// 監聽位址（逗號分隔；預設 0.0.0.0:53 與 [::]:53，被佔用時改綁各網卡位址）
    #[arg(long, value_delimiter = ',', value_name = "ADDR")]
    pub listen: Vec<String>,
    /// 上游 DNS：https:// 開頭＝加密 DNS（DoH），否則是 IP（預設 Quad9 與 Cloudflare 的 DoH）
    #[arg(long, value_delimiter = ',', value_name = "URL|IP")]
    pub upstream: Vec<String>,
    /// 拿來封鎖的網域情資來源 id（省略＝已啟用、信心夠高的網域清單）
    #[arg(long = "feed", value_name = "ID")]
    pub feeds: Vec<String>,
    /// 自動挑選清單時的最低信心
    #[arg(long, default_value_t = 75)]
    pub min_confidence: u8,
    /// 另外要封鎖的網域（含子網域）
    #[arg(long = "block", value_name = "DOMAIN")]
    pub block: Vec<String>,
    /// 不要封鎖的網域（含子網域）
    #[arg(long = "allow", value_name = "DOMAIN")]
    pub allow: Vec<String>,
    /// 允許使用的用戶端網段（逗號分隔；預設 loopback 與私有網段）
    #[arg(long, value_delimiter = ',', value_name = "CIDR")]
    pub acl: Vec<String>,
    /// 每個用戶端每秒最多幾題（0＝不限）
    #[arg(long, default_value_t = 200)]
    pub rate_limit: u32,
    /// 快取最多幾筆
    #[arg(long, default_value_t = 200_000)]
    pub cache: u64,
    /// 不封鎖，只做加密轉送與快取
    #[arg(long)]
    pub no_block: bool,
    /// 也擋 iCloud Private Relay（讓 Apple 裝置回到這台 DNS）
    #[arg(long)]
    pub block_private_relay: bool,
    /// 不記錄查詢
    #[arg(long)]
    pub no_log: bool,
    /// 內部網域（回私有位址不當成 DNS rebinding），例 corp.example
    #[arg(long = "internal-suffix", value_name = "SUFFIX")]
    pub internal_suffix: Vec<String>,
    /// 連上 Hub：封鎖開關、上游、清單以 Hub 的「防護 DNS」設定為準，送心跳與查詢紀錄（例 https://hub.example:8088）
    #[arg(long, value_name = "URL", env = "AI_SECURITY_MONITOR_DNS_HUB_URL")]
    pub hub: Option<String>,
    /// 連 Hub 用的防護 DNS 權杖（Hub 的 API token 勾「防護 DNS 伺服器」，或 compose 的 AI_SECURITY_MONITOR_HUB_DNS_TOKEN）
    #[arg(
        long,
        value_name = "TOKEN",
        env = "AI_SECURITY_MONITOR_HUB_DNS_TOKEN",
        hide_env_values = true
    )]
    pub hub_token: Option<String>,
    /// 用這台電腦加入 Hub 的身分連 Hub（背景服務帶起時用）
    #[arg(long, conflicts_with = "hub_token")]
    pub hub_agent: bool,
    /// 允許用 http 連公網上的 Hub
    #[arg(long)]
    pub insecure_http: bool,
    /// 不自己下載封鎖用的情資清單（交給背景服務更新）
    #[arg(long)]
    pub no_feed_update: bool,
    /// 檢查本機的防護 DNS 是否正常（健康檢查名稱與測試封鎖網域）後結束
    #[arg(long)]
    pub healthcheck: bool,
    /// 顯示防護 DNS 的狀態（查詢量、快取、封鎖、上游延遲）後結束
    #[arg(long)]
    pub status: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DnsCmd {
    /// 背景 DNS 蒐集的狀態：資料來源、事件數、最後一筆、儲存位置
    Status,
    /// 確認這個網路目前的 DNS 伺服器是正確的（之後被改才告警）
    Accept,
}

#[derive(Args, Debug, Clone)]
pub struct FimArgs {
    #[command(subcommand)]
    pub cmd: Option<FimCmd>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum FimCmd {
    /// 基準建立時間、監看數量與待確認的變更（預設）
    Status,
    /// 接受變更（確認是自己或軟體更新做的）：指定路徑或項目開頭，或 --all
    Accept {
        /// 路徑或開機自啟項目（開頭符合就算）
        path: Option<String>,
        /// 接受全部
        #[arg(long)]
        all: bool,
    },
    /// 丟掉基準與變更清單，下次掃描重新記下目前的狀態
    Baseline,
}

#[derive(Args, Debug, Clone)]
pub struct MetricsArgs {
    /// 量多久（算速率用）
    #[arg(long, default_value = "2s", value_name = "DUR")]
    pub duration: String,
    /// 沒開啟效能蒐集也量一次 CPU、記憶體、磁碟（只在本機顯示，不會上傳）
    #[arg(long)]
    pub perf: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TrafficCmd {
    /// 分析 Wireshark／tcpdump 存的 .pcap／.pcapng（DNS、TLS SNI、明文協定、大量上傳、週期性連線、情資命中）
    Analyze {
        /// 擷取檔路徑
        file: String,
        /// 最多處理幾個封包
        #[arg(long, default_value_t = crate::traffic::offline::DEFAULT_MAX_PACKETS)]
        max_packets: u64,
    },
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
    /// 比對威脅情資（需先 ai-security-monitor intel update）
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
        /// 已註冊 Hub 也不用 Hub 的鏡像，直接找各廠商下載
        #[arg(long)]
        no_hub: bool,
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

#[derive(Subcommand, Debug)]
pub enum FwCmd {
    /// 防火牆後端、啟用狀態、各設定檔與預設動作
    Status,
    /// 稽核防火牆與對外 port（產生 finding）
    Audit,
    /// 列出允許連入的規則
    List {
        /// 包含 UWP 應用程式（每使用者）規則
        #[arg(long)]
        all: bool,
        /// 只列 ai-security-monitor 建立的封鎖與期望狀態
        #[arg(long)]
        ours: bool,
    },
    /// 封鎖 IP / 網段（預設雙向；需要系統管理員權限）
    Block {
        /// IP 或 CIDR
        #[arg(required = true)]
        targets: Vec<String>,
        /// 方向
        #[arg(long, value_enum, default_value = "both")]
        direction: crate::firewall::plan::Dir,
        /// 原因（寫進規則說明）
        #[arg(long, default_value = "manual")]
        reason: String,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 解除 ai-security-monitor 建立的封鎖
    Unblock {
        /// IP 或 CIDR（用 --all-asa 時可省略）
        targets: Vec<String>,
        /// 移除 ai-security-monitor 建立的全部規則
        #[arg(long)]
        all_asa: bool,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 用防火牆關閉對內 port（例：tcp/6379）
    ClosePort {
        /// 協定/port，例：tcp/6379
        spec: String,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 取消 close-port
    OpenPort {
        /// 協定/port，例：tcp/6379
        spec: String,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 啟用防火牆（Windows 可指定設定檔）
    Enable {
        /// Windows 設定檔：domain / private / public（省略＝全部）
        #[arg(long)]
        profile: Option<String>,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 把威脅情資黑名單同步到防火牆（只取公網、高信心、可商用來源）
    SyncBlocklist {
        /// 只用這些來源 id
        #[arg(long = "feed", value_name = "ID")]
        feeds: Vec<String>,
        /// 最低信心（0–100）
        #[arg(long, default_value_t = 80)]
        min_confidence: u8,
        /// 最多幾個網段（預設依後端上限）
        #[arg(long)]
        max: Option<usize>,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 依期望狀態重新套用 ai-security-monitor 規則（pf / nftables 開機後需要）
    Ensure {
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 鎖定 DNS：程式只能連允許的 DNS 伺服器（擋直連外部 53／853，防止繞過公司 DNS）
    DnsLock {
        /// 允許的 DNS 伺服器（逗號分隔；省略＝目前在用的）
        #[arg(long, value_delimiter = ',', value_name = "IP")]
        allow: Vec<String>,
        /// 另外擋常見加密 DNS（DoH）業者的 443，讓瀏覽器回到系統 DNS
        #[arg(long)]
        block_doh: bool,
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
    /// 解除 DNS 鎖定
    DnsUnlock {
        /// 只顯示會執行的步驟，不執行
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct PortsArgs {
    /// 包含只綁本機的 listener
    #[arg(long)]
    pub all: bool,
    /// 主動探測這台主機的 TCP port（只限自己或私有網段）
    #[arg(long, value_name = "HOST")]
    pub probe: Option<String>,
    /// 要探測的 port（例：22,80,8000-8100；預設常見 70 個）
    #[arg(long, value_name = "LIST")]
    pub ports: Option<String>,
    /// 每個連線的逾時
    #[arg(long, default_value = "800ms", value_name = "DUR")]
    pub timeout: String,
    /// 改用已安裝的 nmap（-sT）
    #[arg(long)]
    pub nmap: bool,
    /// 允許探測公網位址（只限你擁有或已獲授權的主機）
    #[arg(long)]
    pub allow_public: bool,
}

#[derive(Args, Debug, Clone, Default)]
pub struct EnrollArgs {
    /// Hub 網址（https://…；本機或私網可用 http）；免金鑰時可省略，改用自動尋找
    pub url: Option<String>,
    /// client 金鑰或註冊金鑰；- 表示從標準輸入讀取。不給就送出免金鑰的加入申請
    #[arg(long)]
    pub key: Option<String>,
    /// 免金鑰加入：自動尋找公司的 Hub（DNS SRV、區網廣播），送出加入申請並等管理員核准
    #[arg(long)]
    pub auto: bool,
    /// 要加入的 Hub 網址（找到好幾個 Hub 時用它指定；安裝程式會預填）
    #[arg(long, value_name = "URL")]
    pub hub: Option<String>,
    /// 等候管理員核准多久（例：15m、2h；0＝送出申請就結束，之後 watch／服務會繼續等）
    #[arg(long, value_name = "DUR")]
    pub wait: Option<String>,
    /// 這台電腦記得的 Hub 指紋和現在找到的不同時，仍改加入新的 Hub（確認過指紋才用）
    #[arg(long)]
    pub repin: bool,
    /// 接受 hub 核准的遠端動作（預設關）
    #[arg(long)]
    pub accept_remote_actions: bool,
    /// 允許對公網 hub 使用未加密的 http
    #[arg(long)]
    pub insecure_http: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DiscoverArgs {
    /// 等候區網廣播回應的時間
    #[arg(long, default_value = "3s", value_name = "DUR")]
    pub timeout: String,
    /// 不查公司 DNS 的 SRV 紀錄
    #[arg(long)]
    pub no_dns: bool,
    /// 不用區網廣播（mDNS）尋找
    #[arg(long)]
    pub no_mdns: bool,
    /// 允許對公網 hub 使用未加密的 http
    #[arg(long)]
    pub insecure_http: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum HubCmd {
    /// 用 mDNS 在區網上廣播這個 Hub（Hub 在 Docker Desktop／bridge 網路裡時，廣播出不了區網，改在這台執行）
    Advertise {
        /// Hub 的對外網址（電腦要連的那個，例：https://hub.corp.example 或 http://192.168.1.10:8088）
        #[arg(long, value_name = "URL")]
        url: String,
        /// 廣播的名稱（預設：Hub 的名稱＋這台電腦的名稱）
        #[arg(long)]
        name: Option<String>,
        /// 廣播多久就結束（預設一直執行到 Ctrl-C）
        #[arg(long, value_name = "DUR")]
        duration: Option<String>,
        /// 允許對公網 hub 使用未加密的 http
        #[arg(long)]
        insecure_http: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServiceCmd {
    /// 安裝並立即啟動（預設 --user：登入時啟動、免系統管理員；--system：開機就啟動的系統服務，需要系統管理員／root）
    Install {
        /// 系統服務（Windows 服務／systemd／LaunchDaemon）
        #[arg(long, conflicts_with = "user")]
        system: bool,
        /// 使用者層（登入時啟動；預設）
        #[arg(long)]
        user: bool,
        /// 完整掃描間隔（例：10m、1h）
        #[arg(long, value_name = "DUR")]
        interval: Option<String>,
    },
    /// 停止並移除開機自動啟動
    Uninstall {
        /// 移除系統服務
        #[arg(long, conflicts_with = "user")]
        system: bool,
        /// 移除使用者層（預設）
        #[arg(long)]
        user: bool,
    },
    /// 系統服務與使用者層的安裝與執行狀態
    Status,
    /// 重新啟動常駐行程（例如更新 ai-security-monitor 之後）
    Restart {
        /// 重新啟動系統服務
        #[arg(long)]
        system: bool,
    },
    /// 看常駐行程的 log
    Logs {
        /// 看系統服務的 log
        #[arg(long)]
        system: bool,
        /// 最後幾行
        #[arg(long, default_value_t = 100)]
        tail: usize,
    },
    /// Windows 服務入口（由服務控制管理員呼叫）
    #[command(hide = true)]
    Run {
        /// 完整掃描間隔
        #[arg(long, value_name = "DUR")]
        interval: Option<String>,
    },
}

#[derive(Args, Debug, Clone, Default)]
pub struct WatchArgs {
    /// 完整掃描間隔（預設取設定 scan.interval）
    #[arg(long, value_name = "DUR")]
    pub interval: Option<String>,
    /// 連線快照與心跳間隔（預設取設定 scan.snapshot_interval）
    #[arg(long, value_name = "DUR")]
    pub snapshot_interval: Option<String>,
    /// 只跑一輪（掃描＋快照＋上傳）就結束
    #[arg(long)]
    pub once: bool,
    /// 不上傳，只在本機掃描
    #[arg(long)]
    pub no_upload: bool,
    /// 以系統服務身分執行（服務管理器使用）
    #[arg(long, hide = true)]
    pub service: bool,
    /// 由 Windows 服務入口（`service run`）啟動：更新後交給服務的失敗動作重新啟動。
    #[arg(skip)]
    pub scm: bool,
}

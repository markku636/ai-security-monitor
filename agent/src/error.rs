//! 統一錯誤型別。對外（MCP / hub / `--json`）序列化成 `{ kind, code, message }`。
//!
//! `#[error(...)]` 一律為中性英文，僅供 Display / log；使用者可見的 `message` 於序列化時以 `tf!`
//! 依當前語言即時產生。

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("config error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("scan failed: {0}")]
    Scan(String),
    #[error("intel error: {0}")]
    Intel(String),
    #[error("firewall error: {0}")]
    Firewall(String),
    #[error("elevation required: {0}")]
    Elevation(String),
    #[error("external tool: {0}")]
    External(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("hub error: {0}")]
    Hub(String),
    #[error("hub auth rejected")]
    HubAuth,
    #[error("hub rejected payload: {0}")]
    HubRejected(String),
    /// Hub 身分驗證失敗（簽章不對、指紋和釘選的不同）：重試也不會過。
    #[error("hub identity: {0}")]
    HubIdentity(String),
    #[error("mcp error: {0}")]
    Mcp(String),
    #[error("ai provider: {0}")]
    Ai(String),
    #[error("capture error: {0}")]
    Capture(String),
    #[error("events error: {0}")]
    Events(String),
    #[error("update failed: {0}")]
    Update(String),
    #[error("service error: {0}")]
    Service(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("timeout after {0} ms")]
    Timeout(u64),
    #[error("cancelled")]
    Cancelled,
    /// 寫入 / 危險命令未加 `--yes`（或 `--force`）：等同預演，CLI 以 exit code 2 回報。
    #[error("confirmation required: {0}")]
    NeedsConfirm(String),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
}

impl AppError {
    /// 類別（snake_case，語言無關）。
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::Config(_) => "config",
            AppError::Storage(_) => "storage",
            AppError::Scan(_) => "scan",
            AppError::Intel(_) => "intel",
            AppError::Firewall(_) => "firewall",
            AppError::Elevation(_) => "elevation",
            AppError::External(_) => "external",
            AppError::Parse(_) => "parse",
            AppError::Hub(_) => "hub",
            AppError::HubAuth => "hub_auth",
            AppError::HubRejected(_) => "hub_rejected",
            AppError::HubIdentity(_) => "hub_identity",
            AppError::Mcp(_) => "mcp",
            AppError::Ai(_) => "ai",
            AppError::Capture(_) => "capture",
            AppError::Events(_) => "events",
            AppError::Update(_) => "update",
            AppError::Service(_) => "service",
            AppError::Unsupported(_) => "unsupported",
            AppError::Timeout(_) => "timeout",
            AppError::Cancelled => "cancelled",
            AppError::NeedsConfirm(_) => "needs_confirm",
            AppError::InvalidArg(_) => "invalid_arg",
        }
    }

    /// 錯誤碼（`ERR_*`，語言無關，給程式判斷）。
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Config(_) => "ERR_CONFIG",
            AppError::Storage(_) => "ERR_STORAGE",
            AppError::Scan(_) => "ERR_SCAN",
            AppError::Intel(_) => "ERR_INTEL",
            AppError::Firewall(_) => "ERR_FIREWALL",
            AppError::Elevation(_) => "ERR_ELEVATION",
            AppError::External(_) => "ERR_EXTERNAL",
            AppError::Parse(_) => "ERR_PARSE",
            AppError::Hub(_) => "ERR_HUB",
            AppError::HubAuth => "ERR_HUB_AUTH",
            AppError::HubRejected(_) => "ERR_HUB_REJECTED",
            AppError::HubIdentity(_) => "ERR_HUB_IDENTITY",
            AppError::Mcp(_) => "ERR_MCP",
            AppError::Ai(_) => "ERR_AI",
            AppError::Capture(_) => "ERR_CAPTURE",
            AppError::Events(_) => "ERR_EVENTS",
            AppError::Update(_) => "ERR_UPDATE",
            AppError::Service(_) => "ERR_SERVICE",
            AppError::Unsupported(_) => "ERR_UNSUPPORTED",
            AppError::Timeout(_) => "ERR_TIMEOUT",
            AppError::Cancelled => "ERR_CANCELLED",
            AppError::NeedsConfirm(_) => "ERR_NEEDS_CONFIRM",
            AppError::InvalidArg(_) => "ERR_INVALID_ARG",
        }
    }

    /// 使用者可見訊息（依當前語言）。
    pub fn message(&self) -> String {
        match self {
            AppError::Config(d) => tf!("設定錯誤：{detail}", detail = d),
            AppError::Storage(d) => tf!("儲存錯誤：{detail}", detail = d),
            AppError::Scan(d) => tf!("掃描失敗：{detail}", detail = d),
            AppError::Intel(d) => tf!("情資錯誤：{detail}", detail = d),
            AppError::Firewall(d) => tf!("防火牆錯誤：{detail}", detail = d),
            AppError::Elevation(d) => tf!("需要系統管理員權限：{detail}", detail = d),
            AppError::External(d) => tf!("外部工具錯誤：{detail}", detail = d),
            AppError::Parse(d) => tf!("解析錯誤：{detail}", detail = d),
            AppError::Hub(d) => tf!("Hub 錯誤：{detail}", detail = d),
            AppError::HubAuth => t!("Hub 拒絕了這把金鑰").to_string(),
            AppError::HubRejected(d) => tf!("Hub 拒收這份資料（不會重送）：{detail}", detail = d),
            AppError::HubIdentity(d) => tf!("Hub 身分驗證失敗：{detail}", detail = d),
            AppError::Mcp(d) => tf!("MCP 錯誤：{detail}", detail = d),
            AppError::Ai(d) => tf!("AI 提供者錯誤：{detail}", detail = d),
            AppError::Capture(d) => tf!("抓包錯誤：{detail}", detail = d),
            AppError::Events(d) => tf!("事件錯誤：{detail}", detail = d),
            AppError::Update(d) => tf!("更新失敗：{detail}", detail = d),
            AppError::Service(d) => tf!("服務錯誤：{detail}", detail = d),
            AppError::Unsupported(d) => tf!("不支援：{detail}", detail = d),
            AppError::Timeout(ms) => tf!("逾時（{ms} ms）", ms = ms),
            AppError::Cancelled => t!("已取消").to_string(),
            AppError::NeedsConfirm(d) => d.clone(),
            AppError::InvalidArg(d) => tf!("參數錯誤：{detail}", detail = d),
        }
    }
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AppError", 3)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.message())?;
        s.end()
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Parse(e.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_kind_code_message() {
        let e = AppError::Firewall("nft missing".into());
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["kind"], "firewall");
        assert_eq!(v["code"], "ERR_FIREWALL");
        assert!(v["message"].as_str().unwrap().contains("nft missing"));
    }

    #[test]
    fn every_variant_has_distinct_code() {
        let all = [
            AppError::Config(String::new()),
            AppError::Storage(String::new()),
            AppError::Scan(String::new()),
            AppError::Intel(String::new()),
            AppError::Firewall(String::new()),
            AppError::Elevation(String::new()),
            AppError::External(String::new()),
            AppError::Parse(String::new()),
            AppError::Hub(String::new()),
            AppError::HubAuth,
            AppError::HubRejected(String::new()),
            AppError::Mcp(String::new()),
            AppError::Ai(String::new()),
            AppError::Capture(String::new()),
            AppError::Events(String::new()),
            AppError::Update(String::new()),
            AppError::Service(String::new()),
            AppError::Unsupported(String::new()),
            AppError::Timeout(1),
            AppError::Cancelled,
            AppError::NeedsConfirm(String::new()),
            AppError::InvalidArg(String::new()),
        ];
        let mut codes: Vec<&str> = all.iter().map(|e| e.code()).collect();
        let n = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), n);
    }
}

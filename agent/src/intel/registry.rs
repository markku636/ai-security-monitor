//! 情資來源登錄：內建 `feeds/registry.json` ＋ 使用者自訂 `<config>/feeds/custom.json`，
//! 啟停狀態存在 `<config>/feeds/state.json`（覆蓋 `enabled_default`）。

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};
use crate::store;

pub const CUSTOM_FILE: &str = "feeds/custom.json";
pub const STATE_FILE: &str = "feeds/state.json";

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct License {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub attribution_required: bool,
    #[serde(default = "yes")]
    pub commercial_ok: bool,
    #[serde(default)]
    pub keep_header: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FeedFormat {
    PlainIpPerLine,
    CidrPerLine,
    SpamhausJson,
    UrlhausText,
    ThreatfoxJson,
    DshieldTab,
    IpsumTab,
    CisaKevJson,
    /// `0.0.0.0 domain`（hosts 檔格式）。
    Hosts,
    /// 一行一個網域。
    DomainPerLine,
    /// 一行一個網域，含子網域（`*.x` 或 `x` 皆可）。
    Wildcard,
    /// adblock 語法 `||domain^`。
    Adblock,
    MmdbGz,
    LookupApi,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeedKind {
    #[serde(rename = "ip")]
    Ip,
    #[serde(rename = "cidr")]
    Cidr,
    #[serde(rename = "ip+port")]
    IpPort,
    #[serde(rename = "domain")]
    Domain,
    #[serde(rename = "url")]
    Url,
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "asn")]
    Asn,
    #[serde(rename = "cve")]
    Cve,
    #[serde(rename = "geo")]
    Geo,
    #[serde(rename = "lookup")]
    Lookup,
    /// 加密 DNS（DoH／DoT）端點網域：不是惡意，只用來偵測繞過公司 DNS。
    #[serde(rename = "doh")]
    Doh,
}

impl FeedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FeedKind::Ip => "ip",
            FeedKind::Cidr => "cidr",
            FeedKind::IpPort => "ip+port",
            FeedKind::Domain => "domain",
            FeedKind::Url => "url",
            FeedKind::Hash => "hash",
            FeedKind::Asn => "asn",
            FeedKind::Cve => "cve",
            FeedKind::Geo => "geo",
            FeedKind::Lookup => "lookup",
            FeedKind::Doh => "doh",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FeedDirection {
    Inbound,
    Outbound,
    #[default]
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedEntry {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub urls: Vec<String>,
    pub format: FeedFormat,
    pub kind: FeedKind,
    #[serde(default)]
    pub direction: FeedDirection,
    #[serde(default)]
    pub confidence: u8,
    pub license: License,
    #[serde(default = "default_refresh")]
    pub refresh_interval: String,
    #[serde(default)]
    pub requires_api_key: Option<String>,
    #[serde(default)]
    pub enabled_default: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// 網域清單的條目是否涵蓋子網域（`evil.example` 也擋 `a.evil.example`）；false＝只比完全相同。
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub match_subdomains: bool,
    /// 使用者自訂（custom.json）來源。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub custom: bool,
}

fn default_refresh() -> String {
    "1h".into()
}

impl FeedEntry {
    pub fn refresh(&self) -> Duration {
        humantime::parse_duration(&self.refresh_interval).unwrap_or(Duration::from_secs(3600))
    }

    /// 可拿來比對連線 / 網域的封鎖清單類來源。
    pub fn is_blocklist(&self) -> bool {
        matches!(
            self.kind,
            FeedKind::Ip | FeedKind::Cidr | FeedKind::IpPort | FeedKind::Domain | FeedKind::Asn
        )
    }

    pub fn source_url(&self) -> String {
        self.urls.first().cloned().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistryFile {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub feeds: Vec<FeedEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeedState {
    #[serde(default)]
    pub enabled: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub feeds: Vec<FeedEntry>,
    pub state: FeedState,
    pub warnings: Vec<String>,
    /// 設定的使用情境允許只限非商業用途的來源（`config.intel.noncommercial()`）；false 時那些來源一律當作關閉。
    pub allow_noncommercial: bool,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 48
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Registry {
    pub fn builtin() -> AppResult<RegistryFile> {
        serde_json::from_str(crate::embedded::registry_json())
            .map_err(|e| AppError::Intel(tf!("內建情資登錄格式錯誤：{e}", e = e)))
    }

    pub fn load(dir: &Path) -> AppResult<Registry> {
        let mut feeds = Self::builtin()?.feeds;
        let mut warnings = Vec::new();
        let custom: RegistryFile = store::read_json_in(dir, CUSTOM_FILE)?;
        for mut f in custom.feeds {
            if !valid_id(&f.id) {
                warnings.push(tf!("自訂情資 id 不合法，已略過：{id}", id = f.id));
                continue;
            }
            if feeds.iter().any(|b| b.id == f.id) {
                warnings.push(tf!("自訂情資 id 與內建重複，已略過：{id}", id = f.id));
                continue;
            }
            if f.urls.is_empty() || !f.urls.iter().all(|u| u.starts_with("https://")) {
                warnings.push(tf!("自訂情資必須使用 https 網址，已略過：{id}", id = f.id));
                continue;
            }
            f.custom = true;
            feeds.push(f);
        }
        let state: FeedState = store::read_json_in(dir, STATE_FILE)?;
        let allow_noncommercial = crate::config::load(dir)
            .map(|c| c.intel.noncommercial())
            .unwrap_or(false);
        Ok(Registry {
            feeds,
            state,
            warnings,
            allow_noncommercial,
        })
    }

    pub fn get(&self, id: &str) -> Option<&FeedEntry> {
        self.feeds.iter().find(|f| f.id == id)
    }

    /// 實際會用的來源：自己打開（或預設開）而且授權允許目前的使用情境。
    pub fn is_enabled(&self, f: &FeedEntry) -> bool {
        self.wanted(f) && self.license_ok(f)
    }

    /// 使用者的開關（不看授權）。
    pub fn wanted(&self, f: &FeedEntry) -> bool {
        self.state.enabled.get(&f.id).copied().unwrap_or(f.enabled_default)
    }

    /// 授權允許目前的使用情境（商用情境不能用只限非商業用途的來源）。
    pub fn license_ok(&self, f: &FeedEntry) -> bool {
        f.license.commercial_ok || self.allow_noncommercial
    }

    /// 開著但因為「只限非商業用途」而沒用的來源。
    pub fn license_blocked(&self, f: &FeedEntry) -> bool {
        self.wanted(f) && !self.license_ok(f)
    }

    pub fn enabled(&self) -> impl Iterator<Item = &FeedEntry> {
        self.feeds.iter().filter(|f| self.is_enabled(f))
    }

    /// 啟用 / 停用一個來源（寫 state.json）。
    pub fn set_enabled(dir: &Path, id: &str, on: bool) -> AppResult<()> {
        let reg = Self::load(dir)?;
        if reg.get(id).is_none() {
            return Err(AppError::InvalidArg(tf!("沒有這個情資來源：{id}", id = id)));
        }
        let mut state = reg.state;
        state.enabled.insert(id.to_string(), on);
        store::ensure_dir(&dir.join("feeds"))?;
        store::write_json_in(dir, STATE_FILE, &state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_parses_and_ids_are_unique() {
        let r = Registry::builtin().unwrap();
        assert!(r.feeds.len() >= 20);
        let mut ids: Vec<&str> = r.feeds.iter().map(|f| f.id.as_str()).collect();
        let n = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n);
        for f in &r.feeds {
            assert!(valid_id(&f.id), "{}", f.id);
            assert_ne!(f.format, FeedFormat::Unknown, "{}", f.id);
            assert!(!f.license.url.is_empty(), "{}", f.id);
            assert!(f.urls.iter().all(|u| u.starts_with("https://")), "{}", f.id);
        }
        let dshield = r.feeds.iter().find(|f| f.id == "dshield-block").unwrap();
        assert!(!dshield.license.commercial_ok);
    }

    #[test]
    fn custom_feeds_and_state_overrides() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("feeds")).unwrap();
        std::fs::write(
            dir.path().join(CUSTOM_FILE),
            r#"{"feeds":[
              {"id":"my-list","name":"Mine","vendor":"Me","urls":["https://example.test/list.txt"],"format":"plain-ip-per-line","kind":"ip","confidence":60,"license":{"name":"private","url":"https://example.test"},"enabled_default":true},
              {"id":"abusech-feodo","name":"dup","vendor":"x","urls":["https://x.test"],"format":"plain-ip-per-line","kind":"ip","license":{"name":"x","url":"https://x"}},
              {"id":"plain-http","name":"bad","vendor":"x","urls":["http://x.test"],"format":"plain-ip-per-line","kind":"ip","license":{"name":"x","url":"https://x"}}
            ]}"#,
        )
        .unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        assert!(reg.get("my-list").unwrap().custom);
        assert_eq!(reg.warnings.len(), 2);
        assert!(reg.is_enabled(reg.get("abusech-feodo").unwrap()));
        Registry::set_enabled(dir.path(), "abusech-feodo", false).unwrap();
        let reg = Registry::load(dir.path()).unwrap();
        assert!(!reg.is_enabled(reg.get("abusech-feodo").unwrap()));
        assert!(Registry::set_enabled(dir.path(), "nope", true).is_err());
    }
}

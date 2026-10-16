//! 內嵌的對照表：藍屏代碼（`feeds/events/bugchecks.json`）與常見事件 ID（`feeds/events/known-ids.json`）。

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Localized<T> {
    pub zh: T,
    pub en: T,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Bugcheck {
    pub code: String,
    pub name: String,
    pub causes: Localized<Vec<String>>,
    pub fix: Localized<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnownEvent {
    pub id: u32,
    pub provider: String,
    pub category: String,
    pub zh: String,
    pub en: String,
}

#[derive(Deserialize, Default)]
struct BugcheckFile {
    #[serde(default)]
    bugchecks: Vec<Bugcheck>,
}

#[derive(Deserialize, Default)]
struct KnownFile {
    #[serde(default)]
    events: Vec<KnownEvent>,
}

fn english() -> bool {
    crate::i18n::current() == crate::i18n::Lang::En
}

pub fn bugchecks() -> Vec<Bugcheck> {
    let text = crate::embedded::feeds_file("events/bugchecks.json").unwrap_or("{}");
    serde_json::from_str::<BugcheckFile>(text).unwrap_or_default().bugchecks
}

pub fn known_events() -> Vec<KnownEvent> {
    let text = crate::embedded::feeds_file("events/known-ids.json").unwrap_or("{}");
    serde_json::from_str::<KnownFile>(text).unwrap_or_default().events
}

/// `0x7E`、`7e`、`126`、`0x0000007e (0xffff…, …)` → 126。
pub fn parse_code(s: &str) -> Option<u32> {
    let first = s
        .trim()
        .split(|c: char| c.is_whitespace() || c == '(' || c == ',')
        .next()?;
    let t = first.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
    }
    if t.chars().all(|c| c.is_ascii_digit()) {
        return t.parse().ok();
    }
    if t.chars().all(|c| c.is_ascii_hexdigit()) {
        return u32::from_str_radix(t, 16).ok();
    }
    None
}

pub fn code_hex(code: u32) -> String {
    format!("0x{code:08X}")
}

pub fn lookup_bugcheck(code: u32) -> Option<Bugcheck> {
    bugchecks().into_iter().find(|b| parse_code(&b.code) == Some(code))
}

/// 依目前語言取原因與處置。
pub fn bugcheck_text(b: &Bugcheck) -> (Vec<String>, String) {
    if english() {
        (b.causes.en.clone(), b.fix.en.clone())
    } else {
        (b.causes.zh.clone(), b.fix.zh.clone())
    }
}

pub fn lookup_event(id: u32, provider: Option<&str>) -> Vec<KnownEvent> {
    known_events()
        .into_iter()
        .filter(|e| e.id == id && provider.map(|p| e.provider.eq_ignore_ascii_case(p)).unwrap_or(true))
        .collect()
}

pub fn event_text(e: &KnownEvent) -> String {
    if english() {
        e.en.clone()
    } else {
        e.zh.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_parse_in_every_shape() {
        assert_eq!(parse_code("0x7E"), Some(0x7E));
        assert_eq!(parse_code("0x0000007e (0xffffffffc0000005, 0x0, 0x0, 0x0)"), Some(0x7E));
        assert_eq!(parse_code("126"), Some(126));
        assert_eq!(parse_code("d1"), Some(0xD1));
        assert_eq!(parse_code("nope"), None);
        assert_eq!(code_hex(0x124), "0x00000124");
    }

    #[test]
    fn tables_are_embedded_and_complete() {
        let all = bugchecks();
        assert!(all.len() >= 30);
        for b in &all {
            assert!(parse_code(&b.code).is_some(), "{}", b.code);
            assert!(!b.causes.zh.is_empty() && !b.causes.en.is_empty(), "{}", b.name);
            assert!(!b.fix.zh.is_empty() && !b.fix.en.is_empty(), "{}", b.name);
        }
        assert_eq!(lookup_bugcheck(0x124).unwrap().name, "WHEA_UNCORRECTABLE_ERROR");
        assert!(lookup_bugcheck(0xDEAD).is_none());
        assert_eq!(lookup_event(41, None)[0].category, "crash");
        assert_eq!(lookup_event(4625, Some("microsoft-windows-security-auditing")).len(), 1);
    }
}

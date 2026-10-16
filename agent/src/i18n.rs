//! i18n（沿用 db-kit 慣例）。
//!
//! - **繁中原文即 translation key**：查無譯文時回傳原字面值（identity fallback）。
//! - 插值佔位符 `{name}`：`tf!("已封鎖 {n} 個位址", n = count)`。
//! - 語言為進程層級全域狀態（`AtomicU8`）；CLI 啟動時依 `--lang` / `ASA_LANG` / config 決定。

use std::sync::atomic::{AtomicU8, Ordering};

/// 介面語言。預設 zh-TW。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lang {
    #[default]
    ZhTw,
    En,
}

impl Lang {
    pub fn as_code(self) -> &'static str {
        match self {
            Lang::ZhTw => "zh-TW",
            Lang::En => "en",
        }
    }

    /// 由語言碼解析（大小寫不敏感，接受 OS locale 寫法如 `en_US.UTF-8`）。
    pub fn from_code(s: &str) -> Option<Lang> {
        let s = s.trim().to_ascii_lowercase();
        let s = s.split('.').next().unwrap_or(&s);
        match s {
            "zh-tw" | "zh" | "zh-hant" | "zh_tw" | "zh-hk" | "zh_hk" | "zh-mo" => Some(Lang::ZhTw),
            "en" | "en-us" | "en_us" | "en-gb" | "en_gb" => Some(Lang::En),
            _ => None,
        }
    }
}

static LANG: AtomicU8 = AtomicU8::new(0);

pub fn set_lang(l: Lang) {
    LANG.store(l as u8, Ordering::Relaxed);
}

pub fn current() -> Lang {
    match LANG.load(Ordering::Relaxed) {
        1 => Lang::En,
        _ => Lang::ZhTw,
    }
}

fn lookup_in(l: Lang, zh: &str) -> Option<&'static str> {
    use crate::locales as loc;
    match l {
        Lang::ZhTw => None,
        Lang::En => loc::en::lookup(zh).or_else(|| loc::en_ext::lookup(zh)),
    }
}

/// 查目前語言譯文；查無回 `None`（不做 identity fallback）。給 clap help 這類執行期 `String` 用。
pub fn lookup_opt(zh: &str) -> Option<&'static str> {
    let l = current();
    if l == Lang::ZhTw {
        return None;
    }
    lookup_in(l, zh)
}

/// 查表；查無回原字面值。
pub fn lookup(zh: &'static str) -> &'static str {
    lookup_opt(zh).unwrap_or(zh)
}

/// `{name}` 佔位符執行期取代。key 須為 `[A-Za-z0-9_]+`；找不到的 key 保留字面。
pub fn interpolate(tpl: &str, args: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(tpl.len());
    let mut rest = tpl;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}') {
            Some(close) => {
                let key = &after[..close];
                let is_ident = !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
                if is_ident {
                    match args.iter().find(|(k, _)| *k == key) {
                        Some((_, v)) => out.push_str(v),
                        None => {
                            out.push('{');
                            out.push_str(key);
                            out.push('}');
                        }
                    }
                    rest = &after[close + 1..];
                } else {
                    out.push('{');
                    rest = after;
                }
            }
            None => {
                out.push('{');
                out.push_str(after);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// 翻譯字面值 → `&'static str`。
#[macro_export]
macro_rules! t {
    ($zh:literal) => {
        $crate::i18n::lookup($zh)
    };
}

/// 翻譯 + `{name}` 插值 → `String`。
#[macro_export]
macro_rules! tf {
    ($zh:literal, $($k:ident = $v:expr),* $(,)?) => {
        $crate::i18n::interpolate(
            $crate::i18n::lookup($zh),
            &[$((stringify!($k), ($v).to_string())),*],
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LANG_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn interpolate_replaces_named_placeholders() {
        let s = interpolate(
            "已封鎖 {n} 個位址到 {backend}",
            &[("n", "3".into()), ("backend", "nft".into())],
        );
        assert_eq!(s, "已封鎖 3 個位址到 nft");
    }

    #[test]
    fn interpolate_keeps_unknown_and_malformed() {
        assert_eq!(interpolate("{a}-{b}", &[("a", "1".into())]), "1-{b}");
        assert_eq!(interpolate("100% {done}", &[]), "100% {done}");
        assert_eq!(interpolate("open {only", &[]), "open {only");
    }

    #[test]
    fn identity_fallback_in_zh() {
        let _g = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_lang(Lang::ZhTw);
        assert_eq!(lookup("完全沒有收錄的字串 xyz"), "完全沒有收錄的字串 xyz");
    }

    #[test]
    fn lang_code_roundtrip() {
        assert_eq!(Lang::from_code("EN"), Some(Lang::En));
        assert_eq!(Lang::from_code("zh-TW"), Some(Lang::ZhTw));
        assert_eq!(Lang::from_code("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::from_code("fr"), None);
        for l in [Lang::ZhTw, Lang::En] {
            assert_eq!(Lang::from_code(l.as_code()), Some(l));
        }
    }

    #[test]
    fn set_lang_round_trips() {
        let _g = LANG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for l in [Lang::En, Lang::ZhTw] {
            set_lang(l);
            assert_eq!(current(), l);
        }
    }
}

//! 環境變數：新前綴 `AI_SECURITY_MONITOR_*` 優先，讀不到再讀舊的 `ASA_*`（改名前的版本與既有部署腳本）。
//!
//! 呼叫端一律傳**不含前綴**的名稱，例如 `var("LANG")` 依序讀 `AI_SECURITY_MONITOR_LANG`、`ASA_LANG`。
//! 空字串視同沒設定（才能讓舊名接手）。

pub const PREFIX: &str = "AI_SECURITY_MONITOR_";
pub const LEGACY_PREFIX: &str = "ASA_";

/// 新名（例 `AI_SECURITY_MONITOR_LANG`）。
pub fn name(rest: &str) -> String {
    format!("{PREFIX}{rest}")
}

/// 舊名（例 `ASA_LANG`）。
pub fn legacy_name(rest: &str) -> String {
    format!("{LEGACY_PREFIX}{rest}")
}

/// 先讀新名、再讀舊名；都沒有（或是空字串）回 `None`。
pub fn var(rest: &str) -> Option<String> {
    var_from(rest, |k| std::env::var(k).ok())
}

/// 同 [`var`]，但回 `OsString`（路徑用）。
pub fn var_os(rest: &str) -> Option<std::ffi::OsString> {
    [name(rest), legacy_name(rest)]
        .into_iter()
        .find_map(|k| std::env::var_os(k).filter(|v| !v.is_empty()))
}

/// 可測試的核心：`get` 回傳某個環境變數的值。
pub fn var_from(rest: &str, get: impl Fn(&str) -> Option<String>) -> Option<String> {
    [name(rest), legacy_name(rest)]
        .into_iter()
        .find_map(|k| get(&k).filter(|v| !v.is_empty()))
}

/// clap 的 `env = "AI_SECURITY_MONITOR_…"` 只認一個名字：解析參數前把只設了舊名的值複製到新名。
pub fn seed_from_legacy(rests: &[&str]) {
    for rest in rests {
        let new = name(rest);
        if std::env::var_os(&new).is_some_and(|v| !v.is_empty()) {
            continue;
        }
        if let Some(v) = std::env::var_os(legacy_name(rest)).filter(|v| !v.is_empty()) {
            std::env::set_var(new, v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn new_name_wins_then_legacy() {
        let mut m: HashMap<&str, &str> = HashMap::new();
        let get = |m: &HashMap<&str, &str>, k: &str| m.get(k).map(|v| v.to_string());
        assert_eq!(var_from("LANG", |k| get(&m, k)), None);
        m.insert("ASA_LANG", "en");
        assert_eq!(var_from("LANG", |k| get(&m, k)).as_deref(), Some("en"));
        m.insert("AI_SECURITY_MONITOR_LANG", "zh-TW");
        assert_eq!(var_from("LANG", |k| get(&m, k)).as_deref(), Some("zh-TW"));
        // 新名是空字串：當作沒設，讓舊名接手
        m.insert("AI_SECURITY_MONITOR_LANG", "");
        assert_eq!(var_from("LANG", |k| get(&m, k)).as_deref(), Some("en"));
        assert_eq!(
            name("SECRET_HUB_CLIENT_KEY"),
            "AI_SECURITY_MONITOR_SECRET_HUB_CLIENT_KEY"
        );
        assert_eq!(legacy_name("SECRET_HUB_CLIENT_KEY"), "ASA_SECRET_HUB_CLIENT_KEY");
    }

    #[test]
    fn seeds_new_name_from_legacy() {
        // 用專屬名稱，避免與其他測試共用環境變數
        std::env::set_var("ASA_ZZ_SEED_TEST", "legacy");
        seed_from_legacy(&["ZZ_SEED_TEST"]);
        assert_eq!(
            std::env::var("AI_SECURITY_MONITOR_ZZ_SEED_TEST").as_deref(),
            Ok("legacy")
        );
        std::env::set_var("AI_SECURITY_MONITOR_ZZ_SEED_TEST", "new");
        seed_from_legacy(&["ZZ_SEED_TEST"]);
        assert_eq!(std::env::var("AI_SECURITY_MONITOR_ZZ_SEED_TEST").as_deref(), Ok("new"));
        assert_eq!(var("ZZ_SEED_TEST").as_deref(), Some("new"));
        assert!(var_os("ZZ_SEED_TEST").is_some());
    }
}

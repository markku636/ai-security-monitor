//! 內嵌 repo 根目錄 `feeds/`（情資登錄、硬化策略、bugcheck 表、known-good）。
//! 執行期 `<config>/feeds/registry.json`、`custom.json` 可覆寫 / 合併。

use include_dir::{include_dir, Dir};

pub static FEEDS: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../feeds");

/// 取內嵌檔（UTF-8 文字）。路徑相對 `feeds/`，例 `registry.json`、`policies/linux/sshd.yml`。
pub fn feeds_file(path: &str) -> Option<&'static str> {
    FEEDS.get_file(path).and_then(|f| f.contents_utf8())
}

pub fn registry_json() -> &'static str {
    feeds_file("registry.json").expect("feeds/registry.json is embedded at build time")
}

pub fn known_good_json() -> &'static str {
    feeds_file("known-good.json").expect("feeds/known-good.json is embedded at build time")
}

/// 列出某子目錄下的檔案路徑（相對 `feeds/`）。
pub fn list_dir(prefix: &str) -> Vec<&'static str> {
    FEEDS
        .get_dir(prefix)
        .map(|d| {
            d.files()
                .filter_map(|f| f.path().to_str())
                .map(|p| p.replace('\\', "/"))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| FEEDS.get_file(&p).and_then(|f| f.path().to_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(registry_json()).unwrap();
        assert!(v["feeds"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
    }

    #[test]
    fn known_good_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(known_good_json()).unwrap();
        assert!(v["lists"].is_array());
    }
}

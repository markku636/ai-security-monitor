//! 網域的推測型判斷（不靠情資）：可註冊網域（eTLD+1）、熱門網域、DGA（亂數產生的網域）分數、
//! 少見頂級網域與長高熵標籤。給即時 DNS 偵測與離線 pcap 分析共用。
//!
//! 內嵌資料（`feeds/dns/`，`scripts/update-dns-data.mjs` 產生）：
//! - `public_suffix_list.dat`：Mozilla Public Suffix List（MPL-2.0），含 private 區段，
//!   讓 `x.github.io`、`y.duckdns.org` 各自算一個可註冊網域，不會整批被放行。
//! - `toplist.txt`：Majestic Million 前 1 萬名（CC BY 3.0），只用來壓低推測型誤報，不當安全保證。

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use crate::intel::domainset;

struct Psl {
    rules: HashSet<&'static str>,
    /// `*.ck` 這類萬用規則，存 `ck`。
    wild: HashSet<&'static str>,
    /// `!www.ck` 這類例外規則，存 `www.ck`。
    exceptions: HashSet<&'static str>,
}

fn psl() -> &'static Psl {
    static PSL: OnceLock<Psl> = OnceLock::new();
    PSL.get_or_init(|| {
        let mut p = Psl {
            rules: HashSet::new(),
            wild: HashSet::new(),
            exceptions: HashSet::new(),
        };
        let text = crate::embedded::feeds_file("dns/public_suffix_list.dat").unwrap_or("");
        for line in text.lines() {
            let l = line.split_whitespace().next().unwrap_or("");
            if l.is_empty() || l.starts_with("//") || !l.is_ascii() {
                continue;
            }
            if let Some(rest) = l.strip_prefix('!') {
                p.exceptions.insert(rest);
            } else if let Some(rest) = l.strip_prefix("*.") {
                p.wild.insert(rest);
            } else {
                p.rules.insert(l);
            }
        }
        p
    })
}

/// 每一層後綴在字串裡的起點：`a.b.c` → [0, 2, 4]。
fn label_starts(name: &str) -> Vec<usize> {
    let mut v = vec![0];
    v.extend(name.match_indices('.').map(|(i, _)| i + 1));
    v
}

/// 公共後綴（`com`、`co.uk`、`github.io`）。名稱要先轉小寫、去結尾點。
pub fn public_suffix(name: &str) -> &str {
    let p = psl();
    let starts = label_starts(name);
    for (i, &s) in starts.iter().enumerate() {
        let cand = &name[s..];
        if p.exceptions.contains(cand) {
            return starts.get(i + 1).map(|&n| &name[n..]).unwrap_or(cand);
        }
        if p.rules.contains(cand) {
            return cand;
        }
        if let Some(&next) = starts.get(i + 1) {
            if p.wild.contains(&name[next..]) {
                return cand;
            }
        }
    }
    // 沒有規則：預設規則 `*`，最後一段就是公共後綴。
    &name[*starts.last().unwrap_or(&0)..]
}

/// 可註冊網域（eTLD+1）：`a.b.example.co.uk` → `example.co.uk`；名稱本身就是公共後綴時回 None。
pub fn registrable_domain(name: &str) -> Option<&str> {
    let ps = public_suffix(name);
    let head = name.strip_suffix(ps)?.strip_suffix('.')?;
    let start = head.rfind('.').map(|i| i + 1).unwrap_or(0);
    Some(&name[start..])
}

/// 可註冊網域最左邊那段（`example.co.uk` 的 `example`），DGA 判斷看的就是它。
fn registrable_label(name: &str) -> Option<&str> {
    registrable_domain(name).and_then(|r| r.split('.').next())
}

fn toplist() -> &'static HashSet<u64> {
    static TOP: OnceLock<HashSet<u64>> = OnceLock::new();
    TOP.get_or_init(|| top_domains().map(domainset::hash).collect())
}

fn top_domains() -> impl Iterator<Item = &'static str> {
    crate::embedded::feeds_file("dns/toplist.txt")
        .unwrap_or("")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// 名稱本身或它的可註冊網域在熱門清單裡。
pub fn is_popular(name: &str) -> bool {
    let t = toplist();
    t.contains(&domainset::hash(name)) || registrable_domain(name).is_some_and(|r| t.contains(&domainset::hash(r)))
}

/// 字元二元組（bigram）模型：從熱門網域的可註冊標籤學出「像人取的名字」的字母組合機率。
struct Bigram {
    logp: HashMap<(u8, u8), f64>,
    unseen: f64,
}

const BOS: u8 = b'^';
const EOS: u8 = b'$';

fn bigram() -> &'static Bigram {
    static B: OnceLock<Bigram> = OnceLock::new();
    B.get_or_init(|| {
        let mut pair: HashMap<(u8, u8), f64> = HashMap::new();
        let mut first: HashMap<u8, f64> = HashMap::new();
        for d in top_domains() {
            let Some(label) = registrable_label(d) else {
                continue;
            };
            let bytes: Vec<u8> = std::iter::once(BOS)
                .chain(label.bytes())
                .chain(std::iter::once(EOS))
                .collect();
            for w in bytes.windows(2) {
                *pair.entry((w[0], w[1])).or_default() += 1.0;
                *first.entry(w[0]).or_default() += 1.0;
            }
        }
        // 加一平滑：字母表 a-z、0-9、-、_ 加上結尾。
        const V: f64 = 39.0;
        let logp = pair
            .iter()
            .map(|(&(a, b), &n)| ((a, b), ((n + 1.0) / (first.get(&a).copied().unwrap_or(0.0) + V)).log2()))
            .collect();
        let avg_first = if first.is_empty() {
            1.0
        } else {
            first.values().sum::<f64>() / first.len() as f64
        };
        Bigram {
            logp,
            unseen: (1.0 / (avg_first + V)).log2(),
        }
    })
}

/// 標籤的平均二元組對數機率（越低越不像人取的名字）。
pub fn bigram_score(label: &str) -> f64 {
    let m = bigram();
    let bytes: Vec<u8> = std::iter::once(BOS)
        .chain(label.bytes().map(|b| b.to_ascii_lowercase()))
        .chain(std::iter::once(EOS))
        .collect();
    let n = (bytes.len() - 1) as f64;
    bytes
        .windows(2)
        .map(|w| m.logp.get(&(w[0], w[1])).copied().unwrap_or(m.unseen))
        .sum::<f64>()
        / n
}

/// DGA 判斷門檻：標籤至少這麼長才判（短名字樣本太少，誤報多）。
pub const DGA_MIN_LEN: usize = 8;
/// 平均二元組對數機率低於這個值視為亂數產生（由 `dga_threshold_separates_samples` 測試校準）。
pub const DGA_BIGRAM_MAX: f64 = -5.0;

/// 看起來像 DGA 產生的網域：可註冊標籤夠長、字母組合不像人取的名字，且不是熱門網域。
pub fn looks_generated(name: &str) -> bool {
    let Some(label) = registrable_label(name) else {
        return false;
    };
    // punycode（國際化網域，`xn--` 開頭）本來就不像英文字母組合，不判。
    label.len() >= DGA_MIN_LEN
        && !label.starts_with("xn--")
        && !is_popular(name)
        && bigram_score(label) < DGA_BIGRAM_MAX
}

/// Chromium 開機時會查 3 個 7–15 個字母的單段名稱，測 DNS 有沒有攔截 NXDOMAIN；不是 DGA。
pub fn is_chromium_probe(name: &str) -> bool {
    (7..=15).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase())
}

/// 網域名稱是否可疑：最長標籤很長且高熵（DGA／DNS 通道），或少見頂級網域。
pub fn suspicious_domain(name: &str) -> Option<String> {
    const RARE_TLDS: [&str; 12] = [
        "zip", "mov", "top", "xyz", "tk", "gq", "ml", "cf", "ga", "click", "country", "kim",
    ];
    let labels: Vec<&str> = name.split('.').collect();
    if let Some(tld) = labels.last() {
        if RARE_TLDS.contains(tld) {
            return Some(format!("rare-tld .{tld}"));
        }
    }
    let longest = labels
        .iter()
        .take(labels.len().saturating_sub(2).max(1))
        .max_by_key(|l| l.len())?;
    if longest.len() >= 20 && shannon(longest) >= 3.6 {
        return Some(format!("high-entropy label ({:.1} bits)", shannon(longest)));
    }
    None
}

/// Shannon 熵（bits／字元）。
pub fn shannon(s: &str) -> f64 {
    let mut counts: HashMap<u8, f64> = HashMap::new();
    for b in s.bytes() {
        *counts.entry(b).or_default() += 1.0;
    }
    let n = s.len() as f64;
    counts.values().map(|c| -(c / n) * (c / n).log2()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_domains_follow_psl() {
        assert_eq!(registrable_domain("a.b.example.com"), Some("example.com"));
        assert_eq!(registrable_domain("www.example.co.uk"), Some("example.co.uk"));
        assert_eq!(registrable_domain("evil.github.io"), Some("evil.github.io"));
        assert_eq!(registrable_domain("x.y.duckdns.org"), Some("y.duckdns.org"));
        assert_eq!(registrable_domain("example.com"), Some("example.com"));
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("co.uk"), None);
        // 沒有規則的 TLD 走預設規則
        assert_eq!(registrable_domain("a.b.unknowntld"), Some("b.unknowntld"));
        // 萬用與例外：*.ck、!www.ck
        assert_eq!(public_suffix("a.b.ck"), "b.ck");
        assert_eq!(registrable_domain("www.ck"), Some("www.ck"));
    }

    #[test]
    fn popular_domains() {
        assert!(is_popular("www.google.com"));
        assert!(is_popular("google.com"));
        assert!(!is_popular("q7x9z2k4m8v1b3n5.com"));
    }

    #[test]
    fn dga_threshold_separates_samples() {
        let benign = [
            "microsoft",
            "wikipedia",
            "stackoverflow",
            "cloudflare",
            "amazonaws",
            "salesforce",
            "washingtonpost",
            "booking",
            "spotify",
            "dropbox",
            "pinterest",
            "telegram",
            "shopping",
            "university",
            "bloomberg",
        ];
        let dga = [
            "q7x9z2k4m8v1b3n5",
            "xkmqjzdlwpvbt",
            "kqfcpqbyqllgbr",
            "zxcvqwrtplkj",
            "fjwqxzkvbnm",
            "rhqjxvzwkpld",
            "a1b9c8d7e6f5g4",
            "vqzxjkwpfm",
            "lkjhgfdsaqwrtz",
        ];
        for b in benign {
            let s = bigram_score(b);
            assert!(s >= DGA_BIGRAM_MAX, "benign {b} scored {s:.2}");
        }
        for d in dga {
            let s = bigram_score(d);
            assert!(s < DGA_BIGRAM_MAX, "dga {d} scored {s:.2}");
        }
        assert!(looks_generated("kqfcpqbyqllgbr.net"));
        assert!(!looks_generated("www.microsoft.com"));
        assert!(!looks_generated("abc.net"));
    }

    #[test]
    fn chromium_probes() {
        assert!(is_chromium_probe("qwkdhsueyt"));
        assert!(!is_chromium_probe("short"));
        assert!(!is_chromium_probe("example.com"));
    }

    #[test]
    fn suspicious_domains() {
        assert!(suspicious_domain("x9q2kz7f1v8m3n4b6c0d2e5r.example.com").is_some());
        assert!(suspicious_domain("login.microsoftonline.com").is_none());
        assert!(suspicious_domain("free-gift.zip").is_some());
        assert!(suspicious_domain("www.googleapis.com").is_none());
    }
}

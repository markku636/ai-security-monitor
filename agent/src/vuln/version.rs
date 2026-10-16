//! 寬鬆的版本比較：依非英數字元切段，數字段比數值、文字段比字串；`138.0.7204.96` vs `138.0.7204.100`、`7.13` vs `7.01`、
//! `2.45.1.windows.1` vs `2.45.1` 都能比。dpkg 的 epoch（`1:`）先去掉。

use std::cmp::Ordering;

fn segments(v: &str) -> Vec<String> {
    let v = v.trim();
    let v = match v.split_once(':') {
        Some((epoch, rest)) if epoch.chars().all(|c| c.is_ascii_digit()) => rest,
        _ => v,
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut digit: Option<bool> = None;
    for c in v.chars() {
        if !c.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            digit = None;
            continue;
        }
        let d = c.is_ascii_digit();
        if digit.is_some_and(|x| x != d) && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        digit = Some(d);
        cur.push(c);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 預發行標記（`1.0rc1` 比 `1.0` 舊）；其他文字尾巴（`2.45.1.windows.1`）視為同版或較新。
fn is_prerelease(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "a" | "b" | "alpha" | "beta" | "rc" | "pre" | "preview" | "dev" | "snapshot"
    )
}

pub fn compare(a: &str, b: &str) -> Ordering {
    let (sa, sb) = (segments(a), segments(b));
    for i in 0..sa.len().max(sb.len()) {
        let (x, y) = match (sa.get(i), sb.get(i)) {
            (Some(x), Some(y)) => (x.as_str(), y.as_str()),
            // 一邊已用完：另一邊剩文字尾巴時依是否預發行決定
            (Some(x), None) if x.parse::<u64>().is_err() => {
                return if is_prerelease(x) {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (None, Some(y)) if y.parse::<u64>().is_err() => {
                return if is_prerelease(y) {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            (x, y) => (
                x.map(String::as_str).unwrap_or("0"),
                y.map(String::as_str).unwrap_or("0"),
            ),
        };
        let o = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(p), Ok(q)) => p.cmp(&q),
            // 數字比文字新（1.0 > 1.0beta 的近似）
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
            _ => x.to_ascii_lowercase().cmp(&y.to_ascii_lowercase()),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    Ordering::Equal
}

pub fn older_than(installed: &str, fixed: &str) -> bool {
    !installed.trim().is_empty() && compare(installed, fixed) == Ordering::Less
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_common_shapes() {
        assert!(older_than("138.0.7204.50", "138.0.7204.96"));
        assert!(!older_than("138.0.7204.100", "138.0.7204.96"));
        assert!(older_than("7.01", "7.13"));
        assert!(!older_than("7.13", "7.13"));
        assert!(older_than("24.08", "24.09"));
        assert!(!older_than("2.45.1.windows.1", "2.45.1"));
        assert!(older_than("0.80", "0.81"));
        assert!(older_than("20.11.0", "22.0.0"));
        assert!(!older_than("1:2.45.2-1", "2.45.1"));
        assert!(older_than("3.9.13150.0", "3.11.0"));
        assert!(!older_than("", "1.0"));
        assert!(older_than("1.0rc1", "1.0"));
        assert!(older_than("1.0-beta", "1.0"));
        assert_eq!(compare("1.0", "1.0.0"), Ordering::Equal);
    }
}

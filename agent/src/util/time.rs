use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::{AppError, AppResult};

/// 解析 `10m` / `30s` / `7d` 這類時間長度。
pub fn parse_duration(s: &str) -> AppResult<Duration> {
    humantime::parse_duration(s.trim())
        .map_err(|_| AppError::InvalidArg(tf!("無法解析時間長度：{value}（例 10m、30s、7d）", value = s)))
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

/// RFC 3339（秒精度）。
pub fn iso(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn now_iso() -> String {
    iso(&now())
}

/// 人看的時間長度（`1h 02m`、`35s`）。
pub fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        return format!("{s}s");
    }
    let (h, m) = (s / 3600, (s % 3600) / 60);
    if h == 0 {
        format!("{m}m {:02}s", s % 60)
    } else {
        format!("{h}h {m:02}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_humantime() {
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert!(parse_duration("later").is_err());
    }

    #[test]
    fn formats_duration() {
        assert_eq!(fmt_duration(Duration::from_secs(35)), "35s");
        assert_eq!(fmt_duration(Duration::from_secs(125)), "2m 05s");
        assert_eq!(fmt_duration(Duration::from_secs(3720)), "1h 02m");
    }
}

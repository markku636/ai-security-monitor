//! 連線判定：安全 / 未知 / 可疑 / 危險，附帶每一條理由（情資來源、異常旗標、名譽分數…）。
//! 這是對外的 headline 功能；規則收在一個純函數，hub 端以相同語意重算。

use serde::{Deserialize, Serialize};

use super::finding::IntelHit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum VerdictLevel {
    Safe,
    Unknown,
    Suspicious,
    Dangerous,
}

impl VerdictLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictLevel::Safe => "safe",
            VerdictLevel::Unknown => "unknown",
            VerdictLevel::Suspicious => "suspicious",
            VerdictLevel::Dangerous => "dangerous",
        }
    }

    /// 顯示用（依當前語言）。
    pub fn label(self) -> &'static str {
        match self {
            VerdictLevel::Safe => t!("安全"),
            VerdictLevel::Unknown => t!("未知"),
            VerdictLevel::Suspicious => t!("可疑"),
            VerdictLevel::Dangerous => t!("危險"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    NewDestination,
    NewListener,
    RiskyPort,
    Beaconing,
    ShellWithNetwork,
    TempDirProcess,
    UnknownExe,
    ExposedListener,
    FailedLogonBurstSource,
    TorExit,
    OffHours,
    HighVolumeUpload,
    PlaintextProtocol,
}

impl AnomalyKind {
    /// 單獨出現就足以列為可疑的旗標。
    fn strong(self) -> bool {
        matches!(
            self,
            AnomalyKind::Beaconing
                | AnomalyKind::ShellWithNetwork
                | AnomalyKind::FailedLogonBurstSource
                | AnomalyKind::TempDirProcess
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Reason {
    IntelHit(Box<IntelHit>),
    Anomaly {
        kind: AnomalyKind,
        detail: String,
    },
    Reputation {
        provider: String,
        score: u8,
        detail: String,
    },
    KnownGood {
        list: String,
        detail: String,
    },
    Allowlisted {
        entry_id: String,
    },
    PrivateNetwork,
    Loopback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub level: VerdictLevel,
    #[serde(default)]
    pub reasons: Vec<Reason>,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            level: VerdictLevel::Unknown,
            reasons: Vec::new(),
        }
    }
}

/// 高信心門檻：達到即判危險。
pub const DANGEROUS_CONFIDENCE: u8 = 80;
/// 名譽分數門檻。
pub const REPUTATION_DANGEROUS: u8 = 75;
pub const REPUTATION_SUSPICIOUS: u8 = 40;

impl Verdict {
    /// 由理由推判定（純函數）。
    ///
    /// 1. `Allowlisted` 一律 Safe（使用者明示）。
    /// 2. 任一情資命中 confidence ≥ 80，或名譽 ≥ 75 → Dangerous。
    /// 3. 任一情資命中（較低信心）、名譽 ≥ 40、強旗標、或 ≥ 2 個旗標 → Suspicious。
    /// 4. KnownGood / 私網 / loopback 且無旗標 → Safe。
    /// 5. 其餘 Unknown。
    pub fn compute(reasons: Vec<Reason>) -> Verdict {
        if reasons.iter().any(|r| matches!(r, Reason::Allowlisted { .. })) {
            return Verdict {
                level: VerdictLevel::Safe,
                reasons,
            };
        }
        let strong_hit = reasons.iter().any(|r| match r {
            Reason::IntelHit(h) => h.confidence >= DANGEROUS_CONFIDENCE,
            Reason::Reputation { score, .. } => *score >= REPUTATION_DANGEROUS,
            _ => false,
        });
        if strong_hit {
            return Verdict {
                level: VerdictLevel::Dangerous,
                reasons,
            };
        }
        let any_hit = reasons.iter().any(|r| match r {
            Reason::IntelHit(_) => true,
            Reason::Reputation { score, .. } => *score >= REPUTATION_SUSPICIOUS,
            _ => false,
        });
        let anomalies: Vec<AnomalyKind> = reasons
            .iter()
            .filter_map(|r| match r {
                Reason::Anomaly { kind, .. } => Some(*kind),
                _ => None,
            })
            .collect();
        if any_hit || anomalies.iter().any(|k| k.strong()) || anomalies.len() >= 2 {
            return Verdict {
                level: VerdictLevel::Suspicious,
                reasons,
            };
        }
        let benign = reasons
            .iter()
            .any(|r| matches!(r, Reason::KnownGood { .. } | Reason::PrivateNetwork | Reason::Loopback));
        if benign && anomalies.is_empty() {
            return Verdict {
                level: VerdictLevel::Safe,
                reasons,
            };
        }
        Verdict {
            level: VerdictLevel::Unknown,
            reasons,
        }
    }

    pub fn is_bad(&self) -> bool {
        matches!(self.level, VerdictLevel::Suspicious | VerdictLevel::Dangerous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn hit(conf: u8) -> Reason {
        Reason::IntelHit(Box::new(IntelHit {
            feed_id: "abusech-feodo".into(),
            name: "Feodo Tracker".into(),
            vendor: "abuse.ch".into(),
            confidence: conf,
            license: "CC0".into(),
            license_url: "https://creativecommons.org/publicdomain/zero/1.0/".into(),
            attribution_required: false,
            fetched_at: Utc::now(),
            source_url: "https://feodotracker.abuse.ch/".into(),
            matched: "1.2.3.4".into(),
            extra: serde_json::Value::Null,
        }))
    }

    fn anomaly(kind: AnomalyKind) -> Reason {
        Reason::Anomaly {
            kind,
            detail: String::new(),
        }
    }

    #[test]
    fn high_confidence_hit_is_dangerous() {
        assert_eq!(Verdict::compute(vec![hit(90)]).level, VerdictLevel::Dangerous);
    }

    #[test]
    fn low_confidence_hit_is_suspicious() {
        assert_eq!(Verdict::compute(vec![hit(20)]).level, VerdictLevel::Suspicious);
    }

    #[test]
    fn allowlist_wins() {
        let v = Verdict::compute(vec![
            hit(95),
            Reason::Allowlisted {
                entry_id: "al_1".into(),
            },
        ]);
        assert_eq!(v.level, VerdictLevel::Safe);
    }

    #[test]
    fn anomaly_rules() {
        assert_eq!(
            Verdict::compute(vec![anomaly(AnomalyKind::RiskyPort)]).level,
            VerdictLevel::Unknown
        );
        assert_eq!(
            Verdict::compute(vec![
                anomaly(AnomalyKind::RiskyPort),
                anomaly(AnomalyKind::NewDestination)
            ])
            .level,
            VerdictLevel::Suspicious
        );
        assert_eq!(
            Verdict::compute(vec![anomaly(AnomalyKind::Beaconing)]).level,
            VerdictLevel::Suspicious
        );
    }

    #[test]
    fn private_without_flags_is_safe() {
        assert_eq!(Verdict::compute(vec![Reason::PrivateNetwork]).level, VerdictLevel::Safe);
        assert_eq!(
            Verdict::compute(vec![Reason::PrivateNetwork, anomaly(AnomalyKind::RiskyPort)]).level,
            VerdictLevel::Unknown
        );
        assert_eq!(Verdict::compute(vec![]).level, VerdictLevel::Unknown);
    }

    #[test]
    fn reputation_thresholds() {
        let rep = |s: u8| Reason::Reputation {
            provider: "abuseipdb".into(),
            score: s,
            detail: String::new(),
        };
        assert_eq!(Verdict::compute(vec![rep(80)]).level, VerdictLevel::Dangerous);
        assert_eq!(Verdict::compute(vec![rep(50)]).level, VerdictLevel::Suspicious);
        assert_eq!(Verdict::compute(vec![rep(10)]).level, VerdictLevel::Unknown);
    }
}

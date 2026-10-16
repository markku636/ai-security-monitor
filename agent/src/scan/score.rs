//! 分數：每個面向 100 − Σ罰分（下限 0）；KEV 額外 +10；硬化＝加權通過率；
//! overall ＝ 0.30 連線 ＋ 0.20 曝露 ＋ 0.25 漏洞 ＋ 0.25 硬化（缺的面向重新正規化）。

use crate::model::finding::{Evidence, Finding, ScannerId};
use crate::model::report::{HardeningSummary, Scores};

fn component(findings: &[Finding], scanners: &[ScannerId]) -> u8 {
    let mut penalty: u32 = 0;
    for f in findings {
        if f.suppressed_by.is_some() || !scanners.contains(&f.scanner) {
            continue;
        }
        penalty += f.severity.penalty();
        if let Evidence::Cve { kev: true, .. } = f.evidence {
            penalty += 10;
        }
    }
    100u32.saturating_sub(penalty) as u8
}

fn hardening_score(h: &HardeningSummary, findings: &[Finding]) -> u8 {
    // 以 finding 嚴重度加權：fail 的 finding 權重 crit 4 / high 3 / med 2 / low 1；pass 數量視為權重 2。
    let fail_weight: u32 = findings
        .iter()
        .filter(|f| f.scanner == ScannerId::Hardening && f.suppressed_by.is_none())
        .map(|f| match f.severity {
            crate::model::finding::Severity::Critical => 4,
            crate::model::finding::Severity::High => 3,
            crate::model::finding::Severity::Medium => 2,
            _ => 1,
        })
        .sum();
    let pass_weight = h.pass * 2;
    let total = pass_weight + fail_weight;
    if total == 0 {
        return 100;
    }
    ((pass_weight as f64 / total as f64) * 100.0).round() as u8
}

pub fn compute(findings: &[Finding], hardening: Option<&HardeningSummary>, ran: &[ScannerId]) -> Scores {
    let has = |ids: &[ScannerId]| ids.iter().any(|i| ran.contains(i));

    let connections = has(&[
        ScannerId::Connections,
        ScannerId::Intel,
        ScannerId::Traffic,
        ScannerId::Events,
    ])
    .then(|| {
        component(
            findings,
            &[
                ScannerId::Connections,
                ScannerId::Intel,
                ScannerId::Traffic,
                ScannerId::Events,
            ],
        )
    });
    let exposure = has(&[ScannerId::Ports, ScannerId::Firewall])
        .then(|| component(findings, &[ScannerId::Ports, ScannerId::Firewall]));
    let vulns =
        has(&[ScannerId::Vuln, ScannerId::Files]).then(|| component(findings, &[ScannerId::Vuln, ScannerId::Files]));
    let hardening_s = hardening
        .filter(|_| ran.contains(&ScannerId::Hardening))
        .map(|h| hardening_score(h, findings));

    let parts: [(Option<u8>, f64); 4] = [
        (connections, 0.30),
        (exposure, 0.20),
        (vulns, 0.25),
        (hardening_s, 0.25),
    ];
    let (sum, weight) = parts.iter().fold((0.0, 0.0), |(s, w), (v, wt)| match v {
        Some(x) => (s + (*x as f64) * wt, w + wt),
        None => (s, w),
    });
    let overall = if weight == 0.0 {
        100
    } else {
        (sum / weight).round() as u8
    };

    Scores {
        overall,
        connections: connections.unwrap_or(100),
        exposure: exposure.unwrap_or(100),
        vulns: vulns.unwrap_or(100),
        hardening: hardening_s.unwrap_or(100),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::Severity;

    fn f(scanner: ScannerId, sev: Severity) -> Finding {
        Finding::new(
            scanner,
            "r",
            "k",
            sev,
            "t",
            "d",
            Evidence::Text { detail: String::new() },
            "rec",
        )
    }

    #[test]
    fn penalties_and_floor() {
        let fs = vec![
            f(ScannerId::Connections, Severity::Critical),
            f(ScannerId::Connections, Severity::High),
            f(ScannerId::Ports, Severity::Medium),
        ];
        let s = compute(&fs, None, &[ScannerId::Connections, ScannerId::Ports]);
        assert_eq!(s.connections, 60);
        assert_eq!(s.exposure, 93);
        assert_eq!(s.vulns, 100);
        // overall = (60*0.30 + 93*0.20) / 0.50 = (18 + 18.6)/0.5 = 73.2
        assert_eq!(s.overall, 73);
        let many: Vec<Finding> = (0..6).map(|_| f(ScannerId::Vuln, Severity::Critical)).collect();
        assert_eq!(compute(&many, None, &[ScannerId::Vuln]).vulns, 0);
    }

    #[test]
    fn suppressed_do_not_count_and_nothing_ran_is_100() {
        let mut x = f(ScannerId::Connections, Severity::Critical);
        x.suppressed_by = Some("al_1".into());
        let s = compute(&[x], None, &[ScannerId::Connections]);
        assert_eq!(s.connections, 100);
        assert_eq!(compute(&[], None, &[]).overall, 100);
    }

    #[test]
    fn hardening_weighted_pass_rate() {
        let h = HardeningSummary {
            pass: 8,
            fail: 2,
            na: 1,
            error: 0,
        };
        let fs = vec![
            f(ScannerId::Hardening, Severity::High),
            f(ScannerId::Hardening, Severity::Low),
        ];
        let s = compute(&fs, Some(&h), &[ScannerId::Hardening]);
        // pass 16 / (16 + 3 + 1) = 0.8 → 80
        assert_eq!(s.hardening, 80);
        assert_eq!(s.overall, 80);
    }
}

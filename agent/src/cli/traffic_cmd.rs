//! `asa traffic`：即時 flow-lite 取樣；`asa traffic analyze <file>`：離線分析 pcap／pcapng。

use std::path::Path;

use super::args::{TrafficArgs, TrafficCmd};
use super::render::{print_json, table};
use super::Env;
use crate::error::AppResult;
use crate::traffic::summary::TrafficSummary;
use crate::traffic::{lite, offline, summary};
use crate::util::text::{clip, fmt_bytes};
use crate::util::time::parse_duration;

pub async fn run(env: &Env, a: TrafficArgs) -> AppResult<()> {
    let intel = crate::hub::watch::load_intel(&env.config_dir).await;
    let s = match a.cmd {
        Some(TrafficCmd::Analyze { file, max_packets }) => {
            let path = Path::new(&file).to_path_buf();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let db = intel.clone();
            let (s, stats) = tokio::task::spawn_blocking(move || -> AppResult<_> {
                let (table, stats) = offline::analyze_file(&path, max_packets)?;
                Ok((summary::from_flows(&table, &name, db.as_deref()), stats))
            })
            .await
            .map_err(|e| crate::error::AppError::Scan(e.to_string()))??;
            let mut s = s;
            if stats.truncated {
                s.notes.push(format!("stopped after {} records", stats.records));
            }
            if stats.unsupported_link > 0 {
                s.notes.push(format!(
                    "{} records with an unsupported link type were skipped",
                    stats.unsupported_link
                ));
            }
            if stats.undecodable > 0 {
                s.notes
                    .push(format!("{} records could not be decoded", stats.undecodable));
            }
            s
        }
        None => {
            let duration = parse_duration(&a.duration)?;
            let every = parse_duration(&a.every)?;
            if !env.global.quiet && !env.global.json {
                eprintln!(
                    "{}",
                    tf!(
                        "觀察 {d} 中（每 {e} 讀一次連線表；不抓封包、不需要系統管理員權限）…",
                        d = a.duration,
                        e = a.every
                    )
                );
            }
            lite::sample(&env.config_dir, duration, every, intel).await?
        }
    };
    if env.global.json {
        print_json(&s);
    } else {
        print_summary(&s);
    }
    Ok(())
}

fn sev_label(s: &str) -> String {
    match s {
        "high" => t!("高").into(),
        "medium" => t!("中").into(),
        _ => t!("低").into(),
    }
}

fn kind_label(k: &str) -> String {
    match k {
        "intel_match" => t!("情資命中").into(),
        "plaintext_protocol" => t!("明文協定").into(),
        "unusual_port" => t!("高風險 port").into(),
        "large_upload" => t!("大量上傳").into(),
        "beaconing" => t!("週期性連線").into(),
        "suspicious_dns" => t!("可疑 DNS").into(),
        other => other.into(),
    }
}

pub fn print_summary(s: &TrafficSummary) {
    println!(
        "{}",
        tf!(
            "模式 {mode} · 來源 {source} · {secs} 秒 · {flows} 條流 · 送出 {out} · 收到 {inn}",
            mode = s.mode,
            source = s.source,
            secs = s.window.duration_s,
            flows = s.totals.flows,
            out = fmt_bytes(s.totals.bytes_out),
            inn = fmt_bytes(s.totals.bytes_in)
        )
    );
    if !s.alerts.is_empty() {
        println!("\n{}", t!("警示"));
        let rows = s
            .alerts
            .iter()
            .map(|a| {
                let src = a
                    .intel
                    .iter()
                    .map(|h| format!("{} {}%", h.vendor, h.confidence))
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![
                    sev_label(&a.severity),
                    kind_label(&a.kind),
                    match a.port {
                        Some(p) => format!("{}:{p}", a.remote),
                        None => a.remote.clone(),
                    },
                    clip(
                        &if src.is_empty() {
                            a.detail.clone()
                        } else {
                            format!("{} · {src}", a.detail)
                        },
                        70,
                    ),
                ]
            })
            .collect();
        println!("{}", table(&[t!("嚴重度"), t!("類型"), t!("對象"), t!("說明")], rows));
    } else {
        println!("\n{}", t!("沒有發現可疑流量。"));
    }
    if !s.top_talkers.is_empty() {
        println!("\n{}", t!("主要對象"));
        let rows = s
            .top_talkers
            .iter()
            .map(|t| {
                vec![
                    t.remote.clone(),
                    t.domain.clone().unwrap_or_default(),
                    t.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
                    if s.mode == "pcap" {
                        format!("{} / {}", fmt_bytes(t.bytes_out), fmt_bytes(t.bytes_in))
                    } else {
                        "-".into()
                    },
                    t.flows.to_string(),
                    t.process.clone().unwrap_or_default(),
                    if t.intel.is_empty() {
                        String::new()
                    } else {
                        "⚠".into()
                    },
                ]
            })
            .collect();
        println!(
            "{}",
            table(
                &[
                    t!("遠端"),
                    t!("網域"),
                    "port",
                    t!("送出／收到"),
                    t!("連線"),
                    t!("行程"),
                    t!("情資")
                ],
                rows
            )
        );
    }
    if !s.per_process.is_empty() {
        println!("\n{}", t!("各行程"));
        let rows = s
            .per_process
            .iter()
            .map(|p| vec![p.process.clone(), p.connections.to_string(), p.remotes.to_string()])
            .collect();
        println!("{}", table(&[t!("行程"), t!("連線"), t!("遠端數")], rows));
    }
    if !s.dns_queries.is_empty() {
        println!("\n{}", t!("DNS 查詢"));
        let rows = s
            .dns_queries
            .iter()
            .take(20)
            .map(|d| {
                vec![
                    clip(&d.name, 50),
                    d.qtype.clone(),
                    d.count.to_string(),
                    clip(&d.answers.join(", "), 40),
                    d.suspicious.clone().unwrap_or_default(),
                ]
            })
            .collect();
        println!(
            "{}",
            table(&[t!("名稱"), t!("類型"), t!("次數"), t!("回應"), t!("可疑")], rows)
        );
    }
    if !s.tls_sni.is_empty() || !s.http_hosts.is_empty() {
        println!("\n{}", t!("TLS SNI／HTTP Host"));
        let rows = s
            .tls_sni
            .iter()
            .map(|n| vec!["TLS".to_string(), n.name.clone(), n.flows.to_string()])
            .chain(
                s.http_hosts
                    .iter()
                    .map(|n| vec!["HTTP".to_string(), n.name.clone(), n.flows.to_string()]),
            )
            .take(30)
            .collect();
        println!("{}", table(&["", t!("名稱"), t!("連線")], rows));
    }
    if !s.interfaces.is_empty() {
        println!("\n{}", t!("網路介面"));
        let rows = s
            .interfaces
            .iter()
            .map(|i| vec![i.name.clone(), fmt_bytes(i.rx_bytes), fmt_bytes(i.tx_bytes)])
            .collect();
        println!("{}", table(&[t!("介面"), t!("收到"), t!("送出")], rows));
    }
    for n in &s.notes {
        println!("· {n}");
    }
}

//! `ai-security-monitor metrics`：現在的網路流量（各介面、各程式）與效能（有開啟或加 `--perf` 才量）。
//! 只在本機量一次，不碰背景 `watch` 的待送佇列。

use std::time::Duration;

use super::args::MetricsArgs;
use super::render::{print_json, table};
use super::Env;
use crate::config;
use crate::error::AppResult;
use crate::metrics::{self, MetricsSample, Options};
use crate::util::text::fmt_bytes;

fn rate(bytes: u64, secs: u32) -> String {
    format!("{}/s", fmt_bytes(bytes / u64::from(secs.max(1))))
}

fn pct(used: u64, total: u64) -> String {
    if total == 0 {
        "—".into()
    } else {
        format!("{:.0}%", used as f64 * 100.0 / total as f64)
    }
}

pub async fn run(env: &Env, a: MetricsArgs) -> AppResult<()> {
    let cfg = config::load_or_init(&env.config_dir)?;
    let window =
        crate::util::time::parse_duration(&a.duration)?.clamp(Duration::from_millis(500), Duration::from_secs(60));
    let opts = Options {
        performance: cfg.metrics.performance || a.perf,
        process_network: cfg.metrics.process_network,
    };
    let sample = metrics::measure(window, opts).await;
    let queued = metrics::queue::len(&env.config_dir);
    let recent = metrics::queue::recent(&env.config_dir);
    if env.global.json {
        let (rx, tx) = sample.as_ref().map(MetricsSample::rates).unwrap_or((0.0, 0.0));
        print_json(&serde_json::json!({
            "performance_enabled": cfg.metrics.performance,
            "process_network": cfg.metrics.process_network,
            "interval": cfg.metrics.interval,
            "window_s": window.as_secs_f64(),
            "sample": sample,
            "rates": { "rx_bytes_per_s": rx, "tx_bytes_per_s": tx },
            "interfaces": metrics::interface_totals(),
            "elevated": crate::elevate::is_elevated(),
            "queue": queued,
            "recent": { "count": recent.len(), "last_at": recent.last().map(|s| s.ts) },
        }));
        return Ok(());
    }
    let Some(s) = sample else {
        println!("{}", t!("取樣逾時，請再試一次"));
        return Ok(());
    };
    print_human(&s, &cfg.metrics, a.perf);
    println!(
        "{}",
        tf!(
            "背景回報（ai-security-monitor watch）每 {every} 取樣一次；待上傳 {n} 筆、本機保留最近 {r} 筆",
            every = cfg.metrics.interval,
            n = queued,
            r = recent.len()
        )
    );
    Ok(())
}

fn print_human(s: &MetricsSample, mc: &config::MetricsConfig, forced: bool) {
    let secs = s.interval_s;
    println!(
        "{}",
        tf!(
            "網路（過去 {secs} 秒，只算實體介面）：下載 {rx}、上傳 {tx}",
            secs = secs,
            rx = rate(s.net.rx_bytes, secs),
            tx = rate(s.net.tx_bytes, secs)
        )
    );
    let totals = metrics::interface_totals();
    let total_of = |name: &str, k: &str| {
        totals
            .iter()
            .find(|v| v["name"] == name)
            .and_then(|v| v[k].as_u64())
            .map(fmt_bytes)
            .unwrap_or_else(|| "—".into())
    };
    let rows = s
        .net
        .interfaces
        .iter()
        .map(|i| {
            vec![
                i.name.clone(),
                if i.is_virtual {
                    t!("虛擬").to_string()
                } else {
                    t!("實體").to_string()
                },
                rate(i.rx_bytes, secs),
                rate(i.tx_bytes, secs),
                total_of(&i.name, "rx_total"),
                total_of(&i.name, "tx_total"),
            ]
        })
        .collect();
    println!(
        "{}",
        table(
            &[
                t!("介面"),
                t!("類型"),
                t!("下載"),
                t!("上傳"),
                t!("開機後累計收到"),
                t!("開機後累計送出")
            ],
            rows
        )
    );
    match &s.net.processes {
        Some(p) if !p.is_empty() => {
            println!(
                "{}",
                tf!(
                    "各程式（來源：{src}）：",
                    src = s.net.process_source.as_deref().unwrap_or("-")
                )
            );
            let rows = p
                .iter()
                .map(|x| vec![x.name.clone(), rate(x.rx_bytes, secs), rate(x.tx_bytes, secs)])
                .collect();
            println!("{}", table(&[t!("程式"), t!("下載"), t!("上傳")], rows));
        }
        Some(_) => println!("{}", t!("各程式：這段時間沒有程式收發資料")),
        None if !mc.process_network => {}
        None => println!(
            "{}",
            if cfg!(windows) {
                t!("各程式：需要系統管理員權限才讀得到（以系統管理員執行，或裝成系統服務）")
            } else {
                t!("各程式：這個平台讀不到各程式的網路用量（Linux 需要 eBPF），請看 connections 的各程式連線數")
            }
        ),
    }
    let Some(p) = &s.perf else {
        println!(
            "{}",
            t!("效能蒐集：未開啟。開啟：ai-security-monitor config set metrics.performance true（或加 --perf 只在本機看一次）")
        );
        return;
    };
    if forced && !mc.performance {
        println!("{}", t!("效能（--perf：只在本機顯示，不會上傳）："));
    } else {
        println!("{}", t!("效能（已開啟，會送到這台加入的 Hub）："));
    }
    let load = p
        .load
        .map(|l| tf!("，負載 {a} {b} {c}", a = l[0], b = l[1], c = l[2]))
        .unwrap_or_default();
    println!(
        "  {}",
        tf!(
            "CPU {cpu}%（{n} 核）{load}",
            cpu = p.cpu_pct,
            n = p.cpu_cores,
            load = load
        )
    );
    println!(
        "  {}",
        tf!(
            "記憶體 {used}／{total}（{pct}），置換 {su}／{st}",
            used = fmt_bytes(p.mem_used),
            total = fmt_bytes(p.mem_total),
            pct = pct(p.mem_used, p.mem_total),
            su = fmt_bytes(p.swap_used),
            st = fmt_bytes(p.swap_total)
        )
    );
    for d in &p.disks {
        println!(
            "  {}",
            tf!(
                "磁碟 {mount}：{used}／{total}（{pct}）",
                mount = d.mount,
                used = fmt_bytes(d.used),
                total = fmt_bytes(d.total),
                pct = pct(d.used, d.total)
            )
        );
    }
    if let (Some(r), Some(w)) = (p.disk_read_bytes, p.disk_write_bytes) {
        println!(
            "  {}",
            tf!("磁碟讀寫：讀 {r}、寫 {w}", r = rate(r, secs), w = rate(w, secs))
        );
    }
    println!(
        "  {}",
        tf!(
            "開機時間 {at}（{d} 天 {h} 小時前）",
            at = p.boot_time.format("%Y-%m-%d %H:%M UTC"),
            d = p.uptime_s / 86_400,
            h = (p.uptime_s % 86_400) / 3600
        )
    );
    if let Some(b) = &p.battery {
        println!(
            "  {}",
            tf!(
                "電池 {p}%（{state}）",
                p = b.percent,
                state = if b.charging { t!("充電中") } else { t!("未充電") }
            )
        );
    }
    let procs = |list: &[metrics::ProcPerf]| -> Vec<Vec<String>> {
        list.iter()
            .map(|x| {
                vec![
                    if x.count > 1 {
                        format!("{} ×{}", x.name, x.count)
                    } else {
                        x.name.clone()
                    },
                    x.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into()),
                    format!("{:.1}%", x.cpu_pct),
                    fmt_bytes(x.rss),
                ]
            })
            .collect()
    };
    if !p.top_cpu.is_empty() {
        println!("{}", t!("最吃 CPU 的程式："));
        println!(
            "{}",
            table(&[t!("程式"), "pid", "CPU", t!("記憶體")], procs(&p.top_cpu))
        );
    }
    if !p.top_mem.is_empty() {
        println!("{}", t!("最吃記憶體的程式："));
        println!(
            "{}",
            table(&[t!("程式"), "pid", "CPU", t!("記憶體")], procs(&p.top_mem))
        );
    }
}

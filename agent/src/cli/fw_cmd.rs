//! `asa fw`：防火牆狀態、稽核、規則清單（本輪唯讀）。

use super::args::{FwCmd, ScanArgs};
use super::render::{print_json, table};
use super::Env;
use crate::error::AppResult;
use crate::firewall::{read_current, FwSnapshot};
use crate::model::finding::ScannerId;
use crate::util::cmd::RealRunner;
use crate::util::text::clip;

fn on_off(v: Option<bool>) -> String {
    match v {
        Some(true) => t!("啟用").into(),
        Some(false) => t!("關閉").into(),
        None => t!("未知").into(),
    }
}

pub fn print_status(fw: &FwSnapshot) {
    println!(
        "{}",
        tf!(
            "後端：{backend} · 狀態：{state} · 預設連入：{din} · 允許連入規則：{n} · asa 規則：{ours}",
            backend = fw.backend,
            state = on_off(fw.enabled),
            din = fw.default_inbound.clone().unwrap_or_else(|| "-".into()),
            n = fw.inbound_allow.len(),
            ours = fw.ours_rules
        )
    );
    if !fw.profiles.is_empty() {
        let rows = fw
            .profiles
            .iter()
            .map(|p| {
                vec![
                    if p.active { "●".into() } else { "".into() },
                    p.name.clone(),
                    on_off(Some(p.enabled)),
                    p.default_inbound.clone(),
                    p.default_outbound.clone(),
                ]
            })
            .collect();
        println!(
            "{}",
            table(
                &[
                    t!("作用中"),
                    t!("防火牆設定檔"),
                    t!("狀態"),
                    t!("預設連入"),
                    t!("預設連出")
                ],
                rows
            )
        );
    }
    for n in &fw.notes {
        println!("  · {n}");
    }
    if fw.needs_elevation {
        println!("{}", t!("部分規則需要系統管理員權限才能讀取（sudo asa fw status）"));
    }
}

pub async fn run(env: &Env, cmd: FwCmd) -> AppResult<()> {
    match cmd {
        FwCmd::Status => {
            let fw = read_current(&RealRunner, crate::elevate::is_elevated()).await?;
            if env.global.json {
                print_json(&fw);
            } else {
                print_status(&fw);
            }
            Ok(())
        }
        FwCmd::Audit => {
            super::scan_cmd::run(
                env,
                ScanArgs {
                    scanners: vec![ScannerId::Firewall, ScannerId::Ports],
                    no_online: true,
                    ..Default::default()
                },
            )
            .await
        }
        FwCmd::List { all } => {
            let fw = read_current(&RealRunner, crate::elevate::is_elevated()).await?;
            let rules: Vec<_> = fw.inbound_allow.iter().filter(|r| all || r.owner.is_none()).collect();
            if env.global.json {
                print_json(&rules);
                return Ok(());
            }
            let rows = rules
                .iter()
                .map(|r| {
                    vec![
                        clip(&r.display, 44),
                        r.protocol.clone(),
                        clip(&r.ports.iter().map(|p| p.display()).collect::<Vec<_>>().join(","), 20),
                        clip(r.program.as_deref().unwrap_or("any"), 40),
                        r.profiles.join(","),
                        clip(&r.remote_address, 18),
                    ]
                })
                .collect();
            println!(
                "{}",
                table(
                    &[
                        t!("規則"),
                        t!("協定"),
                        "port",
                        t!("程式"),
                        t!("防火牆設定檔"),
                        t!("來源位址")
                    ],
                    rows
                )
            );
            println!(
                "{}",
                tf!(
                    "共 {n} 條允許連入規則（{total} 條含 UWP 應用程式規則；--all 全部列出）",
                    n = rules.len(),
                    total = fw.inbound_allow.len()
                )
            );
            Ok(())
        }
    }
}

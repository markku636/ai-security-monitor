use super::args::BaselineCmd;
use super::guard::ensure_confirmed;
use super::render::print_json;
use super::Env;
use crate::error::{AppError, AppResult};
use crate::model::baseline::{Baseline, Snapshot};

pub async fn run(env: &Env, cmd: BaselineCmd) -> AppResult<()> {
    match cmd {
        BaselineCmd::Save => {
            ensure_confirmed(env.global.yes, true, false, t!("以目前狀態更新基準線"))?;
            let (report, snapshot) = super::scan_cmd::scan_for_baseline(env).await?;
            let mut base =
                Baseline::load(&env.config_dir)?.unwrap_or_else(|| Baseline::from_snapshot(&Snapshot::default()));
            base.merge(&snapshot);
            base.save(&env.config_dir)?;
            if env.global.json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "listeners": base.listeners.len(),
                    "network_processes": base.network_processes.len(),
                    "destinations": base.destinations.len(),
                    "finding_ids": base.finding_ids.len(),
                    "scanners_run": report.scanners_run,
                }));
            } else {
                println!(
                    "{}",
                    tf!(
                        "基準線已更新：{l} 個 listener、{p} 個網路行程、{d} 個目的地、{f} 筆 finding",
                        l = base.listeners.len(),
                        p = base.network_processes.len(),
                        d = base.destinations.len(),
                        f = base.finding_ids.len()
                    )
                );
            }
            Ok(())
        }
        BaselineCmd::Diff => {
            let base = Baseline::load(&env.config_dir)?
                .ok_or_else(|| AppError::Storage(t!("尚無基準線；先執行 asa baseline save --yes").into()))?;
            let (_report, snapshot) = super::scan_cmd::scan_for_baseline(env).await?;
            let diff = base.diff(&snapshot);
            if env.global.json {
                print_json(&diff);
            } else if diff.is_empty() {
                println!("{}", t!("與基準線無差異"));
            } else {
                for l in &diff.new_listeners {
                    println!(
                        "{}",
                        tf!(
                            "新 listener：{proto} {port}（{bind}）{exe}",
                            proto = l.proto,
                            port = l.port,
                            bind = l.bind,
                            exe = l.exe
                        )
                    );
                }
                for p in &diff.new_network_processes {
                    println!("{}", tf!("新的網路行程：{exe}", exe = p));
                }
                for d in &diff.new_destinations {
                    println!("{}", tf!("新目的地：{dest}", dest = d));
                }
                for f in &diff.new_findings {
                    println!("{}", tf!("新 finding：{id}", id = f));
                }
                for f in &diff.resolved_findings {
                    println!("{}", tf!("已消失的 finding：{id}", id = f));
                }
            }
            Ok(())
        }
        BaselineCmd::Show => {
            match Baseline::load(&env.config_dir)? {
                Some(b) => print_json(&b),
                None => println!("{}", t!("尚無基準線；先執行 asa baseline save --yes")),
            }
            Ok(())
        }
    }
}

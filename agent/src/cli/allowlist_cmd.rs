use super::args::AllowlistCmd;
use super::guard::ensure_confirmed;
use super::render::{print_json, table};
use super::Env;
use crate::error::AppResult;
use crate::model::allowlist::Allowlist;

pub fn run(env: &Env, cmd: AllowlistCmd) -> AppResult<()> {
    let mut al = Allowlist::load(&env.config_dir)?;
    match cmd {
        AllowlistCmd::Add { value, kind, note } => {
            ensure_confirmed(env.global.yes, true, false, &tf!("新增白名單 {value}", value = value))?;
            let entry = al.add(kind, &value, note)?.clone();
            al.save(&env.config_dir)?;
            if env.global.json {
                print_json(&entry);
            } else {
                println!(
                    "{}",
                    tf!(
                        "已加入白名單：{id}（{kind}）{value}",
                        id = entry.id,
                        kind = format!("{:?}", entry.kind).to_lowercase(),
                        value = entry.value
                    )
                );
            }
        }
        AllowlistCmd::Remove { entry } => {
            ensure_confirmed(env.global.yes, true, false, &tf!("移除白名單 {entry}", entry = entry))?;
            let removed = al.remove(&entry);
            al.save(&env.config_dir)?;
            if env.global.json {
                print_json(&serde_json::json!({ "removed": removed, "entry": entry }));
            } else if removed {
                println!("{}", tf!("已移除：{entry}", entry = entry));
            } else {
                println!("{}", tf!("找不到條目：{entry}", entry = entry));
            }
        }
        AllowlistCmd::List => {
            if env.global.json {
                print_json(&al);
            } else if al.entries.is_empty() {
                println!("{}", t!("白名單是空的"));
            } else {
                let rows = al
                    .entries
                    .iter()
                    .map(|e| {
                        vec![
                            e.id.clone(),
                            format!("{:?}", e.kind).to_lowercase(),
                            e.value.clone(),
                            e.note.clone().unwrap_or_default(),
                            e.added_at.clone(),
                        ]
                    })
                    .collect();
                println!(
                    "{}",
                    table(&["id", t!("種類"), t!("值"), t!("備註"), t!("加入時間")], rows)
                );
            }
        }
    }
    Ok(())
}

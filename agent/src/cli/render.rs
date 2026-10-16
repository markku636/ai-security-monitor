//! 輸出：JSON（`--json`）或 comfy-table 表格。

use comfy_table::{presets::UTF8_FULL_CONDENSED, ContentArrangement, Table};
use serde::Serialize;

use crate::model::report::Report;
use crate::util::text::clip;

pub fn print_json<T: Serialize>(v: &T) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("{}", tf!("序列化失敗：{e}", e = e)),
    }
}

pub fn table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut t = Table::new();
    t.load_style(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic);
    t.set_header(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    for r in rows {
        t.add_row(r);
    }
    t.to_string()
}

pub fn print_report(r: &Report) {
    let [info, low, med, high, crit] = r.count_by_severity();
    println!(
        "{}",
        tf!(
            "掃描完成：{n} 筆發現（嚴重 {crit}／高 {high}／中 {med}／低 {low}／資訊 {info}）；總分 {score}",
            n = r.findings.len(),
            crit = crit,
            high = high,
            med = med,
            low = low,
            info = info,
            score = r.score.overall
        )
    );
    println!(
        "{}",
        tf!(
            "面向分數：連線 {c}、曝露 {e}、漏洞 {v}、硬化 {h}；掃描器：{s}",
            c = r.score.connections,
            e = r.score.exposure,
            v = r.score.vulns,
            h = r.score.hardening,
            s = r.scanners_run.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )
    );
    if r.partial {
        println!(
            "{}",
            t!("注意：部分資料因權限不足而缺失（以管理員身分重跑可取得完整結果）")
        );
    }
    for w in &r.warnings {
        println!("  ! {w}");
    }
    if r.findings.is_empty() {
        return;
    }
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut sorted: Vec<&crate::model::finding::Finding> = r.findings.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in sorted {
        let mut tags = f.tags.join(",");
        if f.suppressed_by.is_some() {
            tags = format!("{tags} {}", t!("（白名單）")).trim().to_string();
        }
        rows.push(vec![
            f.severity.as_str().to_string(),
            f.scanner.as_str().to_string(),
            clip(&f.title, 48),
            clip(&f.detail, 60),
            tags,
        ]);
    }
    println!(
        "{}",
        table(&[t!("嚴重度"), t!("掃描器"), t!("標題"), t!("細節"), t!("標籤")], rows)
    );
}

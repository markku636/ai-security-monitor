//! MCP 工具：定義（名稱、說明、inputSchema）與實作。全部回傳文字（JSON），失敗回 Err 文字給模型看。
//! 唯讀工具隨時可用；動作工具（preview_action／execute_action）只在伺服器以 `--allow-actions` 啟動時列出。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::actions::review::{Pending, PendingStore};
use crate::cli::args::GlobalArgs;
use crate::cli::Env;
use crate::firewall::plan::{self, Dir, FwAction};
use crate::intel::IntelDb;
use crate::model::connection::{Connection, Direction};
use crate::model::finding::ScannerId;
use crate::model::verdict::{Reason, VerdictLevel};

/// 一支工具的定義。
#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: String,
    pub input_schema: Value,
}

/// 回傳文字的上限（超過就截斷並註明）。
pub const MAX_TEXT: usize = 60 * 1024;

pub const READ_ONLY: &[&str] = &[
    "list_connections",
    "lookup_ip",
    "inbound_attackers",
    "intel_sources",
    "scan",
    "list_findings",
    "get_report",
    "listening_ports",
    "firewall_status",
    "baseline_diff",
    "doctor",
    "traffic_summary",
    "analyze_pcap",
    "events_summary",
    "crash_history",
    "explain_code",
];
pub const ACTION_TOOLS: &[&str] = &["preview_action", "execute_action"];

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false })
}

pub fn read_only_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "list_connections",
            description: t!("這台電腦目前的網路連線（對外／對內／監聽），每條附判定（安全／未知／可疑／危險）與理由，情資命中會列出來源廠商與網址。").into(),
            input_schema: obj(
                json!({
                    "direction": { "type": "string", "enum": ["outbound", "inbound", "listening", "local"] },
                    "verdict": { "type": "array", "items": { "type": "string", "enum": ["safe", "unknown", "suspicious", "dangerous"] } },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 300 }
                }),
                &[],
            ),
        },
        ToolDef {
            name: "lookup_ip",
            description: t!("用已下載的威脅情資查一個 IP 或網域：判定、命中的來源（廠商、信心、授權、網址）、國家與 ASN；online=true 時另查已設定 API key 的名譽服務。").into(),
            input_schema: obj(json!({ "indicator": { "type": "string" }, "online": { "type": "boolean" } }), &["indicator"]),
        },
        ToolDef {
            name: "inbound_attackers",
            description: t!("對內的可疑來源：目前連進來且判定可疑／危險的 IP，加上事件記錄裡的暴力破解來源（含情資命中）。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "intel_sources",
            description: t!("威脅情資來源清單：廠商、類型、信心、授權（能否商用、是否需標註）、最後下載時間與筆數。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "scan",
            description: t!("執行一次完整或部分掃描（connections、intel、firewall、ports、events），回傳分數與發現清單，並存成最新報告。").into(),
            input_schema: obj(
                json!({ "scanners": { "type": "array", "items": { "type": "string", "enum": ["connections", "intel", "firewall", "ports", "events"] } } }),
                &[],
            ),
        },
        ToolDef {
            name: "list_findings",
            description: t!("最新報告裡的發現（沒有報告會先掃描）：嚴重度、規則、標題、說明、建議與情資來源。").into(),
            input_schema: obj(
                json!({
                    "min_severity": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] },
                    "scanner": { "type": "string" }
                }),
                &[],
            ),
        },
        ToolDef {
            name: "get_report",
            description: t!("最新完整報告（JSON；太大時省略證據細節）。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "listening_ports",
            description: t!("監聽中的 port 與實際可達性（只有本機／可從網路連入／已被防火牆擋），附行程與高風險服務說明。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "firewall_status",
            description: t!("防火牆狀態：後端、各設定檔是否開啟、預設連入動作、允許連入的規則與 asa 建立的封鎖規則數。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "baseline_diff",
            description: t!("與基準線比較：新出現的監聽 port、新的連網程式、新的目的地與新發現。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "doctor",
            description: t!("環境檢查：權限、hub 註冊、情資新鮮度、封包擷取工具與外部工具。").into(),
            input_schema: obj(json!({}), &[]),
        },
        ToolDef {
            name: "traffic_summary",
            description: t!("觀察即時流量 N 秒（不抓封包）：各行程連到哪些遠端、新連線、介面流量、高風險 port、週期性連線與情資命中。").into(),
            input_schema: obj(json!({ "duration_s": { "type": "integer", "minimum": 3, "maximum": 60 } }), &[]),
        },
        ToolDef {
            name: "analyze_pcap",
            description: t!("分析 pcap／pcapng 擷取檔：DNS、TLS SNI、HTTP Host、明文協定、大量上傳、週期性連線、可疑 DNS 與情資命中。").into(),
            input_schema: obj(json!({ "path": { "type": "string" } }), &["path"]),
        },
        ToolDef {
            name: "events_summary",
            description: t!("事件記錄摘要（預設 7 天）：當機（藍屏代碼與可能原因）、資安事件（暴力破解、新帳號、新服務、清除稽核）、最常見的錯誤。").into(),
            input_schema: obj(json!({ "days": { "type": "integer", "minimum": 1, "maximum": 90 } }), &[]),
        },
        ToolDef {
            name: "crash_history",
            description: t!("當機紀錄（預設 30 天）：藍屏、非預期關機、程式當掉、服務失敗、磁碟與硬體錯誤，附可能原因與處置。").into(),
            input_schema: obj(json!({ "days": { "type": "integer", "minimum": 1, "maximum": 90 } }), &[]),
        },
        ToolDef {
            name: "explain_code",
            description: t!("解釋藍屏代碼（例 0x7E）或 Windows 事件 ID（例 41、4625）。").into(),
            input_schema: obj(json!({ "code": { "type": "string" } }), &["code"]),
        },
    ]
}

pub fn action_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "preview_action",
            description: t!("預覽防禦動作（block_ip、unblock_ip、close_port、open_port）：回傳確切會執行的指令與審查代碼，不會改任何東西。執行前一定要先給使用者看預覽並取得同意。").into(),
            input_schema: obj(
                json!({
                    "kind": { "type": "string", "enum": ["block_ip", "unblock_ip", "close_port", "open_port"] },
                    "ip": { "type": "string", "description": "IP or CIDR (block_ip / unblock_ip)" },
                    "direction": { "type": "string", "enum": ["in", "out", "both"] },
                    "proto": { "type": "string", "enum": ["tcp", "udp"] },
                    "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
                    "reason": { "type": "string" }
                }),
                &["kind"],
            ),
        },
        ToolDef {
            name: "execute_action",
            description: t!("以 preview_action 回傳的審查代碼執行動作（單次有效、15 分鐘內）。asa mcp 需以系統管理員身分執行才能套用。").into(),
            input_schema: obj(json!({ "review_token": { "type": "string" } }), &["review_token"]),
        },
    ]
}

/// 工具執行時需要的共享狀態。
pub struct ToolCtx {
    pub config_dir: PathBuf,
    pub allow_destructive: bool,
    pub pending: PendingStore,
    pub intel: tokio::sync::OnceCell<Option<Arc<IntelDb>>>,
}

impl ToolCtx {
    pub fn env(&self) -> Env {
        Env {
            global: GlobalArgs {
                quiet: true,
                json: true,
                ..Default::default()
            },
            config_dir: self.config_dir.clone(),
        }
    }

    async fn intel(&self) -> Option<Arc<IntelDb>> {
        self.intel
            .get_or_init(|| async { crate::hub::watch::load_intel(&self.config_dir).await })
            .await
            .clone()
    }
}

/// JSON → 文字；超過上限截斷。
pub fn to_text(v: &Value) -> String {
    let s = serde_json::to_string_pretty(v).unwrap_or_default();
    if s.len() <= MAX_TEXT {
        return s;
    }
    let mut cut = MAX_TEXT;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n… (truncated, {} bytes total)", &s[..cut], s.len())
}

fn reason_brief(r: &Reason) -> Value {
    match r {
        Reason::IntelHit(h) => json!({
            "intel": format!("{} · {}", h.vendor, h.name),
            "confidence": h.confidence,
            "license": h.license,
            "source_url": h.source_url,
        }),
        Reason::Anomaly { kind, detail } => json!({ "anomaly": kind, "detail": detail }),
        Reason::Reputation { provider, score, .. } => json!({ "reputation": provider, "score": score }),
        Reason::KnownGood { list, .. } => json!({ "known_good": list }),
        Reason::Allowlisted { entry_id } => json!({ "allowlisted": entry_id }),
        Reason::PrivateNetwork => json!("private_network"),
        Reason::Loopback => json!("loopback"),
    }
}

fn conn_brief(c: &Connection) -> Value {
    json!({
        "direction": c.direction,
        "verdict": c.verdict.level,
        "proto": c.proto,
        "local": format!("{}:{}", c.local_ip, c.local_port),
        "remote": c.remote_ip.map(|ip| format!("{}:{}", ip, c.remote_port.unwrap_or(0))),
        "state": c.state,
        "process": c.process.as_ref().map(|p| json!({ "name": p.name, "pid": p.pid, "exe": p.exe })),
        "geo": c.geo,
        "reasons": c.verdict.reasons.iter().map(reason_brief).collect::<Vec<_>>(),
    })
}

fn verdict_of(s: &str) -> Option<VerdictLevel> {
    serde_json::from_value(json!(s)).ok()
}

fn direction_of(s: &str) -> Option<Direction> {
    serde_json::from_value(json!(s)).ok()
}

async fn snapshot(ctx: &ToolCtx) -> Result<crate::hub::contract::SnapshotPayload, String> {
    let cfg = crate::config::load_or_init(&ctx.config_dir).map_err(|e| e.message())?;
    crate::hub::watch::snapshot(&ctx.config_dir, &cfg.agent_id, ctx.intel().await)
        .await
        .map_err(|e| e.message())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

pub async fn call(ctx: &ToolCtx, name: &str, args: &Value) -> Result<String, String> {
    let s = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let n = |k: &str| args.get(k).and_then(Value::as_u64);
    match name {
        "list_connections" => {
            let snap = snapshot(ctx).await?;
            let dir = s("direction").and_then(direction_of);
            let verdicts: Vec<VerdictLevel> = args
                .get("verdict")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().and_then(verdict_of)).collect())
                .unwrap_or_default();
            let limit = n("limit").unwrap_or(100).clamp(1, 300) as usize;
            let mut list: Vec<&Connection> = snap
                .connections
                .iter()
                .filter(|c| dir.is_none_or(|d| c.direction == d))
                .filter(|c| verdicts.is_empty() || verdicts.contains(&c.verdict.level))
                .collect();
            list.sort_by_key(|c| std::cmp::Reverse(c.verdict.level));
            let total = list.len();
            Ok(to_text(&json!({
                "total": total,
                "shown": total.min(limit),
                "connections": list.into_iter().take(limit).map(conn_brief).collect::<Vec<_>>(),
            })))
        }
        "lookup_ip" => {
            let ind = s("indicator").ok_or_else(|| t!("缺少 indicator").to_string())?;
            let online = args.get("online").and_then(Value::as_bool).unwrap_or(false);
            let out = crate::cli::intel_cmd::compute_lookup(&ctx.config_dir, ind, online)
                .await
                .map_err(|e| e.message())?;
            Ok(to_text(&out.to_json()))
        }
        "inbound_attackers" => {
            let snap = snapshot(ctx).await?;
            let live: Vec<Value> = snap
                .connections
                .iter()
                .filter(|c| c.direction == Direction::Inbound && c.verdict.is_bad())
                .map(conn_brief)
                .collect();
            let collected = crate::events::collect(&crate::util::cmd::RealRunner, 7)
                .await
                .map_err(|e| e.message())?;
            let intel = ctx.intel().await;
            let summary = crate::events::summarize(collected, 7, intel.as_deref());
            let brute: Vec<&crate::events::model::SecurityHit> = summary
                .security
                .iter()
                .filter(|h| h.rule == "failed_logon_burst")
                .collect();
            Ok(to_text(&json!({
                "live_inbound": live,
                "failed_logon_bursts": brute,
                "needs_admin": summary.needs_admin,
            })))
        }
        "intel_sources" => {
            let reg = crate::intel::registry::Registry::load(&ctx.config_dir).map_err(|e| e.message())?;
            let feeds: Vec<Value> = reg
                .feeds
                .iter()
                .map(|f| {
                    let meta = crate::intel::fetch::FeedMeta::load(&ctx.config_dir, &f.id);
                    json!({
                        "id": f.id,
                        "vendor": f.vendor,
                        "name": f.name,
                        "kind": f.kind,
                        "confidence": f.confidence,
                        "enabled": reg.is_enabled(f),
                        "license": f.license,
                        "url": f.urls.first(),
                        "fetched_at": meta.as_ref().and_then(|m| m.fetched_at),
                        "entries": meta.as_ref().map(|m| m.entries),
                    })
                })
                .collect();
            Ok(to_text(&json!({ "feeds": feeds })))
        }
        "scan" => {
            let scanners: Vec<ScannerId> = args
                .get("scanners")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().and_then(ScannerId::parse)).collect())
                .unwrap_or_default();
            let (report, _) = crate::cli::scan_cmd::run_scan(&ctx.env(), &scanners, false)
                .await
                .map_err(|e| e.message())?;
            let _ = crate::hub::watch::save_latest(&ctx.config_dir, &report);
            Ok(to_text(&json!({
                "score": report.score,
                "partial": report.partial,
                "warnings": report.warnings,
                "findings": report.findings.iter().map(|f| json!({
                    "severity": f.severity, "rule": f.rule, "title": f.title, "id": f.id,
                })).collect::<Vec<_>>(),
            })))
        }
        "list_findings" => {
            let report = match crate::hub::watch::load_latest(&ctx.config_dir) {
                Some(r) => r,
                None => {
                    let (r, _) = crate::cli::scan_cmd::run_scan(&ctx.env(), &[], false)
                        .await
                        .map_err(|e| e.message())?;
                    let _ = crate::hub::watch::save_latest(&ctx.config_dir, &r);
                    r
                }
            };
            let min = severity_rank(s("min_severity").unwrap_or("info"));
            let scanner = s("scanner");
            let list: Vec<Value> = report
                .findings
                .iter()
                .filter(|f| severity_rank(f.severity.as_str()) >= min)
                .filter(|f| scanner.is_none_or(|sc| f.scanner.as_str() == sc))
                .map(|f| {
                    json!({
                        "id": f.id,
                        "severity": f.severity,
                        "scanner": f.scanner,
                        "rule": f.rule,
                        "title": f.title,
                        "detail": f.detail,
                        "recommendation": f.recommendation,
                        "intel": f.intel_hits.iter().map(|h| json!({ "vendor": h.vendor, "feed": h.name, "confidence": h.confidence, "source_url": h.source_url })).collect::<Vec<_>>(),
                        "actions": f.actions.iter().map(|a| json!({ "kind": a.kind, "params": a.params, "description": a.description })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            Ok(to_text(
                &json!({ "report_finished_at": report.finished_at, "findings": list }),
            ))
        }
        "get_report" => {
            let report = crate::hub::watch::load_latest(&ctx.config_dir)
                .ok_or_else(|| t!("還沒有報告；先呼叫 scan").to_string())?;
            let mut v = serde_json::to_value(&report).map_err(|e| e.to_string())?;
            if serde_json::to_string(&v).map(|t| t.len()).unwrap_or(0) > MAX_TEXT {
                if let Some(arr) = v.get_mut("findings").and_then(Value::as_array_mut) {
                    for f in arr {
                        f["evidence"] = json!("(omitted)");
                    }
                }
            }
            Ok(to_text(&v))
        }
        "listening_ports" => {
            let (_, _, listeners) = crate::cli::scan_cmd::run_scan_full(&ctx.env(), &[ScannerId::Ports], true)
                .await
                .map_err(|e| e.message())?;
            let risky = crate::connections::RiskyTable::load();
            let list: Vec<Value> = listeners
                .iter()
                .map(|l| {
                    json!({
                        "proto": l.proto,
                        "bind": l.bind_ip,
                        "port": l.port,
                        "process": l.process.as_ref().map(|p| json!({ "name": p.name, "pid": p.pid })),
                        "exposed": l.exposed,
                        "reachability": l.reachability,
                        "risky": risky.listening(&l.proto, l.port).map(|r| json!({ "name": r.name, "severity": r.severity, "why": r.rationale })),
                    })
                })
                .collect();
            Ok(to_text(&json!({ "listeners": list })))
        }
        "firewall_status" => {
            let fw = crate::firewall::read_current(&crate::util::cmd::RealRunner, crate::elevate::is_elevated())
                .await
                .map_err(|e| e.message())?;
            let audit: Vec<Value> = crate::firewall::audit(&fw)
                .iter()
                .map(|f| json!({ "severity": f.severity, "title": f.title, "recommendation": f.recommendation }))
                .collect();
            Ok(to_text(&json!({
                "backend": fw.backend,
                "enabled": fw.enabled,
                "profiles": fw.profiles,
                "default_inbound": fw.default_inbound,
                "inbound_allow_rules": fw.inbound_allow.len(),
                "inbound_allow_sample": fw.inbound_allow.iter().take(40).collect::<Vec<_>>(),
                "asa_rules": fw.ours_rules,
                "needs_elevation": fw.needs_elevation,
                "audit": audit,
                "notes": fw.notes,
            })))
        }
        "baseline_diff" => {
            let base = crate::model::baseline::Baseline::load(&ctx.config_dir)
                .map_err(|e| e.message())?
                .ok_or_else(|| t!("尚無基準線；請使用者先執行 asa baseline save --yes").to_string())?;
            let (_, snap) = crate::cli::scan_cmd::scan_for_baseline(&ctx.env())
                .await
                .map_err(|e| e.message())?;
            Ok(to_text(&serde_json::to_value(base.diff(&snap)).unwrap_or_default()))
        }
        "doctor" => {
            let r = crate::cli::doctor_cmd::collect(&ctx.env()).map_err(|e| e.message())?;
            Ok(to_text(&serde_json::to_value(r).unwrap_or_default()))
        }
        "traffic_summary" => {
            let secs = n("duration_s").unwrap_or(15).clamp(3, 60);
            let s = crate::traffic::lite::sample(
                &ctx.config_dir,
                Duration::from_secs(secs),
                Duration::from_secs(2),
                ctx.intel().await,
            )
            .await
            .map_err(|e| e.message())?;
            Ok(to_text(&serde_json::to_value(s).unwrap_or_default()))
        }
        "analyze_pcap" => {
            let path = PathBuf::from(s("path").ok_or_else(|| t!("缺少 path").to_string())?);
            let intel = ctx.intel().await;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let s = tokio::task::spawn_blocking(move || -> Result<_, String> {
                let (table, _) =
                    crate::traffic::offline::analyze_file(&path, crate::traffic::offline::DEFAULT_MAX_PACKETS)
                        .map_err(|e| e.message())?;
                Ok(crate::traffic::summary::from_flows(&table, &name, intel.as_deref()))
            })
            .await
            .map_err(|e| e.to_string())??;
            Ok(to_text(&serde_json::to_value(s).unwrap_or_default()))
        }
        "events_summary" | "crash_history" => {
            let default_days = if name == "events_summary" { 7 } else { 30 };
            let days = n("days").unwrap_or(default_days).clamp(1, 90) as u32;
            let collected = crate::events::collect(&crate::util::cmd::RealRunner, days)
                .await
                .map_err(|e| e.message())?;
            let intel = ctx.intel().await;
            let s = crate::events::summarize(collected, days, intel.as_deref());
            if name == "crash_history" {
                return Ok(to_text(
                    &json!({ "days": s.days, "crash_counts": s.crash_counts, "crashes": s.crashes, "needs_admin": s.needs_admin }),
                ));
            }
            Ok(to_text(&serde_json::to_value(s).unwrap_or_default()))
        }
        "explain_code" => {
            let code = s("code").ok_or_else(|| t!("缺少 code").to_string())?;
            let hex = code.to_ascii_lowercase().starts_with("0x");
            let events = if hex {
                Vec::new()
            } else {
                code.parse::<u32>()
                    .map(|n| crate::events::catalog::lookup_event(n, None))
                    .unwrap_or_default()
            };
            let bug = if events.is_empty() {
                crate::events::catalog::parse_code(code).and_then(crate::events::catalog::lookup_bugcheck)
            } else {
                None
            };
            if events.is_empty() && bug.is_none() {
                return Err(tf!("查無 {code}", code = code));
            }
            Ok(to_text(&json!({
                "events": events.iter().map(|e| json!({ "id": e.id, "provider": e.provider, "category": e.category, "text": crate::events::catalog::event_text(e) })).collect::<Vec<_>>(),
                "bugcheck": bug.map(|b| { let (causes, fix) = crate::events::catalog::bugcheck_text(&b); json!({ "code": b.code, "name": b.name, "causes": causes, "fix": fix }) }),
            })))
        }
        "preview_action" => preview_action(ctx, args).await,
        "execute_action" => execute_action(ctx, args).await,
        other => Err(tf!("未知的工具：{name}", name = other)),
    }
}

fn parse_action(args: &Value) -> Result<(FwAction, bool), String> {
    let s = |k: &str| {
        args.get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let kind = s("kind").ok_or_else(|| t!("缺少 kind").to_string())?;
    let port_spec = || -> Result<(String, u16), String> {
        let proto = s("proto").unwrap_or("tcp").to_string();
        let port = args
            .get("port")
            .and_then(Value::as_u64)
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| t!("缺少或錯誤的 port").to_string())?;
        Ok((proto, port as u16))
    };
    match kind {
        "block_ip" | "unblock_ip" => {
            let ip = s("ip").ok_or_else(|| t!("缺少 ip").to_string())?;
            let nets = crate::cli::fw_cmd::parse_targets(&[ip.to_string()], false).map_err(|e| e.message())?;
            if kind == "unblock_ip" {
                return Ok((FwAction::Unblock { nets }, false));
            }
            let direction = match s("direction").unwrap_or("both") {
                "in" => Dir::In,
                "out" => Dir::Out,
                _ => Dir::Both,
            };
            Ok((
                FwAction::Block {
                    nets,
                    direction,
                    reason: format!("mcp:{}", s("reason").unwrap_or("ai")),
                },
                false,
            ))
        }
        "close_port" => {
            let (proto, port) = port_spec()?;
            Ok((FwAction::ClosePort { proto, port }, true))
        }
        "open_port" => {
            let (proto, port) = port_spec()?;
            Ok((FwAction::OpenPort { proto, port }, false))
        }
        other => Err(tf!("不支援的動作：{kind}", kind = other)),
    }
}

async fn preview_action(ctx: &ToolCtx, args: &Value) -> Result<String, String> {
    let (action, destructive) = parse_action(args)?;
    if destructive && !ctx.allow_destructive {
        return Err(t!("這個 MCP 伺服器不允許破壞性動作（啟動時要加 --allow-destructive）").to_string());
    }
    // 封鎖前檢查白名單與已知良好清單（跟 hub 遠端動作同一套護欄）
    if let FwAction::Block { nets, .. } = &action {
        let allow = crate::model::allowlist::Allowlist::load(&ctx.config_dir).map_err(|e| e.message())?;
        let kg = crate::connections::KnownGood::load();
        for n in nets {
            if let Some(e) = allow.overlaps_net(n) {
                return Err(tf!("{net} 在本機白名單（{id}），不封鎖", net = n, id = e.id));
            }
            if let Some(list) = kg.overlaps_net(n) {
                return Err(tf!("{net} 屬於已知良好清單（{list}），不封鎖", net = n, list = list));
            }
        }
    }
    let backend = plan::write_backend().to_string();
    let p = crate::actions::prepare(&ctx.config_dir, &action, &backend, false).map_err(|e| e.message())?;
    let token = ctx.pending.insert(Pending {
        action: action.clone(),
        backend: backend.clone(),
        destructive,
        created: std::time::Instant::now(),
        origin: "mcp".into(),
    });
    Ok(to_text(&json!({
        "action": action.describe(),
        "backend": backend,
        "plan": p.display(),
        "notes": p.notes,
        "destructive": destructive,
        "reversible": true,
        "requires_elevation": true,
        "server_elevated": crate::elevate::is_elevated(),
        "review_token": token,
        "next": t!("把上面的計畫給使用者看，取得同意後再以 review_token 呼叫 execute_action（15 分鐘內、單次有效）"),
    })))
}

async fn execute_action(ctx: &ToolCtx, args: &Value) -> Result<String, String> {
    let token = args
        .get("review_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let p = ctx
        .pending
        .take(token)
        .ok_or_else(|| t!("審查代碼無效或已過期；請重新 preview_action").to_string())?;
    if !crate::elevate::is_elevated() {
        return Err(t!("asa mcp 不是以系統管理員身分執行，無法套用防火牆變更；請使用者以系統管理員身分重新啟動 MCP 伺服器，或在終端機執行 asa fw …").to_string());
    }
    let rep = crate::actions::execute(
        &ctx.config_dir,
        &p.action,
        &p.backend,
        &p.origin,
        &crate::util::cmd::RealRunner,
        false,
    )
    .await
    .map_err(|e| e.message())?;
    Ok(to_text(
        &json!({ "ok": rep.ok, "action": rep.action, "backend": rep.backend, "steps": rep.steps, "notes": rep.notes }),
    ))
}

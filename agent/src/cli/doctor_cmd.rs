//! `asa doctor`：環境檢查。各輪次陸續補上情資新鮮度、hub 連線、AI 用戶端偵測。

use serde::Serialize;

use super::render::{print_json, table};
use super::Env;
use crate::config;
use crate::error::AppResult;
use crate::secrets::SecretStore;

#[derive(Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub os: String,
    pub arch: String,
    pub elevated: bool,
    pub config_dir: String,
    pub secrets_backend: String,
    pub checks: Vec<Check>,
    pub tools: Vec<ToolCheck>,
}

#[derive(Serialize)]
pub struct ToolCheck {
    pub name: String,
    pub found: bool,
    pub path: Option<String>,
    pub purpose: String,
}

/// 這些外部工具都是「有就更好」，缺了 agent 會降級而不是失敗。
pub fn external_tools() -> Vec<(&'static str, &'static str)> {
    let mut v: Vec<(&str, &str)> = vec![
        ("nmap", t!("port 探測（選用）")),
        ("trivy", t!("套件漏洞外掃（選用）")),
        ("grype", t!("套件漏洞外掃（選用）")),
        ("claude", t!("Claude Code CLI（AI 分析）")),
        ("codex", t!("Codex CLI（AI 分析）")),
    ];
    if cfg!(windows) {
        v.extend([
            ("powershell", t!("防火牆 / 事件 / 清單查詢")),
            ("wevtutil", t!("Windows 事件日誌")),
            ("pktmon", t!("內建封包擷取（轉成 pcapng 給 asa traffic analyze）")),
            ("tshark", t!("Wireshark 命令列擷取（選用）")),
        ]);
    } else if cfg!(target_os = "macos") {
        v.extend([
            ("pfctl", t!("pf 防火牆")),
            ("log", t!("統一日誌")),
            ("nettop", t!("每行程流量（flow-lite）")),
            ("lynis", t!("硬化稽核（選用）")),
            ("tcpdump", t!("封包擷取（存成 pcap 給 asa traffic analyze）")),
        ]);
    } else {
        v.extend([
            ("nft", t!("nftables 防火牆")),
            ("iptables", t!("iptables 防火牆（退回）")),
            ("ufw", t!("ufw 防火牆")),
            ("firewall-cmd", t!("firewalld 防火牆")),
            ("journalctl", t!("systemd 日誌")),
            ("ss", t!("每 socket 流量（flow-lite）")),
            ("tcpdump", t!("封包擷取（存成 pcap 給 asa traffic analyze）")),
            ("lynis", t!("硬化稽核（選用）")),
        ]);
    }
    v
}

/// 封包擷取能力：asa 本身不抓包（不需要驅動），但能分析其他工具存下的 pcap／pcapng。
fn capture_check() -> Check {
    let npcap = cfg!(windows)
        && std::env::var_os("SystemRoot")
            .map(|r| {
                std::path::Path::new(&r)
                    .join("System32")
                    .join("Npcap")
                    .join("wpcap.dll")
                    .is_file()
            })
            .unwrap_or(false);
    let (ok, detail) = if cfg!(windows) {
        if npcap {
            (
                true,
                t!("Npcap 已安裝：可用 Wireshark 擷取後 asa traffic analyze <檔案>").to_string(),
            )
        } else if find_in_path("pktmon").is_some() {
            (
                true,
                t!("可用內建 pktmon：pktmon start --capture → pktmon stop → pktmon etl2pcap PktMon.etl（需系統管理員）").to_string(),
            )
        } else {
            (false, t!("沒有擷取工具；即時模式（asa traffic）仍可用。要逐封包分析請安裝 Npcap／Wireshark：https://npcap.com").to_string())
        }
    } else if find_in_path("tcpdump").is_some() {
        (
            true,
            t!("可用 tcpdump：sudo tcpdump -w cap.pcap → asa traffic analyze cap.pcap").to_string(),
        )
    } else {
        (false, t!("沒有 tcpdump；即時模式（asa traffic）仍可用").to_string())
    };
    Check {
        name: t!("封包擷取").into(),
        ok,
        detail,
    }
}

/// 在 PATH 上找可執行檔（不靠 `which` crate；Windows 補 .exe / .cmd / .bat）。
pub fn find_in_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    let exts: Vec<&str> = if cfg!(windows) {
        vec![".exe", ".cmd", ".bat", ""]
    } else {
        vec![""]
    };
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let p = dir.join(format!("{name}{ext}"));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

pub fn collect(env: &Env) -> AppResult<DoctorReport> {
    let cfg = config::load_or_init(&env.config_dir)?;
    let secrets = SecretStore::open(&env.config_dir);
    let mut checks = Vec::new();

    let writable = std::fs::create_dir_all(&env.config_dir).is_ok()
        && std::fs::write(env.config_dir.join(".write-test"), b"ok").is_ok();
    let _ = std::fs::remove_file(env.config_dir.join(".write-test"));
    checks.push(Check {
        name: t!("設定目錄可寫").into(),
        ok: writable,
        detail: env.config_dir.display().to_string(),
    });
    checks.push(Check {
        name: t!("agent id").into(),
        ok: !cfg.agent_id.is_empty(),
        detail: cfg.agent_id.clone(),
    });
    let elevated = crate::elevate::is_elevated();
    checks.push(Check {
        name: t!("系統管理員權限").into(),
        ok: true,
        detail: if elevated {
            t!("是（可取得完整結果與執行防火牆動作）").into()
        } else {
            t!("否（部分掃描結果受限；防火牆動作會按需請求提權）").into()
        },
    });
    checks.push(Check {
        name: t!("hub 註冊").into(),
        ok: true,
        detail: match &cfg.hub {
            Some(h) => h.url.clone(),
            None => t!("未註冊（asa enroll <HUB_URL> --key …）").into(),
        },
    });

    if let Ok(reg) = crate::intel::registry::Registry::load(&env.config_dir) {
        let (fresh, stale, missing) = crate::intel::fetch::freshness(&env.config_dir, &reg);
        checks.push(Check {
            name: t!("威脅情資").into(),
            ok: fresh > 0 && stale == 0,
            detail: tf!(
                "{fresh} 個最新、{stale} 個過期、{missing} 個未下載",
                fresh = fresh,
                stale = stale,
                missing = missing
            ),
        });
    }

    checks.push(capture_check());

    let tools = external_tools()
        .into_iter()
        .map(|(name, purpose)| {
            let p = find_in_path(name);
            ToolCheck {
                name: name.into(),
                found: p.is_some(),
                path: p.map(|p| p.display().to_string()),
                purpose: purpose.into(),
            }
        })
        .collect();

    Ok(DoctorReport {
        version: crate::VERSION.into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        elevated,
        config_dir: env.config_dir.display().to_string(),
        secrets_backend: secrets.backend().name().into(),
        checks,
        tools,
    })
}

pub async fn run(env: &Env) -> AppResult<()> {
    let r = collect(env)?;
    if env.global.json {
        print_json(&r);
        return Ok(());
    }
    println!(
        "asa {} · {}/{} · {}",
        r.version,
        r.os,
        r.arch,
        tf!("密鑰後端：{b}", b = r.secrets_backend)
    );
    let rows = r
        .checks
        .iter()
        .map(|c| {
            vec![
                if c.ok { "✓".into() } else { "✗".into() },
                c.name.clone(),
                c.detail.clone(),
            ]
        })
        .collect();
    println!("{}", table(&["", t!("檢查"), t!("結果")], rows));
    let rows = r
        .tools
        .iter()
        .map(|c| {
            vec![
                if c.found { "✓".into() } else { "–".into() },
                c.name.clone(),
                c.path.clone().unwrap_or_else(|| t!("未找到").into()),
                c.purpose.clone(),
            ]
        })
        .collect();
    println!("{}", table(&["", t!("外部工具"), t!("路徑"), t!("用途")], rows));
    Ok(())
}

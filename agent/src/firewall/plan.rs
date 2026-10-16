//! 防火牆寫入計畫：把動作（封鎖 / 解封 / 關 port / 啟用 / 同步情資）轉成要寫的檔案＋要跑的指令。
//! 全部是純函數，`--dry-run` 直接印出來給人看；IP 一律先解析成 `IpNet` 再序列化，不會有指令注入。
//!
//! 後端：Windows（NetSecurity，規則名 `ASA: …`、群組 `ASA`）、macOS（pf anchor `com.asa`）、
//! Linux 有 nft 時用自建 `table inet asa`（與 ufw / firewalld 並存），否則 iptables＋ipset。

use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::desired::DesiredState;
use crate::error::{AppError, AppResult};
use crate::util::cmd::{powershell, powershell_file, CmdSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum Dir {
    In,
    Out,
    Both,
}

impl Dir {
    pub fn includes_in(self) -> bool {
        matches!(self, Dir::In | Dir::Both)
    }
    pub fn includes_out(self) -> bool {
        matches!(self, Dir::Out | Dir::Both)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FwAction {
    Block {
        nets: Vec<IpNet>,
        direction: Dir,
        reason: String,
    },
    Unblock {
        nets: Vec<IpNet>,
    },
    UnblockAll,
    ClosePort {
        proto: String,
        port: u16,
    },
    OpenPort {
        proto: String,
        port: u16,
    },
    Enable {
        profile: Option<String>,
    },
    SyncFeeds {
        nets: Vec<IpNet>,
        feed_ids: Vec<String>,
    },
    Ensure,
}

impl FwAction {
    pub fn describe(&self) -> String {
        match self {
            FwAction::Block { nets, direction, .. } => tf!(
                "封鎖 {n} 個位址（{dir}）：{list}",
                n = nets.len(),
                dir = format!("{direction:?}").to_lowercase(),
                list = crate::util::text::clip(&nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "), 80)
            ),
            FwAction::Unblock { nets } => tf!(
                "解除封鎖 {n} 個位址：{list}",
                n = nets.len(),
                list = crate::util::text::clip(&nets.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", "), 80)
            ),
            FwAction::UnblockAll => t!("移除 asa 建立的所有防火牆規則").to_string(),
            FwAction::ClosePort { proto, port } => tf!("關閉對內 {proto} {port}", proto = proto, port = port),
            FwAction::OpenPort { proto, port } => tf!("取消關閉 {proto} {port}", proto = proto, port = port),
            FwAction::Enable { profile } => match profile {
                Some(p) => tf!("啟用 {profile} 防火牆設定檔", profile = p),
                None => t!("啟用主機防火牆").to_string(),
            },
            FwAction::SyncFeeds { nets, .. } => tf!("同步威脅情資黑名單到防火牆（{n} 個網段）", n = nets.len()),
            FwAction::Ensure => t!("依期望狀態重新套用 asa 規則").to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    Replace,
    /// 附加尚未存在的行。
    AppendLines,
    /// 刪除完全相同的行。
    RemoveLines,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FileWrite {
    pub path: PathBuf,
    pub content: String,
    pub mode: WriteMode,
    /// 寫 UTF-8 BOM（PowerShell 5.1 讀無 BOM 的 .ps1 會當成 ANSI）。
    pub bom: bool,
    /// 執行完畢後刪除（暫存腳本）。
    pub temporary: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Plan {
    pub backend: String,
    pub writes: Vec<FileWrite>,
    pub commands: Vec<CmdSpec>,
    pub notes: Vec<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.commands.is_empty()
    }

    /// 給人看的步驟。
    pub fn display(&self) -> Vec<String> {
        let mut out = Vec::new();
        for w in self.writes.iter().filter(|w| !w.temporary) {
            let verb = match w.mode {
                WriteMode::Replace => t!("寫入"),
                WriteMode::AppendLines => t!("附加到"),
                WriteMode::RemoveLines => t!("從檔案移除"),
            };
            out.push(format!(
                "{verb} {} ({} lines)",
                w.path.display(),
                w.content.lines().count()
            ));
        }
        for c in &self.commands {
            out.push(crate::util::text::clip(&c.display(), 400));
        }
        out
    }
}

pub struct PlanCtx {
    /// 暫存腳本目錄（`<config>/tmp`）。
    pub tmp_dir: PathBuf,
    pub desired: DesiredState,
    /// 目前已同步的情資網段（Ensure 用）。
    pub feed_nets: Vec<IpNet>,
    /// sshd 正在監聽（Linux 啟用防火牆前先放行 22，避免把自己鎖在外面）。
    pub ssh_listening: bool,
}

/// 可用來寫入的後端：`windows` / `pf` / `nft` / `ipset` / `none`。
pub fn write_backend() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "pf"
    } else if crate::cli::doctor_cmd::find_in_path("nft").is_some() {
        "nft"
    } else if crate::cli::doctor_cmd::find_in_path("ipset").is_some()
        && crate::cli::doctor_cmd::find_in_path("iptables").is_some()
    {
        "ipset"
    } else {
        "none"
    }
}

/// 規則說明欄只留安全字元。
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':' | '/'))
        .take(120)
        .collect()
}

pub fn plan(backend: &str, action: &FwAction, ctx: &PlanCtx) -> AppResult<Plan> {
    let mut p = match backend {
        "windows" => windows(action, ctx),
        "pf" => pf(action, ctx),
        "nft" => nft(action, ctx),
        "ipset" => ipset(action, ctx),
        _ => {
            return Err(AppError::Unsupported(
                t!("找不到可寫入的防火牆後端（Linux 需要 nft，或 iptables＋ipset）").into(),
            ))
        }
    }?;
    p.backend = backend.to_string();
    Ok(p)
}

fn v4(nets: &[IpNet]) -> Vec<String> {
    nets.iter()
        .filter(|n| matches!(n, IpNet::V4(_)))
        .map(|n| n.to_string())
        .collect()
}

fn v6(nets: &[IpNet]) -> Vec<String> {
    nets.iter()
        .filter(|n| matches!(n, IpNet::V6(_)))
        .map(|n| n.to_string())
        .collect()
}

// ---------------------------------------------------------------- Windows

fn ps_list(nets: &[IpNet]) -> String {
    let items: Vec<String> = nets.iter().map(|n| format!("'{n}'")).collect();
    format!("@({})", items.join(","))
}

fn proto_ps(proto: &str) -> &'static str {
    if proto == "udp" {
        "UDP"
    } else {
        "TCP"
    }
}

fn script_plan(ctx: &PlanCtx, script: String) -> Plan {
    let path = ctx.tmp_dir.join(format!(
        "asa-fw-{}.ps1",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    let content = format!("{}{}", crate::util::cmd::PS_PRELUDE, script);
    Plan {
        writes: vec![FileWrite {
            path: path.clone(),
            content,
            mode: WriteMode::Replace,
            bom: true,
            temporary: true,
        }],
        commands: vec![powershell_file(&path, &script).elevated()],
        ..Default::default()
    }
}

fn win_block_script(nets: &[IpNet], dir: Dir, reason: &str) -> String {
    let mut dirs = Vec::new();
    if dir.includes_in() {
        dirs.push("'Inbound'");
    }
    if dir.includes_out() {
        dirs.push("'Outbound'");
    }
    format!(
        "$nets = {}\nforeach ($n in $nets) {{\n  foreach ($d in @({})) {{\n    $name = \"ASA: block $n $d\"\n    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue\n    New-NetFirewallRule -DisplayName $name -Group 'ASA' -Direction $d -Action Block -RemoteAddress $n -Description 'asa: {}' | Out-Null\n  }}\n}}\n\"ok $($nets.Count)\"\n",
        ps_list(nets),
        dirs.join(","),
        sanitize(reason)
    )
}

fn win_feed_script(nets: &[IpNet]) -> String {
    format!(
        "Remove-NetFirewallRule -DisplayName 'ASA: feed *' -ErrorAction SilentlyContinue\n$a = {}\n$k = 0\nfor ($i = 0; $i -lt $a.Count; $i += 500) {{\n  $k++\n  $chunk = $a[$i..([Math]::Min($i + 499, $a.Count - 1))]\n  New-NetFirewallRule -DisplayName \"ASA: feed $k in\" -Group 'ASA' -Direction Inbound -Action Block -RemoteAddress $chunk -Description 'asa: threat-intel feeds' | Out-Null\n  New-NetFirewallRule -DisplayName \"ASA: feed $k out\" -Group 'ASA' -Direction Outbound -Action Block -RemoteAddress $chunk -Description 'asa: threat-intel feeds' | Out-Null\n}}\n\"ok $($a.Count) in $k chunks\"\n",
        if nets.is_empty() { "@()".to_string() } else { ps_list(nets) }
    )
}

fn win_close_script(proto: &str, port: u16) -> String {
    format!(
        "$name = 'ASA: close {proto} {port}'\nRemove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue\nNew-NetFirewallRule -DisplayName $name -Group 'ASA' -Direction Inbound -Action Block -Protocol {} -LocalPort {port} -Description 'asa: closed port' | Out-Null\n\"ok\"\n",
        proto_ps(proto)
    )
}

fn windows(action: &FwAction, ctx: &PlanCtx) -> AppResult<Plan> {
    let script = match action {
        FwAction::Block { nets, direction, reason } => win_block_script(nets, *direction, reason),
        FwAction::Unblock { nets } => format!(
            "$nets = {}\nforeach ($n in $nets) {{ foreach ($d in @('Inbound','Outbound')) {{ Remove-NetFirewallRule -DisplayName \"ASA: block $n $d\" -ErrorAction SilentlyContinue }} }}\n\"ok\"\n",
            ps_list(nets)
        ),
        FwAction::UnblockAll => "Remove-NetFirewallRule -Group 'ASA' -ErrorAction SilentlyContinue\n\"ok\"\n".to_string(),
        FwAction::ClosePort { proto, port } => win_close_script(proto, *port),
        FwAction::OpenPort { proto, port } => {
            format!("Remove-NetFirewallRule -DisplayName 'ASA: close {proto} {port}' -ErrorAction SilentlyContinue\n\"ok\"\n")
        }
        FwAction::Enable { profile } => {
            let prof = match profile.as_deref().map(|p| p.to_ascii_lowercase()) {
                Some(p) if p == "domain" => "Domain",
                Some(p) if p == "private" => "Private",
                Some(p) if p == "public" => "Public",
                Some(other) => return Err(AppError::InvalidArg(tf!("不支援的設定檔：{profile}", profile = other))),
                None => "Domain,Private,Public",
            };
            format!("Set-NetFirewallProfile -Profile {prof} -Enabled True\n\"ok\"\n")
        }
        FwAction::SyncFeeds { nets, .. } => win_feed_script(nets),
        FwAction::Ensure => {
            let mut s = String::new();
            for b in &ctx.desired.blocked {
                s.push_str(&win_block_script(&[b.net], b.direction, &b.reason));
            }
            for c in &ctx.desired.closed_ports {
                s.push_str(&win_close_script(&c.proto, c.port));
            }
            if !ctx.feed_nets.is_empty() {
                s.push_str(&win_feed_script(&ctx.feed_nets));
            }
            if s.is_empty() {
                return Ok(Plan {
                    notes: vec![t!("沒有需要重新套用的規則").to_string()],
                    ..Default::default()
                });
            }
            s
        }
    };
    // 短腳本直接 -EncodedCommand；長腳本（大量位址）寫成 .ps1 檔再 -File，避開 32K 命令列上限。
    if script.len() < 6000 {
        Ok(Plan {
            commands: vec![powershell(&script).elevated()],
            ..Default::default()
        })
    } else {
        Ok(script_plan(ctx, script))
    }
}

// ---------------------------------------------------------------- macOS pf

pub const PF_ANCHOR: &str = "/etc/pf.anchors/com.asa";
pub const PF_BLOCK: &str = "/etc/pf.anchors/asa_block.txt";
pub const PF_IN: &str = "/etc/pf.anchors/asa_in.txt";
pub const PF_OUT: &str = "/etc/pf.anchors/asa_out.txt";
pub const PF_FEED: &str = "/etc/pf.anchors/asa_feed.txt";
pub const PF_CONF: &str = "/etc/pf.conf";
pub const PF_CONF_BLOCK: &str =
    "# asa-begin\nanchor \"com.asa\"\nload anchor \"com.asa\" from \"/etc/pf.anchors/com.asa\"\n# asa-end\n";

/// anchor 內容依期望狀態產生（關閉的 port 寫在這裡）。
pub fn pf_anchor(closed: &[(String, u16)]) -> String {
    let mut s = String::from(
        "# managed by asa (ai-security-agent) — do not edit\n\
         table <asa_block> persist file \"/etc/pf.anchors/asa_block.txt\"\n\
         table <asa_in> persist file \"/etc/pf.anchors/asa_in.txt\"\n\
         table <asa_out> persist file \"/etc/pf.anchors/asa_out.txt\"\n\
         table <asa_feed> persist file \"/etc/pf.anchors/asa_feed.txt\"\n\
         block drop in quick from { <asa_block>, <asa_in>, <asa_feed> } to any\n\
         block drop out quick from any to { <asa_block>, <asa_out>, <asa_feed> }\n",
    );
    for (proto, port) in closed {
        s.push_str(&format!(
            "block drop in quick proto {proto} from any to any port {port}\n"
        ));
    }
    s
}

fn pf_table_file(dir: Dir) -> (&'static str, &'static str) {
    match dir {
        Dir::Both => ("asa_block", PF_BLOCK),
        Dir::In => ("asa_in", PF_IN),
        Dir::Out => ("asa_out", PF_OUT),
    }
}

fn pf_scaffold(closed: &[(String, u16)]) -> Plan {
    let mut p = Plan::default();
    for f in [PF_BLOCK, PF_IN, PF_OUT, PF_FEED] {
        p.writes.push(FileWrite {
            path: f.into(),
            content: String::new(),
            mode: WriteMode::AppendLines,
            bom: false,
            temporary: false,
        });
    }
    p.writes.push(FileWrite {
        path: PF_ANCHOR.into(),
        content: pf_anchor(closed),
        mode: WriteMode::Replace,
        bom: false,
        temporary: false,
    });
    p.writes.push(FileWrite {
        path: PF_CONF.into(),
        content: PF_CONF_BLOCK.into(),
        mode: WriteMode::AppendLines,
        bom: false,
        temporary: false,
    });
    p.commands.push(CmdSpec::new("pfctl", &["-f", PF_CONF]).elevated());
    p.commands
        .push(CmdSpec::new("pfctl", &["-e"]).elevated().tolerate_failure());
    p
}

fn closed_list(ctx: &PlanCtx) -> Vec<(String, u16)> {
    ctx.desired
        .closed_ports
        .iter()
        .map(|c| (c.proto.clone(), c.port))
        .collect()
}

fn pf(action: &FwAction, ctx: &PlanCtx) -> AppResult<Plan> {
    let mut closed = closed_list(ctx);
    match action {
        FwAction::ClosePort { proto, port } => {
            if !closed.iter().any(|(p, n)| p == proto && n == port) {
                closed.push((proto.clone(), *port));
            }
        }
        FwAction::OpenPort { proto, port } => closed.retain(|(p, n)| !(p == proto && n == port)),
        FwAction::UnblockAll => closed.clear(),
        _ => {}
    }
    let mut p = pf_scaffold(&closed);
    match action {
        FwAction::Block { nets, direction, .. } => {
            let (table, file) = pf_table_file(*direction);
            let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            p.writes.push(FileWrite {
                path: file.into(),
                content: list.iter().map(|s| format!("{s}\n")).collect(),
                mode: WriteMode::AppendLines,
                bom: false,
                temporary: false,
            });
            let mut args = vec!["-a", "com.asa", "-t", table, "-T", "add"];
            args.extend(list.iter().map(|s| s.as_str()));
            p.commands.push(CmdSpec::new("pfctl", &args).elevated());
        }
        FwAction::Unblock { nets } => {
            let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
            for (table, file) in [("asa_block", PF_BLOCK), ("asa_in", PF_IN), ("asa_out", PF_OUT)] {
                p.writes.push(FileWrite {
                    path: file.into(),
                    content: list.iter().map(|s| format!("{s}\n")).collect(),
                    mode: WriteMode::RemoveLines,
                    bom: false,
                    temporary: false,
                });
                let mut args = vec!["-a", "com.asa", "-t", table, "-T", "delete"];
                args.extend(list.iter().map(|s| s.as_str()));
                p.commands
                    .push(CmdSpec::new("pfctl", &args).elevated().tolerate_failure());
            }
        }
        FwAction::UnblockAll => {
            for f in [PF_BLOCK, PF_IN, PF_OUT, PF_FEED] {
                p.writes.push(FileWrite {
                    path: f.into(),
                    content: String::new(),
                    mode: WriteMode::Replace,
                    bom: false,
                    temporary: false,
                });
            }
            p.commands.push(
                CmdSpec::new("pfctl", &["-a", "com.asa", "-F", "all"])
                    .elevated()
                    .tolerate_failure(),
            );
        }
        FwAction::SyncFeeds { nets, .. } => {
            p.writes.push(FileWrite {
                path: PF_FEED.into(),
                content: nets.iter().map(|n| format!("{n}\n")).collect(),
                mode: WriteMode::Replace,
                bom: false,
                temporary: false,
            });
            p.commands.push(
                CmdSpec::new(
                    "pfctl",
                    &["-a", "com.asa", "-t", "asa_feed", "-T", "replace", "-f", PF_FEED],
                )
                .elevated(),
            );
        }
        FwAction::ClosePort { .. } | FwAction::OpenPort { .. } | FwAction::Ensure => {
            p.commands
                .push(CmdSpec::new("pfctl", &["-a", "com.asa", "-f", PF_ANCHOR]).elevated());
        }
        FwAction::Enable { .. } => {
            p.commands
                .push(CmdSpec::new(super::macos::SOCKETFILTERFW, &["--setglobalstate", "on"]).elevated());
        }
    }
    Ok(p)
}

// ---------------------------------------------------------------- Linux nftables

pub const NFT_SCAFFOLD: &str = "add table inet asa
add set inet asa block4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa block6 { type ipv6_addr; flags interval; auto-merge; }
add set inet asa in4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa in6 { type ipv6_addr; flags interval; auto-merge; }
add set inet asa out4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa out6 { type ipv6_addr; flags interval; auto-merge; }
add set inet asa feed4 { type ipv4_addr; flags interval; auto-merge; }
add set inet asa feed6 { type ipv6_addr; flags interval; auto-merge; }
add set inet asa ports_tcp { type inet_service; }
add set inet asa ports_udp { type inet_service; }
add chain inet asa input { type filter hook input priority -10; policy accept; }
add chain inet asa output { type filter hook output priority -10; policy accept; }
flush chain inet asa input
flush chain inet asa output
add rule inet asa input ip saddr @block4 drop
add rule inet asa input ip6 saddr @block6 drop
add rule inet asa input ip saddr @in4 drop
add rule inet asa input ip6 saddr @in6 drop
add rule inet asa input ip saddr @feed4 drop
add rule inet asa input ip6 saddr @feed6 drop
add rule inet asa input tcp dport @ports_tcp drop
add rule inet asa input udp dport @ports_udp drop
add rule inet asa output ip daddr @block4 drop
add rule inet asa output ip6 daddr @block6 drop
add rule inet asa output ip daddr @out4 drop
add rule inet asa output ip6 daddr @out6 drop
add rule inet asa output ip daddr @feed4 drop
add rule inet asa output ip6 daddr @feed6 drop
";

fn nft_sets(dir: Dir) -> (&'static str, &'static str) {
    match dir {
        Dir::Both => ("block4", "block6"),
        Dir::In => ("in4", "in6"),
        Dir::Out => ("out4", "out6"),
    }
}

fn nft_elements(verb: &str, set: &str, items: &[String]) -> String {
    let mut s = String::new();
    for chunk in items.chunks(2000) {
        s.push_str(&format!("{verb} element inet asa {set} {{ {} }}\n", chunk.join(", ")));
    }
    s
}

fn nft_cmd(script: String) -> CmdSpec {
    CmdSpec::new("nft", &["-f", "-"])
        .with_stdin(script)
        .elevated()
        .timeout(120_000)
}

fn nft(action: &FwAction, ctx: &PlanCtx) -> AppResult<Plan> {
    let mut p = Plan::default();
    match action {
        FwAction::Block { nets, direction, .. } => {
            let (s4, s6) = nft_sets(*direction);
            let script = format!(
                "{NFT_SCAFFOLD}{}{}",
                nft_elements("add", s4, &v4(nets)),
                nft_elements("add", s6, &v6(nets))
            );
            p.commands.push(nft_cmd(script));
        }
        FwAction::Unblock { nets } => {
            // delete element 遇到不存在的元素會整批失敗 → 每組分開、容忍失敗。
            for (s4, s6) in [nft_sets(Dir::Both), nft_sets(Dir::In), nft_sets(Dir::Out)] {
                for (set, items) in [(s4, v4(nets)), (s6, v6(nets))] {
                    for it in items {
                        p.commands
                            .push(nft_cmd(format!("delete element inet asa {set} {{ {it} }}\n")).tolerate_failure());
                    }
                }
            }
        }
        FwAction::UnblockAll => p
            .commands
            .push(nft_cmd("delete table inet asa\n".into()).tolerate_failure()),
        FwAction::ClosePort { proto, port } => {
            p.commands.push(nft_cmd(format!(
                "{NFT_SCAFFOLD}add element inet asa ports_{} {{ {port} }}\n",
                if proto == "udp" { "udp" } else { "tcp" }
            )));
        }
        FwAction::OpenPort { proto, port } => {
            p.commands.push(
                nft_cmd(format!(
                    "delete element inet asa ports_{} {{ {port} }}\n",
                    if proto == "udp" { "udp" } else { "tcp" }
                ))
                .tolerate_failure(),
            );
        }
        FwAction::SyncFeeds { nets, .. } => {
            let script = format!(
                "{NFT_SCAFFOLD}flush set inet asa feed4\nflush set inet asa feed6\n{}{}",
                nft_elements("add", "feed4", &v4(nets)),
                nft_elements("add", "feed6", &v6(nets))
            );
            p.commands.push(nft_cmd(script));
        }
        FwAction::Ensure => {
            let mut script = String::from(NFT_SCAFFOLD);
            for b in &ctx.desired.blocked {
                let (s4, s6) = nft_sets(b.direction);
                let set = if matches!(b.net, IpNet::V4(_)) { s4 } else { s6 };
                script.push_str(&format!("add element inet asa {set} {{ {} }}\n", b.net));
            }
            for c in &ctx.desired.closed_ports {
                script.push_str(&format!(
                    "add element inet asa ports_{} {{ {} }}\n",
                    if c.proto == "udp" { "udp" } else { "tcp" },
                    c.port
                ));
            }
            script.push_str("flush set inet asa feed4\nflush set inet asa feed6\n");
            script.push_str(&nft_elements("add", "feed4", &v4(&ctx.feed_nets)));
            script.push_str(&nft_elements("add", "feed6", &v6(&ctx.feed_nets)));
            p.commands.push(nft_cmd(script));
        }
        FwAction::Enable { .. } => linux_enable(&mut p, ctx),
    }
    Ok(p)
}

/// Linux 的「啟用防火牆」＝啟用 ufw 或 firewalld；sshd 在監聽時先放行 22，避免遠端管理被鎖。
fn linux_enable(p: &mut Plan, ctx: &PlanCtx) {
    use crate::cli::doctor_cmd::find_in_path;
    if find_in_path("ufw").is_some() {
        if ctx.ssh_listening {
            p.commands.push(CmdSpec::new("ufw", &["allow", "22/tcp"]).elevated());
            p.notes
                .push(t!("偵測到 sshd 正在監聽：先放行 22/tcp，避免遠端連線被切斷").to_string());
        }
        p.commands.push(CmdSpec::new("ufw", &["--force", "enable"]).elevated());
    } else if find_in_path("firewall-cmd").is_some() {
        p.commands
            .push(CmdSpec::new("systemctl", &["enable", "--now", "firewalld"]).elevated());
    } else {
        p.notes
            .push(t!("沒有 ufw 或 firewalld；請先安裝其中一個（apt install ufw / dnf install firewalld）").to_string());
    }
}

// ---------------------------------------------------------------- Linux iptables + ipset

const IPSET_SETS: &[(&str, &str)] = &[
    ("asa_block4", "inet"),
    ("asa_block6", "inet6"),
    ("asa_in4", "inet"),
    ("asa_in6", "inet6"),
    ("asa_out4", "inet"),
    ("asa_out6", "inet6"),
    ("asa_feed4", "inet"),
    ("asa_feed6", "inet6"),
];

fn sh(cmd: String) -> CmdSpec {
    CmdSpec::new("sh", &["-c", &cmd]).elevated()
}

fn ipset_scaffold(p: &mut Plan) {
    let mut restore = String::new();
    for (name, fam) in IPSET_SETS {
        restore.push_str(&format!("create {name} hash:net family {fam} maxelem 262144 -exist\n"));
    }
    p.commands.push(
        CmdSpec::new("ipset", &["restore", "-exist"])
            .with_stdin(restore)
            .elevated(),
    );
    // (鏈, 指令, set, 方向旗標)
    let rules = [
        ("INPUT", "iptables", "asa_block4", "src"),
        ("INPUT", "iptables", "asa_in4", "src"),
        ("INPUT", "iptables", "asa_feed4", "src"),
        ("OUTPUT", "iptables", "asa_block4", "dst"),
        ("OUTPUT", "iptables", "asa_out4", "dst"),
        ("OUTPUT", "iptables", "asa_feed4", "dst"),
        ("INPUT", "ip6tables", "asa_block6", "src"),
        ("INPUT", "ip6tables", "asa_in6", "src"),
        ("INPUT", "ip6tables", "asa_feed6", "src"),
        ("OUTPUT", "ip6tables", "asa_block6", "dst"),
        ("OUTPUT", "ip6tables", "asa_out6", "dst"),
        ("OUTPUT", "ip6tables", "asa_feed6", "dst"),
    ];
    for (chain, bin, set, flag) in rules {
        let r = format!("{chain} -m set --match-set {set} {flag} -j DROP");
        p.commands.push(sh(format!("{bin} -C {r} 2>/dev/null || {bin} -I {r}")));
    }
}

fn ipset(action: &FwAction, ctx: &PlanCtx) -> AppResult<Plan> {
    let mut p = Plan::default();
    let set_for = |dir: Dir, net: &IpNet| -> &'static str {
        let v6 = matches!(net, IpNet::V6(_));
        match (dir, v6) {
            (Dir::Both, false) => "asa_block4",
            (Dir::Both, true) => "asa_block6",
            (Dir::In, false) => "asa_in4",
            (Dir::In, true) => "asa_in6",
            (Dir::Out, false) => "asa_out4",
            (Dir::Out, true) => "asa_out6",
        }
    };
    match action {
        FwAction::Block { nets, direction, .. } => {
            ipset_scaffold(&mut p);
            let restore: String = nets
                .iter()
                .map(|n| format!("add {} {n} -exist\n", set_for(*direction, n)))
                .collect();
            p.commands.push(
                CmdSpec::new("ipset", &["restore", "-exist"])
                    .with_stdin(restore)
                    .elevated(),
            );
        }
        FwAction::Unblock { nets } => {
            let mut restore = String::new();
            for n in nets {
                for d in [Dir::Both, Dir::In, Dir::Out] {
                    restore.push_str(&format!("del {} {n} -exist\n", set_for(d, n)));
                }
            }
            p.commands.push(
                CmdSpec::new("ipset", &["restore", "-exist"])
                    .with_stdin(restore)
                    .elevated()
                    .tolerate_failure(),
            );
        }
        FwAction::UnblockAll => {
            for (set, _) in IPSET_SETS {
                for (chain, flag) in [("INPUT", "src"), ("OUTPUT", "dst")] {
                    for bin in ["iptables", "ip6tables"] {
                        p.commands.push(
                            sh(format!("while {bin} -D {chain} -m set --match-set {set} {flag} -j DROP 2>/dev/null; do :; done")).tolerate_failure(),
                        );
                    }
                }
            }
            for (set, _) in IPSET_SETS {
                p.commands
                    .push(CmdSpec::new("ipset", &["destroy", set]).elevated().tolerate_failure());
            }
            for c in &ctx.desired.closed_ports {
                p.commands.push(
                    sh(format!(
                        "while iptables -D INPUT -p {} --dport {} -j DROP 2>/dev/null; do :; done",
                        c.proto, c.port
                    ))
                    .tolerate_failure(),
                );
            }
        }
        FwAction::ClosePort { proto, port } => {
            let r = format!("INPUT -p {proto} --dport {port} -j DROP");
            p.commands
                .push(sh(format!("iptables -C {r} 2>/dev/null || iptables -I {r}")));
            p.commands
                .push(sh(format!("ip6tables -C {r} 2>/dev/null || ip6tables -I {r}")).tolerate_failure());
        }
        FwAction::OpenPort { proto, port } => {
            for bin in ["iptables", "ip6tables"] {
                p.commands.push(
                    sh(format!(
                        "while {bin} -D INPUT -p {proto} --dport {port} -j DROP 2>/dev/null; do :; done"
                    ))
                    .tolerate_failure(),
                );
            }
        }
        FwAction::SyncFeeds { nets, .. } => {
            ipset_scaffold(&mut p);
            for (live, fam, list) in [("asa_feed4", "inet", v4(nets)), ("asa_feed6", "inet6", v6(nets))] {
                let tmp = format!("{live}_tmp");
                let mut restore = format!("create {tmp} hash:net family {fam} maxelem 262144 -exist\nflush {tmp}\n");
                for n in &list {
                    restore.push_str(&format!("add {tmp} {n} -exist\n"));
                }
                restore.push_str(&format!("swap {tmp} {live}\ndestroy {tmp}\n"));
                p.commands.push(
                    CmdSpec::new("ipset", &["restore", "-exist"])
                        .with_stdin(restore)
                        .elevated(),
                );
            }
        }
        FwAction::Ensure => {
            ipset_scaffold(&mut p);
            let mut restore = String::new();
            for b in &ctx.desired.blocked {
                restore.push_str(&format!("add {} {} -exist\n", set_for(b.direction, &b.net), b.net));
            }
            for n in &ctx.feed_nets {
                restore.push_str(&format!(
                    "add {} {n} -exist\n",
                    if matches!(n, IpNet::V4(_)) {
                        "asa_feed4"
                    } else {
                        "asa_feed6"
                    }
                ));
            }
            if !restore.is_empty() {
                p.commands.push(
                    CmdSpec::new("ipset", &["restore", "-exist"])
                        .with_stdin(restore)
                        .elevated(),
                );
            }
            for c in &ctx.desired.closed_ports {
                let r = format!("INPUT -p {} --dport {} -j DROP", c.proto, c.port);
                p.commands
                    .push(sh(format!("iptables -C {r} 2>/dev/null || iptables -I {r}")));
            }
        }
        FwAction::Enable { .. } => linux_enable(&mut p, ctx),
    }
    Ok(p)
}

/// 在 Plan 的暫存目錄下產生路徑（測試用）。
pub fn ctx_for_tests(dir: &Path) -> PlanCtx {
    PlanCtx {
        tmp_dir: dir.join("tmp"),
        desired: DesiredState::default(),
        feed_nets: Vec::new(),
        ssh_listening: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(s: &[&str]) -> Vec<IpNet> {
        s.iter().map(|x| x.parse().unwrap()).collect()
    }

    fn ctx() -> PlanCtx {
        ctx_for_tests(Path::new("/tmp/asa-test"))
    }

    #[test]
    fn windows_block_uses_named_group_rules() {
        let p = plan(
            "windows",
            &FwAction::Block {
                nets: nets(&["198.51.100.7/32"]),
                direction: Dir::Both,
                reason: "feodo; rm -rf'".into(),
            },
            &ctx(),
        )
        .unwrap();
        assert_eq!(p.commands.len(), 1);
        let script = p.commands[0].script.as_ref().unwrap();
        assert!(script.contains("@('198.51.100.7/32')"));
        assert!(script.contains("-Group 'ASA'"));
        assert!(script.contains("'Inbound','Outbound'"));
        assert!(script.contains("asa: feodo rm -rf"), "{script}");
        assert!(p.commands[0].needs_elevation);
    }

    #[test]
    fn windows_large_feed_goes_to_script_file() {
        let many: Vec<IpNet> = (0..2000u32)
            .map(|i| IpNet::from(std::net::IpAddr::V4((0x2d000000 + i * 256).into())))
            .collect();
        let p = plan(
            "windows",
            &FwAction::SyncFeeds {
                nets: many,
                feed_ids: vec![],
            },
            &ctx(),
        )
        .unwrap();
        assert_eq!(p.writes.len(), 1);
        assert!(p.writes[0].bom && p.writes[0].temporary);
        assert!(p.commands[0].args.contains(&"-File".to_string()));
        assert!(p.writes[0].content.contains("ASA: feed *"));
    }

    #[test]
    fn windows_enable_validates_profile() {
        let p = plan(
            "windows",
            &FwAction::Enable {
                profile: Some("public".into()),
            },
            &ctx(),
        )
        .unwrap();
        assert!(p.commands[0]
            .script
            .as_ref()
            .unwrap()
            .contains("Set-NetFirewallProfile -Profile Public -Enabled True"));
        assert!(plan(
            "windows",
            &FwAction::Enable {
                profile: Some("evil; x".into())
            },
            &ctx()
        )
        .is_err());
    }

    #[test]
    fn nft_block_and_sync() {
        let p = plan(
            "nft",
            &FwAction::Block {
                nets: nets(&["198.51.100.7/32", "2001:db8::/48"]),
                direction: Dir::In,
                reason: String::new(),
            },
            &ctx(),
        )
        .unwrap();
        let s = p.commands[0].stdin.as_ref().unwrap();
        assert!(s.starts_with("add table inet asa"));
        assert!(s.contains("add element inet asa in4 { 198.51.100.7/32 }"));
        assert!(s.contains("add element inet asa in6 { 2001:db8::/48 }"));
        assert_eq!(p.commands[0].display(), "nft -f -");
        let p = plan(
            "nft",
            &FwAction::SyncFeeds {
                nets: nets(&["203.0.113.0/24"]),
                feed_ids: vec![],
            },
            &ctx(),
        )
        .unwrap();
        let s = p.commands[0].stdin.as_ref().unwrap();
        assert!(s.contains("flush set inet asa feed4") && s.contains("add element inet asa feed4 { 203.0.113.0/24 }"));
        let p = plan(
            "nft",
            &FwAction::Unblock {
                nets: nets(&["198.51.100.7/32"]),
            },
            &ctx(),
        )
        .unwrap();
        assert!(p.commands.iter().all(|c| c.allow_fail));
    }

    #[test]
    fn pf_anchor_and_tables() {
        let p = plan(
            "pf",
            &FwAction::Block {
                nets: nets(&["198.51.100.7/32"]),
                direction: Dir::Both,
                reason: String::new(),
            },
            &ctx(),
        )
        .unwrap();
        assert!(p
            .writes
            .iter()
            .any(|w| w.path == Path::new(PF_CONF) && w.content.contains("load anchor \"com.asa\"")));
        assert!(p
            .commands
            .iter()
            .any(|c| c.display() == "pfctl -a com.asa -t asa_block -T add 198.51.100.7/32"));
        let p = plan(
            "pf",
            &FwAction::ClosePort {
                proto: "tcp".into(),
                port: 6379,
            },
            &ctx(),
        )
        .unwrap();
        let anchor = p.writes.iter().find(|w| w.path == Path::new(PF_ANCHOR)).unwrap();
        assert!(anchor
            .content
            .contains("block drop in quick proto tcp from any to any port 6379"));
    }

    #[test]
    fn ipset_block_and_close() {
        let p = plan(
            "ipset",
            &FwAction::Block {
                nets: nets(&["198.51.100.7/32"]),
                direction: Dir::Out,
                reason: String::new(),
            },
            &ctx(),
        )
        .unwrap();
        assert!(p
            .commands
            .iter()
            .any(|c| c.stdin.as_deref() == Some("add asa_out4 198.51.100.7/32 -exist\n")));
        assert!(p.commands.iter().any(|c| c
            .display()
            .contains("iptables -C OUTPUT -m set --match-set asa_out4 dst -j DROP")));
        let p = plan(
            "ipset",
            &FwAction::ClosePort {
                proto: "tcp".into(),
                port: 6379,
            },
            &ctx(),
        )
        .unwrap();
        assert!(p.commands[0]
            .display()
            .contains("iptables -I INPUT -p tcp --dport 6379 -j DROP"));
    }

    #[test]
    fn unknown_backend_errors() {
        assert!(plan("none", &FwAction::Ensure, &ctx()).is_err());
    }
}

//! 取值：Windows 把所有 registry／powershell 檢查合併成一次 PowerShell 呼叫；Unix 讀檔、/proc/sys、sshd_config、
//! systemctl 與少數內建檢查（UID 0、空白密碼、sudo NOPASSWD、PATH 可寫、AppArmor／SELinux）。

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::PathBuf;

use serde_json::{json, Value};

use super::policy::{Check, ServiceQuery};
use crate::util::cmd::{powershell, CmdRunner, CmdSpec};

#[derive(Debug, Clone, PartialEq)]
pub enum Observed {
    Value(Value),
    /// 讀不到值（機碼、檔案或設定不存在）。
    Missing,
    /// 需要系統管理員／root 才讀得到。
    NeedsAdmin,
    NotApplicable(String),
    Error(String),
}

pub struct ProbeEnv {
    pub family: String,
    /// 檔案類檢查的根目錄（正式為 `/`，測試指向暫存目錄）。
    pub root: PathBuf,
    pub path_var: Option<String>,
    /// Windows 版本標籤（client／server／core／desktop／dc），給策略的 `editions` 篩選；空＝不篩選。
    pub editions: Vec<String>,
}

impl ProbeEnv {
    pub fn current(family: &str) -> Self {
        Self {
            family: family.to_string(),
            root: PathBuf::from("/"),
            path_var: std::env::var("PATH").ok(),
            editions: if family == "windows" {
                crate::util::winver::WinEdition::current().tags()
            } else {
                Vec::new()
            },
        }
    }

    pub fn is_server(&self) -> bool {
        self.editions.iter().any(|t| t == "server")
    }

    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn read(&self, p: &str) -> Result<String, Observed> {
        std::fs::read_to_string(self.path(p)).map_err(|e| match e.kind() {
            ErrorKind::NotFound => Observed::Missing,
            ErrorKind::PermissionDenied => Observed::NeedsAdmin,
            _ => Observed::Error(e.to_string()),
        })
    }
}

pub async fn observe(checks: &[Check], runner: &dyn CmdRunner, env: &ProbeEnv) -> HashMap<String, Observed> {
    let mut out = HashMap::new();
    let mut todo = Vec::new();
    for c in checks {
        if !c.applies_to_edition(&env.editions) {
            out.insert(
                c.id.clone(),
                Observed::NotApplicable(tf!("這個 Windows 版本不適用（{e}）", e = env.editions.join("/"))),
            );
            continue;
        }
        match &c.only_if_exists {
            Some(p) if !env.path(p).exists() => {
                out.insert(c.id.clone(), Observed::NotApplicable(format!("{p} not found")));
            }
            _ => todo.push(c),
        }
    }
    let ps: Vec<&Check> = todo.iter().copied().filter(|c| c.probe.is_powershell()).collect();
    if !ps.is_empty() {
        if env.family == "windows" {
            out.extend(observe_powershell(&ps, runner).await);
        } else {
            for c in &ps {
                out.insert(c.id.clone(), Observed::NotApplicable("Windows only".into()));
            }
        }
    }
    for c in todo.into_iter().filter(|c| !c.probe.is_powershell()) {
        let o = observe_one(c, runner, env).await;
        out.insert(c.id.clone(), o);
    }
    out
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

pub fn windows_script(checks: &[&Check]) -> String {
    let mut s = String::from("$r = [ordered]@{}\n");
    for c in checks {
        let id = ps_quote(&c.id);
        let body = if let Some(r) = &c.probe.registry {
            format!(
                "(Get-ItemProperty -LiteralPath {} -ErrorAction SilentlyContinue).{}",
                ps_quote(&r.path),
                ps_quote(&r.name)
            )
        } else {
            format!("& {{\n{}\n}}", c.probe.powershell.as_deref().unwrap_or(""))
        };
        s.push_str(&format!(
            "try {{ $r[{id}] = {body} }} catch {{ $r[{id}] = @{{ __error = $_.Exception.Message }} }}\n"
        ));
    }
    s.push_str("$r | ConvertTo-Json -Depth 4 -Compress\n");
    s
}

pub fn parse_windows_output(checks: &[&Check], stdout: &str) -> Option<HashMap<String, Observed>> {
    let start = stdout.find('{')?;
    let v: Value = serde_json::from_str(stdout[start..].trim()).ok()?;
    let obj = v.as_object()?;
    Some(
        checks
            .iter()
            .map(|c| {
                let o = match obj.get(&c.id) {
                    None | Some(Value::Null) => Observed::Missing,
                    Some(Value::Object(m)) if m.contains_key("__error") => {
                        Observed::Error(m["__error"].as_str().unwrap_or("").to_string())
                    }
                    Some(v) => Observed::Value(v.clone()),
                };
                (c.id.clone(), o)
            })
            .collect(),
    )
}

async fn observe_powershell(checks: &[&Check], runner: &dyn CmdRunner) -> HashMap<String, Observed> {
    let fail = |msg: String| -> HashMap<String, Observed> {
        checks
            .iter()
            .map(|c| (c.id.clone(), Observed::Error(msg.clone())))
            .collect()
    };
    match runner.run(&powershell(&windows_script(checks)).timeout(120_000)).await {
        Ok(o) => parse_windows_output(checks, &o.stdout)
            .unwrap_or_else(|| fail(crate::util::text::clip(&format!("{} {}", o.stdout, o.stderr), 300))),
        Err(e) => fail(e.message()),
    }
}

fn apply_regex(c: &Check, text: &str) -> Observed {
    match &c.probe.regex {
        Some(r) => match regex::Regex::new(r).ok().and_then(|re| {
            re.captures(text).map(|cap| {
                cap.get(1)
                    .or_else(|| cap.get(0))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default()
            })
        }) {
            Some(v) => Observed::Value(json!(v)),
            None => Observed::Missing,
        },
        None => Observed::Value(json!(text.trim())),
    }
}

async fn observe_one(c: &Check, runner: &dyn CmdRunner, env: &ProbeEnv) -> Observed {
    let p = &c.probe;
    if let Some(cmd) = &p.command {
        let args: Vec<&str> = cmd[1..].iter().map(String::as_str).collect();
        return match runner.run(&CmdSpec::new(&cmd[0], &args).timeout(20_000)).await {
            Err(e) => Observed::NotApplicable(e.message()),
            Ok(o) => {
                let all = format!("{}\n{}", o.stdout, o.stderr).to_ascii_lowercase();
                if o.permission_denied() || all.contains("administrator access") {
                    return Observed::NeedsAdmin;
                }
                let text = if p.stderr {
                    format!("{}\n{}", o.stdout, o.stderr)
                } else {
                    o.stdout.clone()
                };
                if text.trim().is_empty() && !o.ok() {
                    return Observed::Missing;
                }
                apply_regex(c, &text)
            }
        };
    }
    if let Some(f) = &p.file {
        return match env.read(f) {
            Ok(t) => apply_regex(c, &t),
            Err(o) => o,
        };
    }
    if let Some(key) = &p.sysctl {
        if env.family == "linux" {
            return match env.read(&format!("proc/sys/{}", key.replace('.', "/"))) {
                Ok(t) => Observed::Value(json!(t.trim())),
                Err(o) => o,
            };
        }
        return match runner.run(&CmdSpec::new("sysctl", &["-n", key]).timeout(10_000)).await {
            Ok(o) if o.ok() => Observed::Value(json!(o.stdout.trim())),
            Ok(_) => Observed::Missing,
            Err(e) => Observed::NotApplicable(e.message()),
        };
    }
    if let Some(s) = &p.sshd {
        let text = match env.read("etc/ssh/sshd_config") {
            Ok(t) => t,
            Err(Observed::Missing) => return Observed::NotApplicable("sshd_config not found".into()),
            Err(o) => return o,
        };
        return match sshd_value(env, &text, &s.key, 0) {
            Some(v) => Observed::Value(json!(v)),
            None => s
                .default
                .clone()
                .map(|d| Observed::Value(json!(d)))
                .unwrap_or(Observed::Missing),
        };
    }
    if let Some(s) = &p.service {
        let verb = match s.query {
            ServiceQuery::Active => "is-active",
            ServiceQuery::Enabled => "is-enabled",
        };
        let target = match s.query {
            ServiceQuery::Active => "active",
            ServiceQuery::Enabled => "enabled",
        };
        let mut first: Option<String> = None;
        for name in &s.names {
            match runner
                .run(&CmdSpec::new("systemctl", &[verb, name]).timeout(10_000))
                .await
            {
                Err(e) => return Observed::NotApplicable(e.message()),
                Ok(o) => {
                    let state = o.stdout.trim().to_string();
                    if state == target {
                        return Observed::Value(json!(target));
                    }
                    // is-enabled 對不存在的 unit 只印錯誤到 stderr；is-active 一律印 inactive
                    if !state.is_empty() && first.is_none() && !(s.query == ServiceQuery::Active && state == "inactive")
                    {
                        first = Some(state);
                    }
                }
            }
        }
        return match first {
            Some(v) => Observed::Value(json!(v)),
            None if s.query == ServiceQuery::Active => Observed::Value(json!("inactive")),
            None => Observed::Missing,
        };
    }
    if let Some(b) = &p.builtin {
        return builtin(b, env);
    }
    Observed::Error("no probe".into())
}

/// sshd_config 全域區（第一個 Match 之前）的第一個值；Include 依字母順序展開。
fn sshd_value(env: &ProbeEnv, text: &str, key: &str, depth: u8) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let k = parts.next().unwrap_or("");
        let v = parts.next().unwrap_or("").trim().trim_start_matches('=').trim();
        if k.eq_ignore_ascii_case("match") {
            return None;
        }
        if k.eq_ignore_ascii_case("include") && depth < 3 {
            for pat in v.split_whitespace() {
                let pat = if pat.starts_with('/') {
                    pat.to_string()
                } else {
                    format!("/etc/ssh/{pat}")
                };
                for f in expand_glob(env, &pat) {
                    if let Ok(t) = std::fs::read_to_string(&f) {
                        if let Some(found) = sshd_value(env, &t, key, depth + 1) {
                            return Some(found);
                        }
                    }
                }
            }
            continue;
        }
        if k.eq_ignore_ascii_case(key) {
            return v.split_whitespace().next().map(|s| s.to_ascii_lowercase());
        }
    }
    None
}

fn expand_glob(env: &ProbeEnv, pattern: &str) -> Vec<PathBuf> {
    let (dir, name) = pattern.rsplit_once('/').unwrap_or(("/", pattern));
    if !name.contains('*') && !name.contains('?') {
        return vec![env.path(pattern)];
    }
    let Ok(glob) = globset::Glob::new(name).map(|g| g.compile_matcher()) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = std::fs::read_dir(env.path(dir))
        .map(|rd| {
            rd.flatten()
                .filter(|e| glob.is_match(e.file_name().to_string_lossy().as_ref()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn builtin(name: &str, env: &ProbeEnv) -> Observed {
    match name {
        "lsm" => {
            let read = |p: &str| env.read(p).map(|t| t.trim().to_string()).unwrap_or_default();
            if read("sys/module/apparmor/parameters/enabled") == "Y" {
                Observed::Value(json!("apparmor"))
            } else if read("sys/fs/selinux/enforce") == "1" {
                Observed::Value(json!("selinux"))
            } else {
                Observed::Value(json!("none"))
            }
        }
        "uid0_accounts" => match env.read("etc/passwd") {
            Ok(t) => Observed::Value(json!(t
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() > 3 && f[2] == "0" && f[0] != "root" && !l.starts_with('#')).then(|| f[0].to_string())
                })
                .collect::<Vec<_>>())),
            Err(o) => o,
        },
        "empty_passwords" => match env.read("etc/shadow") {
            Ok(t) => Observed::Value(json!(t
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() > 1 && f[1].is_empty()).then(|| f[0].to_string())
                })
                .collect::<Vec<_>>())),
            Err(o) => o,
        },
        "sudo_nopasswd" => {
            let mut files = vec![env.path("etc/sudoers")];
            match std::fs::read_dir(env.path("etc/sudoers.d")) {
                Ok(rd) => {
                    let mut v: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
                    v.sort();
                    files.extend(v);
                }
                Err(e) if e.kind() == ErrorKind::PermissionDenied => return Observed::NeedsAdmin,
                Err(_) => {}
            }
            let mut hits = Vec::new();
            let mut read_any = false;
            for f in files {
                match std::fs::read_to_string(&f) {
                    Ok(t) => {
                        read_any = true;
                        let name = f
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        for l in t.lines().map(str::trim) {
                            if !l.starts_with('#') && l.contains("NOPASSWD") {
                                hits.push(format!("{name}: {}", crate::util::text::clip(l, 120)));
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::PermissionDenied => return Observed::NeedsAdmin,
                    Err(_) => {}
                }
            }
            if read_any {
                Observed::Value(json!(hits))
            } else {
                Observed::Missing
            }
        }
        "path_world_writable" => {
            let dirs = env.path_var.clone().unwrap_or_default();
            let mut bad = Vec::new();
            for d in dirs.split(':').filter(|d| !d.is_empty()) {
                if world_writable(&std::path::PathBuf::from(d)) {
                    bad.push(d.to_string());
                }
            }
            Observed::Value(json!(bad))
        }
        other => Observed::Error(format!("unknown builtin {other}")),
    }
}

#[cfg(unix)]
fn world_writable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_dir() && m.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn world_writable(_p: &std::path::Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardening::policy::parse;
    use crate::util::cmd::{CmdOutput, FakeRunner};

    fn env(root: &std::path::Path, family: &str) -> ProbeEnv {
        ProbeEnv {
            family: family.into(),
            root: root.to_path_buf(),
            path_var: None,
            editions: Vec::new(),
        }
    }

    fn write(root: &std::path::Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    #[test]
    fn windows_batch_script_and_output() {
        let checks = parse(crate::embedded::feeds_file("policies/windows.yml").unwrap()).unwrap();
        let refs: Vec<&Check> = checks.iter().collect();
        let s = windows_script(&refs);
        assert!(s.contains("$r['win.uac.enabled'] = (Get-ItemProperty -LiteralPath 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue).'EnableLUA'"));
        assert!(s.contains("Get-MpComputerStatus"));
        assert!(s.ends_with("ConvertTo-Json -Depth 4 -Compress\n"));
        let out = parse_windows_output(
            &refs,
            "\u{feff}{\"win.uac.enabled\":1,\"win.defender.realtime\":\"on\",\"win.secureboot\":null,\"win.account.guest\":{\"__error\":\"boom\"}}",
        )
        .unwrap();
        assert_eq!(out["win.uac.enabled"], Observed::Value(json!(1)));
        assert_eq!(out["win.secureboot"], Observed::Missing);
        assert_eq!(out["win.lsa.protection"], Observed::Missing);
        assert_eq!(out["win.account.guest"], Observed::Error("boom".into()));
    }

    #[test]
    fn linux_probes_read_files_sysctl_sshd_and_builtins() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        write(r, "etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n# PermitRootLogin yes\nPermitRootLogin yes\nX11Forwarding yes\nMatch User bob\n  PasswordAuthentication no\n");
        write(
            r,
            "etc/ssh/sshd_config.d/50-cloud.conf",
            "PasswordAuthentication no\nPermitRootLogin=no\n",
        );
        write(r, "proc/sys/kernel/randomize_va_space", "2\n");
        write(
            r,
            "etc/passwd",
            "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nbob:x:1000:1000::/home/bob:/bin/bash\n",
        );
        write(r, "etc/shadow", "root:$6$x:1::::::\nbob::1::::::\n");
        write(
            r,
            "etc/sudoers",
            "# %wheel ALL=(ALL) NOPASSWD: ALL\nroot ALL=(ALL) ALL\n",
        );
        write(r, "etc/sudoers.d/90-cloud", "ubuntu ALL=(ALL) NOPASSWD:ALL\n");
        write(
            r,
            "etc/apt/apt.conf.d/20auto-upgrades",
            "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
        );
        write(r, "sys/module/apparmor/parameters/enabled", "Y\n");
        let checks = parse(crate::embedded::feeds_file("policies/linux.yml").unwrap()).unwrap();
        let runner = FakeRunner::new()
            .on(
                "systemctl is-active fail2ban",
                CmdOutput {
                    code: Some(3),
                    stdout: "inactive\n".into(),
                    stderr: String::new(),
                },
            )
            .on("systemctl is-active crowdsec", CmdOutput::success("active\n"))
            .on(
                "systemctl is-active auditd",
                CmdOutput {
                    code: Some(3),
                    stdout: "inactive\n".into(),
                    stderr: String::new(),
                },
            )
            .on(
                "systemctl is-active",
                CmdOutput {
                    code: Some(3),
                    stdout: "inactive\n".into(),
                    stderr: String::new(),
                },
            );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let o = rt.block_on(observe(&checks, &runner, &env(r, "linux")));
        assert_eq!(
            o["lin.ssh.root_login"],
            Observed::Value(json!("no")),
            "Include 先於主檔"
        );
        assert_eq!(o["lin.ssh.password_auth"], Observed::Value(json!("no")));
        assert_eq!(o["lin.ssh.x11_forwarding"], Observed::Value(json!("yes")));
        assert_eq!(o["lin.ssh.empty_passwords"], Observed::Value(json!("no")), "預設值");
        assert_eq!(o["lin.ssh.brute_force_guard"], Observed::Value(json!("active")));
        assert_eq!(o["lin.kernel.aslr"], Observed::Value(json!("2")));
        assert_eq!(o["lin.kernel.kptr_restrict"], Observed::Missing);
        assert_eq!(o["lin.accounts.uid0"], Observed::Value(json!(["toor"])));
        assert_eq!(o["lin.accounts.empty_passwords"], Observed::Value(json!(["bob"])));
        assert_eq!(
            o["lin.sudo.nopasswd"],
            Observed::Value(json!(["90-cloud: ubuntu ALL=(ALL) NOPASSWD:ALL"]))
        );
        assert_eq!(o["lin.updates.unattended"], Observed::Value(json!("1")));
        assert_eq!(o["lin.mac.enforcing"], Observed::Value(json!("apparmor")));
        assert_eq!(o["lin.audit.auditd"], Observed::Value(json!("inactive")));
        assert_eq!(o["lin.services.legacy"], Observed::Value(json!("inactive")));
    }

    #[test]
    fn missing_sshd_and_commands() {
        let d = tempfile::tempdir().unwrap();
        let linux = parse(crate::embedded::feeds_file("policies/linux.yml").unwrap()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let o = rt.block_on(observe(&linux, &FakeRunner::new(), &env(d.path(), "linux")));
        assert!(matches!(o["lin.ssh.root_login"], Observed::NotApplicable(_)));
        assert!(matches!(o["lin.ssh.brute_force_guard"], Observed::NotApplicable(_)));
        assert!(
            matches!(o["lin.audit.auditd"], Observed::NotApplicable(_)),
            "沒有 systemctl"
        );
        assert_eq!(o["lin.sudo.nopasswd"], Observed::Missing);

        let mac = parse(crate::embedded::feeds_file("policies/macos.yml").unwrap()).unwrap();
        let runner = FakeRunner::new()
            .on(
                "spctl --status",
                CmdOutput {
                    code: Some(1),
                    stdout: "assessments disabled\n".into(),
                    stderr: String::new(),
                },
            )
            .on("fdesetup status", CmdOutput::success("FileVault is On.\n"))
            .on(
                "GuestEnabled",
                CmdOutput {
                    code: Some(1),
                    stdout: String::new(),
                    stderr: "does not exist".into(),
                },
            )
            .on(
                "sysadminctl",
                CmdOutput {
                    code: Some(0),
                    stdout: String::new(),
                    stderr: "2026-10-17 sysadminctl[1] screenLock delay is immediate\n".into(),
                },
            )
            .on(
                "systemsetup",
                CmdOutput::success("You need administrator access to run this tool... exiting!\n"),
            );
        let o = rt.block_on(observe(&mac, &runner, &env(d.path(), "macos")));
        assert_eq!(o["mac.gatekeeper"], Observed::Value(json!("disabled")));
        assert_eq!(o["mac.filevault"], Observed::Value(json!("On")));
        assert_eq!(o["mac.login.guest"], Observed::Missing);
        assert_eq!(o["mac.screen_lock"], Observed::Value(json!("delay is immediate")));
        assert_eq!(o["mac.remote_login"], Observed::NeedsAdmin);
        assert!(matches!(o["mac.sip"], Observed::NotApplicable(_)));
    }
}

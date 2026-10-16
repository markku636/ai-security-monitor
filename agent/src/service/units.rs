//! 服務設定檔內容（純函數）：systemd unit、launchd plist、XDG autostart、Windows 命令列。

use std::path::Path;

pub const LABEL: &str = "dev.asa.agent";
pub const SERVICE_NAME: &str = "asa";
pub const DISPLAY_NAME: &str = "ai-security-agent";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// systemd 的 ExecStart 參數：含空白或特殊字元的加雙引號。
fn systemd_quote(a: &str) -> String {
    if !a.is_empty() && a.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:@+,".contains(c)) {
        a.to_string()
    } else {
        format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Windows 命令列：exe 一律加引號，其餘含空白的加引號。
pub fn windows_cmdline(exe: &Path, args: &[String]) -> String {
    let mut s = format!("\"{}\"", exe.display());
    for a in args {
        s.push(' ');
        s.push_str(&crate::elevate::quote_win_arg(a));
    }
    s
}

pub fn systemd_unit(exe: &Path, args: &[String], system: bool, config_dir: &Path) -> String {
    let exec = std::iter::once(exe.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| systemd_quote(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let mut s = String::from(
        "[Unit]\nDescription=ai-security-agent (asa watch)\nDocumentation=https://github.com/markku636/ai-security-agent\n\
         Wants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=simple\n",
    );
    s.push_str(&format!("ExecStart={exec}\n"));
    s.push_str("Restart=on-failure\nRestartSec=30\n");
    if system {
        // 讀所有行程的 socket 與防火牆需要 root；檔案系統只開設定目錄可寫
        s.push_str(&format!(
            "Environment=ASA_SECRETS_BACKEND=file\nProtectSystem=full\nProtectHome=read-only\nPrivateTmp=true\nReadWritePaths={}\nNoNewPrivileges=false\n",
            systemd_quote(&config_dir.display().to_string())
        ));
    }
    s.push_str(&format!(
        "\n[Install]\nWantedBy={}\n",
        if system { "multi-user.target" } else { "default.target" }
    ));
    s
}

pub fn launchd_plist(exe: &Path, args: &[String], log_dir: &Path, system: bool) -> String {
    let mut prog = format!("    <string>{}</string>\n", xml_escape(&exe.display().to_string()));
    for a in args {
        prog.push_str(&format!("    <string>{}</string>\n", xml_escape(a)));
    }
    let env = if system {
        "  <key>EnvironmentVariables</key>\n  <dict>\n    <key>ASA_SECRETS_BACKEND</key>\n    <string>file</string>\n  </dict>\n"
    } else {
        ""
    };
    let out = xml_escape(&log_dir.join("launchd.out.log").display().to_string());
    let err = xml_escape(&log_dir.join("launchd.err.log").display().to_string());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>{LABEL}</string>\n  <key>ProgramArguments</key>\n  <array>\n{prog}  </array>\n\
{env}  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n\
  <key>ThrottleInterval</key>\n  <integer>30</integer>\n  <key>ProcessType</key>\n  <string>Background</string>\n\
  <key>StandardOutPath</key>\n  <string>{out}</string>\n  <key>StandardErrorPath</key>\n  <string>{err}</string>\n</dict>\n</plist>\n"
    )
}

pub fn xdg_desktop(exe: &Path, args: &[String]) -> String {
    let exec = std::iter::once(exe.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| systemd_quote(&a))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Desktop Entry]\nType=Application\nName=ai-security-agent\nComment=asa watch (background security monitoring)\nExec={exec}\n\
         Terminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn args() -> Vec<String> {
        [
            "--config-dir",
            "/var/lib/asa",
            "--secrets-backend",
            "file",
            "watch",
            "--service",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn systemd_system_unit() {
        let u = systemd_unit(
            &PathBuf::from("/usr/local/bin/asa"),
            &args(),
            true,
            &PathBuf::from("/var/lib/asa"),
        );
        assert!(u.contains(
            "ExecStart=/usr/local/bin/asa --config-dir /var/lib/asa --secrets-backend file watch --service\n"
        ));
        assert!(u.contains("WantedBy=multi-user.target"));
        assert!(u.contains("Environment=ASA_SECRETS_BACKEND=file"));
        assert!(u.contains("ReadWritePaths=/var/lib/asa"));
        let user = systemd_unit(
            &PathBuf::from("/home/me/my bin/asa"),
            &["watch".into()],
            false,
            &PathBuf::from("/x"),
        );
        assert!(user.contains("ExecStart=\"/home/me/my bin/asa\" watch\n"));
        assert!(user.contains("WantedBy=default.target"));
        assert!(!user.contains("ProtectSystem"));
    }

    #[test]
    fn launchd_and_xdg() {
        let p = launchd_plist(
            &PathBuf::from("/usr/local/bin/asa"),
            &args(),
            &PathBuf::from("/Library/Logs/asa"),
            true,
        );
        assert!(p.contains("<string>dev.asa.agent</string>"));
        assert!(p.contains("    <string>/usr/local/bin/asa</string>\n    <string>--config-dir</string>"));
        assert!(p.contains("<key>ASA_SECRETS_BACKEND</key>"));
        assert!(p.contains("<key>RunAtLoad</key>\n  <true/>"));
        let u = launchd_plist(
            &PathBuf::from("/Applications/A & B/asa"),
            &[],
            &PathBuf::from("/tmp"),
            false,
        );
        assert!(u.contains("A &amp; B"));
        assert!(!u.contains("EnvironmentVariables"));
        let d = xdg_desktop(&PathBuf::from("/opt/asa/asa"), &["watch".into(), "--service".into()]);
        assert!(d.contains("Exec=/opt/asa/asa watch --service\n"));
    }

    #[test]
    fn windows_command_line() {
        let c = windows_cmdline(
            &PathBuf::from(r"C:\Program Files\asa\asa.exe"),
            &[
                "--config-dir".into(),
                r"C:\ProgramData\ai-security-agent".into(),
                "service".into(),
                "run".into(),
            ],
        );
        assert_eq!(
            c,
            r#""C:\Program Files\asa\asa.exe" --config-dir C:\ProgramData\ai-security-agent service run"#
        );
    }
}

//! 桌面版入口：沒有參數就開視窗；`--tray`（登入時自動啟動）只放到系統匣、不跳視窗；
//! 其他命令列參數（例如 AI 掛的 `mcp --tools …`、背景服務的 `watch --service`）就當 ai-security-monitor CLI 執行。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // 這個執行檔是桌面版：內建的 agent（背景自動回報、AI 的 MCP server）不自我更新，交給桌面版的更新器
    asa_lib::update::auto::set_embedded_in_desktop();
    let first = std::env::args().nth(1);
    if first.as_deref() == Some(ai_security_monitor_desktop_lib::TRAY_ARG) {
        ai_security_monitor_desktop_lib::run(true);
        return;
    }
    if first.is_some_and(|a| !a.starts_with("-psn")) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let code = rt.block_on(asa_lib::cli::run());
        std::process::exit(code);
    }
    ai_security_monitor_desktop_lib::run(false);
}

//! 桌面版入口：沒有參數就開視窗；帶命令列參數（例如 AI 掛的 `mcp --tools …`）就當 asa CLI 執行。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if std::env::args().nth(1).is_some_and(|a| !a.starts_with("-psn")) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        let code = rt.block_on(asa_lib::cli::run());
        std::process::exit(code);
    }
    asa_desktop_lib::run();
}

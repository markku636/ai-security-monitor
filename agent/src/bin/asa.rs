//! `asa` 命令列入口：建 tokio runtime 後交給 `asa_lib::cli::run()`。
//! 刻意不設 `windows_subsystem`——CLI 要保留主控台；服務模式本來就沒有主控台。

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(asa_lib::cli::run());
    std::process::exit(code);
}

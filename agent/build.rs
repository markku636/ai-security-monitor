//! 建置腳本：重新內嵌 `../feeds`（情資登錄、策略、bugcheck 表）並把 git sha 餵進 `env!()`。

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../feeds");
    println!("cargo:rerun-if-changed=build.rs");
    // commit 變了就重新取 git sha（路徑不存在時 cargo 會每次重跑，所以只在存在時才監看）
    for p in ["../.git/HEAD", "../.git/refs/heads"] {
        if std::path::Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }

    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ASA_GIT_SHA={sha}");

    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=ASA_BUILD_UNIX={secs}");
}

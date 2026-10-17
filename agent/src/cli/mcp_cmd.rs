//! `ai-security-monitor mcp`：啟動 MCP 伺服器（stdio 或 --http）；`config` 印設定、`install`／`uninstall` 寫入或移除 AI 用戶端設定。

use std::net::SocketAddr;
use std::sync::Arc;

use super::args::{McpArgs, McpCmd};
use super::Env;
use crate::error::{AppError, AppResult};
use crate::mcp::{self, http, setup, McpServer, ServeOpts};

fn exe() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "ai-security-monitor".into())
}

fn server_args(allow_actions: bool) -> Vec<String> {
    let mut a = vec!["mcp".to_string()];
    if allow_actions {
        a.push("--allow-actions".into());
    }
    a
}

pub async fn run(env: &Env, a: McpArgs) -> AppResult<()> {
    match a.cmd {
        Some(McpCmd::Config { client, allow_actions }) => {
            print!("{}", setup::snippet(client, &exe(), &server_args(allow_actions)));
            Ok(())
        }
        Some(McpCmd::Install {
            client,
            project,
            allow_actions,
        }) => {
            let home = dirs::home_dir().ok_or_else(|| AppError::Config(t!("找不到使用者家目錄").into()))?;
            let path = setup::config_path(client, &home, project.as_deref())?;
            super::guard::ensure_confirmed(
                env.global.yes,
                false,
                false,
                &tf!(
                    "把 ai-security-monitor MCP 伺服器寫進 {client} 設定（{path}）",
                    client = client.label(),
                    path = path.display()
                ),
            )?;
            let p = setup::apply(
                client,
                &home,
                project.as_deref(),
                &exe(),
                &server_args(allow_actions),
                false,
            )?;
            println!(
                "{}",
                tf!(
                    "已寫入 {path}（原檔備份為 .bak）；重新啟動 {client} 後生效",
                    path = p.display(),
                    client = client.label()
                )
            );
            Ok(())
        }
        Some(McpCmd::Uninstall { client, project }) => {
            let home = dirs::home_dir().ok_or_else(|| AppError::Config(t!("找不到使用者家目錄").into()))?;
            let path = setup::config_path(client, &home, project.as_deref())?;
            super::guard::ensure_confirmed(
                env.global.yes,
                false,
                false,
                &tf!(
                    "從 {client} 設定移除 ai-security-monitor（{path}）",
                    client = client.label(),
                    path = path.display()
                ),
            )?;
            setup::apply(client, &home, project.as_deref(), "", &[], true)?;
            println!("{}", tf!("已從 {path} 移除 ai-security-monitor", path = path.display()));
            Ok(())
        }
        None => {
            let server = McpServer::new(
                env.config_dir.clone(),
                &ServeOpts {
                    tools: a.tools,
                    allow_actions: a.allow_actions,
                    allow_destructive: a.allow_destructive,
                },
            );
            match a.http {
                Some(addr) => {
                    let addr: SocketAddr = addr.parse().map_err(|_| {
                        AppError::InvalidArg(tf!("位址格式錯誤：{addr}（例 127.0.0.1:7870）", addr = addr))
                    })?;
                    http::serve(Arc::new(http::HttpState::new(server, a.token)), addr).await
                }
                None => mcp::serve_stdio(server).await,
            }
        }
    }
}

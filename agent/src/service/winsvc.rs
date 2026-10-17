//! Windows 服務（SCM）入口：`ai-security-monitor service run`。服務控制管理員啟動這個命令後，
//! 由 service_main 回報 Running、執行 `ai-security-monitor watch --service`，收到 Stop／Shutdown 時要求常駐迴圈結束。

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::units::SERVICE_NAME;
use crate::cli::args::{GlobalArgs, WatchArgs};
use crate::error::{AppError, AppResult};

struct Ctx {
    handle: tokio::runtime::Handle,
    global: GlobalArgs,
    config_dir: PathBuf,
    interval: Option<String>,
}

static CTX: OnceLock<Ctx> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub async fn run(global: GlobalArgs, config_dir: PathBuf, interval: Option<String>) -> AppResult<()> {
    let _ = CTX.set(Ctx {
        handle: tokio::runtime::Handle::current(),
        global,
        config_dir,
        interval,
    });
    tokio::task::spawn_blocking(|| service_dispatcher::start(SERVICE_NAME, ffi_service_main))
        .await
        .map_err(|e| AppError::Service(e.to_string()))?
        .map_err(|e| {
            AppError::Service(tf!(
                "無法連上服務控制管理員（這個命令只能由 Windows 服務啟動）：{e}",
                e = e
            ))
        })
}

fn service_main(_args: Vec<OsString>) {
    let Some(ctx) = CTX.get() else { return };
    let handler = |c: ServiceControl| match c {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            super::instance::request_stop();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let set = |state: ServiceState, accept: ServiceControlAccept| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        });
    };
    set(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    );
    let env = crate::cli::Env {
        global: ctx.global.clone(),
        config_dir: ctx.config_dir.clone(),
    };
    let args = WatchArgs {
        service: true,
        scm: true,
        interval: ctx.interval.clone(),
        ..Default::default()
    };
    if let Err(e) = ctx.handle.block_on(crate::cli::hub_cmd::watch(&env, args)) {
        super::instance::write_log(&format!("watch: {}", e.message()));
    }
    set(ServiceState::Stopped, ServiceControlAccept::empty());
}

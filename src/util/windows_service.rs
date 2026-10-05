//! Windows NT 系统服务运行时状态与控制工具
//!
//! # 职责边界
//! 本模块负责管理 Windows NT 服务的运行时全局标记、取消令牌注册、
//! 以及在自更新完成后协调 SCM 进行安全平滑重启，不承载上层业务逻辑。

#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
use log::info;
use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
use crate::util::daemon::configure_daemon_command;
#[cfg(windows)]
use std::process::Command;

/// 服务名称常量
pub const SERVICE_NAME: &str = "rddns";

/// 全局标记：指示当前进程是否正运行在 Windows NT 服务控制会话中
static IS_RUNNING_AS_SERVICE: AtomicBool = AtomicBool::new(false);

/// 全局服务取消令牌，供外部（如在线自更新）触发服务平滑停机
static SERVICE_CANCEL_TOKEN: RwLock<Option<CancellationToken>> = RwLock::new(None);

/// 查询当前是否处于 Windows 服务模式
pub fn is_running_as_service() -> bool {
    IS_RUNNING_AS_SERVICE.load(Ordering::Relaxed)
}

/// 标记当前是否处于 Windows 服务模式
pub fn set_running_as_service(val: bool) {
    IS_RUNNING_AS_SERVICE.store(val, Ordering::Relaxed);
}

/// 注册全局服务停机取消令牌
pub fn set_service_cancel_token(token: CancellationToken) {
    *SERVICE_CANCEL_TOKEN.write() = Some(token);
}

/// 触发当前服务平滑退场
pub fn trigger_service_shutdown() {
    if let Some(ref token) = *SERVICE_CANCEL_TOKEN.read() {
        info!("正在触发 Windows NT 服务全局优雅停机流程...");
        token.cancel();
    }
}

/// 构造 Windows NT 服务平滑重启后台脚本
///
/// 通过循环探测 SCM 服务状态是否变为 `STOPPED`，避免固定延时造成的竞态或启动失败。
#[cfg(any(windows, test))]
pub(crate) fn build_restart_command_script(service_name: &str) -> String {
    format!(
        "for /l %i in (1,1,30) do @(sc.exe query {svc} | findstr /i \"STOPPED\" >nul && (sc.exe start {svc} & exit /b 0) || ping 127.0.0.1 -n 2 >nul) & sc.exe start {svc}",
        svc = service_name
    )
}

/// 自更新完成后调度 Windows NT 服务平滑重启
///
/// # 设计原理
/// - **实现初衷**：Windows NT 服务受 SCM 纳管，不能直接以普通控制台子进程形式裸拉起。
/// - **核心优势**：派生独立后台轮询进程，通过 `sc.exe query` 循环探测服务状态，一旦旧版本完全停止（`STOPPED`）
///   立即调用 `sc.exe start` 唤醒新版本，避免固定延时造成的启动竞态或无谓等待；
///   同时主动触发当前服务停机，确保新旧版本交接零冲突、不产生孤儿进程并继续受 SCM 秒级崩溃拉活保护。
///
/// # Errors
/// 当外部后台延迟拉起命令派生失败时返回错误。
pub fn restart_windows_service_after_update() -> Result<()> {
    #[cfg(windows)]
    {
        info!("正在调度 Windows NT 服务自更新平滑重启任务...");
        let script = build_restart_command_script(SERVICE_NAME);
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c", &script]);
        configure_daemon_command(&mut cmd);
        cmd.spawn().context("派生 Windows 服务后台重启指令失败")?;

        trigger_service_shutdown();
        Ok(())
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_mode_flag() {
        set_running_as_service(false);
        assert!(!is_running_as_service());
        set_running_as_service(true);
        assert!(is_running_as_service());
        set_running_as_service(false);
    }

    #[test]
    fn test_build_restart_command_script() {
        let script = build_restart_command_script("rddns");
        assert!(script.contains("sc.exe query rddns"));
        assert!(script.contains("STOPPED"));
        assert!(script.contains("sc.exe start rddns"));
    }
}

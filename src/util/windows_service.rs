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
/// 先预留 2 秒缓冲等待旧服务完全停止，随后通过带退避重试的 `sc.exe start` 安全拉活新服务。
#[cfg(any(windows, test))]
pub(crate) fn build_restart_command_script(service_name: &str) -> String {
    format!(
        "ping 127.0.0.1 -n 2 >nul & for /l %i in (1,1,15) do @(sc.exe start {svc} >nul 2>&1 && exit /b 0 || ping 127.0.0.1 -n 2 >nul)",
        svc = service_name
    )
}

/// 自更新完成后调度 Windows NT 服务平滑重启
///
/// # 设计原理
/// - **实现初衷**：Windows NT 服务受 SCM 纳管，不能直接以普通控制台子进程形式裸拉起。
/// - **核心优势**：
///   - 注入 `CREATE_BREAKAWAY_FROM_JOB`，确保拉起子进程完全脱离当前 Windows 服务所属的 Job Object，避免父服务退出时被 SCM 连坐终止；
///   - 注入 `CREATE_NO_WINDOW | DETACHED_PROCESS` 静默运行，无黑窗口弹出；
///   - 通过带退避重试的 `sc.exe start` 循环拉起，并在触发停机前预留缓冲时间，确保 Web 响应与 SSE 日志完整发送至前端。
/// - **代价与局限**：依赖本地 SCM 控制命令 `sc.exe`。
///
/// # Errors
/// 当外部后台延迟拉起命令派生失败时返回错误。
pub fn restart_windows_service_after_update() -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x01000000;

        info!("正在调度 Windows NT 服务自更新平滑重启任务...");
        let script = build_restart_command_script(SERVICE_NAME);
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/c", &script]);
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB);
        cmd.spawn().context("派生 Windows 服务后台重启指令失败")?;

        // 异步派生延迟停机任务，为前端 SSE 与 Web 响应留出 1.2 秒的完整刷盘与网络传输窗口
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            trigger_service_shutdown();
        });
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
        assert!(script.contains("sc.exe start rddns"));
        assert!(script.contains("for /l %i in (1,1,15)"));
    }
}

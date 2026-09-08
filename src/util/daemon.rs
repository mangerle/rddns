use anyhow::{Context, Result};
use std::env;
use std::process::Command;

/// 后台子进程标识环境变量
pub const DAEMON_ENV_KEY: &str = "RDDNS_DAEMON";

/// 判断当前进程是否已处于守护进程子进程模式
///
/// # 设计原理
/// - **实现初衷**：通过检查特定的环境变量标志区分父进程（前台控制台启动者）与子进程（后台静默运行者），防止守护进程无限递归派生。
pub fn is_daemon_child() -> bool {
    env::var(DAEMON_ENV_KEY).unwrap_or_default() == "1"
}

/// 将当前程序作为后台独立守护进程派生并脱离控制台
///
/// # 设计原理
/// - **实现初衷**：为不需要 systemd 或 Windows Service 的简单服务器环境提供快捷脱离终端的能力。
/// - **核心优势**：自动过滤 `-d` 命令行标志，注入守护进程环境变量标识并打印 PID 引导。
///
/// # Errors
/// 当获取当前程序可执行文件路径失败或系统进程派生失败时返回错误。
pub fn run_as_daemon() -> Result<()> {
    let current_exe = env::current_exe().context("获取当前程序执行路径失败")?;
    let args: Vec<String> = env::args()
        .skip(1)
        .filter(|arg| arg != "-d" && arg != "--daemon")
        .collect();

    let mut cmd = Command::new(&current_exe);
    cmd.args(&args);
    cmd.env(DAEMON_ENV_KEY, "1");
    configure_daemon_command(&mut cmd);

    let child = cmd.spawn().context("派生后台守护进程失败")?;

    println!("==========================================");
    println!("RDDNS 已成功在后台静默运行！");
    println!("后台进程 PID: {}", child.id());
    println!("请访问 Web 管理界面查看运行状态与实时日志");
    println!("==========================================");

    Ok(())
}

/// 为 Command 配置静默后台守护运行属性 (跨平台兼容 Windows 无窗口脱离与 Unix 进程组脱离)
///
/// # 设计原理
/// - **实现初衷**：确保后台进程完全脱离当前终端窗口生命周期，防止关闭终端时被一同杀死。
/// - **核心优势**：跨平台条件编译（Windows 下设置 CREATE_NO_WINDOW 与 DETACHED_PROCESS 标志，Unix 下重定向到 /dev/null 并创建独立进程组）。
pub fn configure_daemon_command(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW (0x08000000) | DETACHED_PROCESS (0x00000008)
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_env_detection() {
        unsafe {
            env::remove_var(DAEMON_ENV_KEY);
        }
        assert!(!is_daemon_child());

        unsafe {
            env::set_var(DAEMON_ENV_KEY, "1");
        }
        assert!(is_daemon_child());
        unsafe {
            env::remove_var(DAEMON_ENV_KEY);
        }
    }
}

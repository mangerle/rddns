use anyhow::{Context, Result};
use std::env;
use std::process::Command;

/// 后台子进程标识环境变量
pub const DAEMON_ENV_KEY: &str = "RDDNS_DAEMON";

/// 判断当前进程是否已处于守护进程子进程模式
pub fn is_daemon_child() -> bool {
    env::var(DAEMON_ENV_KEY).unwrap_or_default() == "1"
}

/// 将当前程序作为后台独立守护进程派生并脱离控制台
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

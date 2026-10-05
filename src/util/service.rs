use anyhow::{Context, Result, bail};
use log::info;
#[cfg(windows)]
use log::warn;
use std::env;
use std::path::Path;
use std::process::Command;
#[cfg(windows)]
use std::thread::sleep;
#[cfg(windows)]
use std::time::Duration;

#[cfg(unix)]
use std::fs;

const SERVICE_NAME: &str = "rddns";
#[cfg(unix)]
const SERVICE_DESCRIPTION: &str = "基于 Rust 的高性能动态域名解析 (DDNS) 系统自启守护服务";

/// 处理系统服务管理命令 (install | uninstall | start | stop | restart | status)
///
/// # 设计原理
/// - **实现初衷**：为用户提供统一的跨平台 CLI 接口（`rddns service <action>`），一键注册为系统级常驻服务，无需手写复杂的服务脚本。
/// - **核心优势**：自动解析二进制与配置文件的绝对路径、Windows 下注册原生 NT 服务并配置 SCM 秒级崩溃/强杀故障自愈、Linux 下生成标准 systemd unit、macOS 下生成 launchd plist。
///
/// # Errors
/// 当路径解析失败、无管理员权限导致注册失败或传入不支持的操作动作时返回错误。
pub fn handle_service_command(action: &str, config_path: &Path) -> Result<()> {
    let current_exe = env::current_exe().context("获取当前程序可执行路径失败")?;
    let abs_exe = current_exe.canonicalize().unwrap_or(current_exe.clone());
    let abs_config = if config_path.is_relative() {
        match config_path.canonicalize() {
            Ok(p) => p,
            Err(_) => env::current_dir()
                .context("获取当前工作目录失败")?
                .join(config_path),
        }
    } else {
        config_path.to_path_buf()
    };

    let act = action.trim().to_lowercase();

    #[cfg(windows)]
    {
        handle_windows_service(&act, &abs_exe, &abs_config)?;
    }

    #[cfg(target_os = "linux")]
    {
        handle_linux_service(&act, &abs_exe, &abs_config)?;
    }

    #[cfg(target_os = "macos")]
    {
        handle_macos_service(&act, &abs_exe, &abs_config)?;
    }

    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        bail!("当前操作系统平台暂不支持自动注册系统服务，请手动配置系统守护进程");
    }

    Ok(())
}

#[cfg(windows)]
fn install_windows_service(exe_path: &Path, config_path: &Path) -> Result<()> {
    info!("正在配置 Windows NT 原生自愈服务 [{}]...", SERVICE_NAME);

    // 1. 迁移清理旧版本可能残留的计划任务与注册表自启项
    let _ = Command::new("schtasks.exe")
        .args(["/delete", "/tn", SERVICE_NAME, "/f"])
        .output();
    let _ = Command::new("reg.exe")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            SERVICE_NAME,
            "/f",
        ])
        .output();
    let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
    let _ = Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output();

    // 2. 构造 SCM 原生系统服务创建指令
    let exe_str = exe_path.to_string_lossy();
    let cfg_str = config_path.to_string_lossy();
    let bin_path_arg = format!("\"{}\" -c \"{}\" --windows-service", exe_str, cfg_str);

    let create_out = Command::new("sc.exe")
        .args([
            "create",
            SERVICE_NAME,
            &format!("binPath= {}", bin_path_arg),
            "start= auto",
            "DisplayName= RDDNS Dynamic DNS Service",
        ])
        .output()
        .context("调用 sc.exe 创建系统服务失败")?;

    if !create_out.status.success() {
        let out_msg = String::from_utf8_lossy(&create_out.stdout);
        let err_msg = String::from_utf8_lossy(&create_out.stderr);
        bail!(
            "创建 Windows 服务失败：\n{}\n{}\n提示：注册 Windows 系统服务需要管理员权限，请以管理员身份运行终端后重试。",
            out_msg.trim(),
            err_msg.trim()
        );
    }

    // 3. 配置服务中文描述
    let _ = Command::new("sc.exe")
        .args([
            "description",
            SERVICE_NAME,
            "基于 Rust 的高性能动态域名解析 (DDNS) 系统自启与故障自愈守护服务",
        ])
        .output();

    // 4. 配置 SCM 故障恢复策略：异常崩溃或任务管理器强杀后 3 秒自动拉活重启，永远重置失败计数
    let failure_out = Command::new("sc.exe")
        .args([
            "failure",
            SERVICE_NAME,
            "reset= 0",
            "actions= restart/3000/restart/3000/restart/3000",
        ])
        .output();
    if let Ok(ref f) = failure_out
        && !f.status.success()
    {
        warn!(
            "配置服务故障恢复策略告警: {}",
            String::from_utf8_lossy(&f.stdout).trim()
        );
    }
    let _ = Command::new("sc.exe")
        .args(["failureflag", SERVICE_NAME, "1"])
        .output();

    // 5. 立即启动服务
    info!("正在启动 [{}] Windows 系统服务...", SERVICE_NAME);
    let start_out = Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()
        .context("启动 Windows 服务失败")?;
    let start_msg = String::from_utf8_lossy(&start_out.stdout);

    info!("==========================================");
    info!("RDDNS 已成功安装为 Windows NT 原生系统服务！");
    info!("服务名称:   {}", SERVICE_NAME);
    info!("运行程序:   {}", exe_path.display());
    info!("配置文件:   {}", config_path.display());
    info!("自愈能力:   已启用 (异常崩溃或任务管理器强杀 3 秒自动拉起)");
    info!("启动输出:   {}", start_msg.trim());
    info!("Web 控制台: http://localhost:9876");
    info!("==========================================");
    Ok(())
}

#[cfg(windows)]
fn uninstall_windows_service() -> Result<()> {
    info!("正在停止并卸载 Windows 系统服务 [{}]...", SERVICE_NAME);
    let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
    let delete_out = Command::new("sc.exe")
        .args(["delete", SERVICE_NAME])
        .output()
        .context("调用 sc.exe 删除系统服务失败")?;

    // 清理历史残留计划任务与注册表
    let _ = Command::new("schtasks.exe")
        .args(["/delete", "/tn", SERVICE_NAME, "/f"])
        .output();
    let _ = Command::new("reg.exe")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            SERVICE_NAME,
            "/f",
        ])
        .output();
    let _ = Command::new("taskkill.exe")
        .args(["/f", "/im", "rddns.exe"])
        .output();

    if !delete_out.status.success() {
        let msg = String::from_utf8_lossy(&delete_out.stdout);
        warn!("删除服务输出: {}", msg.trim());
    } else {
        info!("[{}] Windows NT 系统服务已成功卸载！", SERVICE_NAME);
    }
    Ok(())
}

#[cfg(windows)]
fn start_windows_service() -> Result<()> {
    info!("正在启动 [{}] Windows 系统服务...", SERVICE_NAME);
    let out = Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()
        .context("调用 sc.exe 启动服务失败")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    info!("启动服务输出:\n{}", stdout.trim());
    Ok(())
}

#[cfg(windows)]
fn stop_windows_service() -> Result<()> {
    info!("正在停止 [{}] Windows 系统服务...", SERVICE_NAME);
    let out = Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .output()
        .context("调用 sc.exe 停止服务失败")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    info!("停止服务输出:\n{}", stdout.trim());
    Ok(())
}

#[cfg(windows)]
fn restart_windows_service() -> Result<()> {
    info!("正在重启 [{}] Windows 系统服务...", SERVICE_NAME);
    let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
    sleep(Duration::from_millis(1500));
    let out = Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .output()
        .context("调用 sc.exe 重启服务失败")?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    info!("重启服务输出:\n{}", stdout.trim());
    Ok(())
}

#[cfg(windows)]
fn status_windows_service() -> Result<()> {
    info!("正在查询 [{}] Windows 系统服务状态...", SERVICE_NAME);
    let out = Command::new("sc.exe")
        .args(["query", SERVICE_NAME])
        .output()
        .context("查询 Windows 服务状态失败")?;
    info!(
        "服务状态查询结果:\n{}",
        String::from_utf8_lossy(&out.stdout).trim()
    );
    Ok(())
}

#[cfg(windows)]
fn handle_windows_service(action: &str, exe_path: &Path, config_path: &Path) -> Result<()> {
    match action {
        "install" => install_windows_service(exe_path, config_path),
        "uninstall" => uninstall_windows_service(),
        "start" => start_windows_service(),
        "stop" => stop_windows_service(),
        "restart" => restart_windows_service(),
        "status" => status_windows_service(),
        _ => bail!(
            "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
            action
        ),
    }
}

#[cfg(target_os = "linux")]
fn handle_linux_service(action: &str, exe_path: &Path, config_path: &Path) -> Result<()> {
    let service_file_path = "/etc/systemd/system/rddns.service";

    match action {
        "install" => {
            info!("正在生成 systemd 服务配置文件 [{}]...", service_file_path);
            let service_content = format!(
                r#"[Unit]
Description={}
Documentation=https://github.com/mangerle/rddns
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="{}" -c "{}"
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#,
                SERVICE_DESCRIPTION,
                exe_path.display(),
                config_path.display()
            );

            fs::write(service_file_path, service_content).context("写入 systemd 服务文件失败")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(service_file_path, fs::Permissions::from_mode(0o644));
            }
            info!("正在重载 systemd 守护进程并启用自启服务...");
            Command::new("systemctl")
                .args(["daemon-reload"])
                .status()
                .context("重载 systemd 失败")?;
            Command::new("systemctl")
                .args(["enable", "--now", SERVICE_NAME])
                .status()
                .context("启用 systemd 服务失败")?;

            info!("==========================================");
            info!("RDDNS systemd 服务已成功安装并启动！");
            info!("服务文件: {}", service_file_path);
            info!("运行程序: {}", exe_path.display());
            info!("配置文件: {}", config_path.display());
            info!("可使用 systemctl status rddns 查看服务实时状态");
            info!("==========================================");
        }
        "uninstall" => {
            info!("正在停止并卸载 systemd 服务 [{}]...", SERVICE_NAME);
            let _ = Command::new("systemctl")
                .args(["disable", "--now", SERVICE_NAME])
                .status();
            if Path::new(service_file_path).exists() {
                fs::remove_file(service_file_path).context("删除 systemd 服务文件失败")?;
            }
            let _ = Command::new("systemctl").args(["daemon-reload"]).status();
            info!("[{}] systemd 服务已成功卸载！", SERVICE_NAME);
        }
        "start" => {
            Command::new("systemctl")
                .args(["start", SERVICE_NAME])
                .status()
                .context("启动 systemd 服务失败")?;
            info!("[{}] 服务已启动", SERVICE_NAME);
        }
        "stop" => {
            Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .status()
                .context("停止 systemd 服务失败")?;
            info!("[{}] 服务已停止", SERVICE_NAME);
        }
        "restart" => {
            Command::new("systemctl")
                .args(["restart", SERVICE_NAME])
                .status()
                .context("重启 systemd 服务失败")?;
            info!("[{}] 服务已重启", SERVICE_NAME);
        }
        "status" => {
            Command::new("systemctl")
                .args(["status", SERVICE_NAME])
                .status()
                .context("查询 systemd 状态失败")?;
        }
        _ => {
            bail!(
                "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
                action
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn handle_macos_service(action: &str, exe_path: &Path, config_path: &Path) -> Result<()> {
    let plist_path = "/Library/LaunchDaemons/com.mangerle.rddns.plist";

    match action {
        "install" => {
            info!("正在生成 launchd 配置文件 [{}]...", plist_path);
            let plist_content = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mangerle.rddns</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>-c</string>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/rddns.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/rddns.log</string>
</dict>
</plist>
"#,
                exe_path.display(),
                config_path.display()
            );

            fs::write(plist_path, plist_content).context("写入 launchd plist 失败")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(plist_path, fs::Permissions::from_mode(0o644));
            }
            Command::new("launchctl")
                .args(["load", "-w", plist_path])
                .status()
                .context("加载 launchd 服务失败")?;

            info!("==========================================");
            info!("RDDNS macOS launchd 服务已成功安装并启动！");
            info!("配置文件: {}", plist_path);
            info!("==========================================");
        }
        "uninstall" => {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", plist_path])
                .status();
            if Path::new(plist_path).exists() {
                fs::remove_file(plist_path).context("删除 launchd plist 文件失败")?;
            }
            info!("RDDNS macOS launchd 服务已成功卸载！");
        }
        "start" => {
            Command::new("launchctl")
                .args(["start", "com.mangerle.rddns"])
                .status()
                .context("启动 launchd 服务失败")?;
        }
        "stop" => {
            Command::new("launchctl")
                .args(["stop", "com.mangerle.rddns"])
                .status()
                .context("停止 launchd 服务失败")?;
        }
        "restart" => {
            let _ = Command::new("launchctl")
                .args(["stop", "com.mangerle.rddns"])
                .status();
            Command::new("launchctl")
                .args(["start", "com.mangerle.rddns"])
                .status()
                .context("重启 launchd 服务失败")?;
        }
        "status" => {
            Command::new("launchctl")
                .args(["list", "com.mangerle.rddns"])
                .status()
                .context("查询 launchd 状态失败")?;
        }
        _ => {
            bail!(
                "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
                action
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_service_action() {
        let dummy_path = Path::new("dummy.yaml");
        let res = handle_service_command("invalid_action_xyz", dummy_path);
        assert!(res.is_err());
    }
}

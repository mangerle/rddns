use std::env;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
use std::fs;

const SERVICE_NAME: &str = "rddns";
const SERVICE_DISPLAY_NAME: &str = "RDDNS Dynamic DNS Service";
const SERVICE_DESCRIPTION: &str = "基于 Rust 的高性能动态域名解析 (DDNS) 系统自启守护服务";

/// 处理系统服务管理命令 (install | uninstall | start | stop | restart | status)
pub fn handle_service_command(
    action: &str,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let abs_exe = current_exe.canonicalize().unwrap_or(current_exe.clone());
    let abs_config = if config_path.is_relative() {
        match config_path.canonicalize() {
            Ok(p) => p,
            Err(_) => env::current_dir()?.join(config_path),
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
        return Err(
            format!("当前操作系统平台暂不支持自动注册系统服务，请手动配置系统守护进程").into(),
        );
    }

    Ok(())
}

#[cfg(windows)]
fn handle_windows_service(
    action: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    match action {
        "install" => {
            println!(
                "🔧 正在向 Windows 服务控制管理器注册 [{}] 服务...",
                SERVICE_NAME
            );
            let bin_path = format!(
                "\"{}\" -c \"{}\"",
                exe_path.display(),
                config_path.display()
            );

            let output = Command::new("sc.exe")
                .args([
                    "create",
                    SERVICE_NAME,
                    &format!("binPath= {}", bin_path),
                    "start= auto",
                    &format!("DisplayName= {}", SERVICE_DISPLAY_NAME),
                ])
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if !output.status.success() && !stdout.contains("1073") {
                return Err(format!(
                    "创建 Windows 服务失败: {}\n提示: 请以管理员身份运行终端！",
                    stdout
                )
                .into());
            }

            // 设置服务描述
            let _ = Command::new("sc.exe")
                .args(["description", SERVICE_NAME, SERVICE_DESCRIPTION])
                .output();

            println!("🚀 正在启动 [{}] Windows 服务...", SERVICE_NAME);
            let start_out = Command::new("sc.exe")
                .args(["start", SERVICE_NAME])
                .output()?;
            let start_stdout = String::from_utf8_lossy(&start_out.stdout);
            println!("{}", start_stdout);

            println!("==========================================");
            println!("✅ RDDNS Windows 服务已成功安装并设置为开机自启！");
            println!("📌 服务名称: {}", SERVICE_NAME);
            println!("📌 运行程序: {}", exe_path.display());
            println!("📌 配置文件: {}", config_path.display());
            println!("==========================================");
        }
        "uninstall" => {
            println!("🛑 正在停止并卸载 Windows 服务 [{}]...", SERVICE_NAME);
            let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
            let del_out = Command::new("sc.exe")
                .args(["delete", SERVICE_NAME])
                .output()?;
            let stdout = String::from_utf8_lossy(&del_out.stdout);
            if del_out.status.success() {
                println!("✅ [{}] Windows 服务已成功卸载！", SERVICE_NAME);
            } else {
                return Err(
                    format!("卸载服务失败: {}\n提示: 请以管理员身份运行终端！", stdout).into(),
                );
            }
        }
        "start" => {
            let out = Command::new("sc.exe")
                .args(["start", SERVICE_NAME])
                .output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        "stop" => {
            let out = Command::new("sc.exe")
                .args(["stop", SERVICE_NAME])
                .output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        "restart" => {
            let _ = Command::new("sc.exe").args(["stop", SERVICE_NAME]).output();
            std::thread::sleep(std::time::Duration::from_millis(800));
            let out = Command::new("sc.exe")
                .args(["start", SERVICE_NAME])
                .output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));
            println!("✅ [{}] 服务已完成重启！", SERVICE_NAME);
        }
        "status" => {
            let out = Command::new("sc.exe")
                .args(["query", SERVICE_NAME])
                .output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }
        _ => {
            return Err(format!(
                "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
                action
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn handle_linux_service(
    action: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let service_file_path = "/etc/systemd/system/rddns.service";

    match action {
        "install" => {
            println!(
                "🔧 正在生成 systemd 服务配置文件 [{}]...",
                service_file_path
            );
            let service_content = format!(
                r#"[Unit]
Description={}
Documentation=https://github.com/mangerle/rddns
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={} -c {}
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

            fs::write(service_file_path, service_content)?;
            println!("🔄 正在重载 systemd 守护进程并启用自启服务...");
            Command::new("systemctl").args(["daemon-reload"]).status()?;
            Command::new("systemctl")
                .args(["enable", "--now", SERVICE_NAME])
                .status()?;

            println!("==========================================");
            println!("✅ RDDNS systemd 服务已成功安装并启动！");
            println!("📌 服务文件: {}", service_file_path);
            println!("📌 运行程序: {}", exe_path.display());
            println!("📌 配置文件: {}", config_path.display());
            println!("💡 可使用 systemctl status rddns 查看服务实时状态");
            println!("==========================================");
        }
        "uninstall" => {
            println!("🛑 正在停止并卸载 systemd 服务 [{}]...", SERVICE_NAME);
            let _ = Command::new("systemctl")
                .args(["disable", "--now", SERVICE_NAME])
                .status();
            if Path::new(service_file_path).exists() {
                fs::remove_file(service_file_path)?;
            }
            let _ = Command::new("systemctl").args(["daemon-reload"]).status();
            println!("✅ [{}] systemd 服务已成功卸载！", SERVICE_NAME);
        }
        "start" => {
            Command::new("systemctl")
                .args(["start", SERVICE_NAME])
                .status()?;
            println!("✅ [{}] 服务已启动", SERVICE_NAME);
        }
        "stop" => {
            Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .status()?;
            println!("🛑 [{}] 服务已停止", SERVICE_NAME);
        }
        "restart" => {
            Command::new("systemctl")
                .args(["restart", SERVICE_NAME])
                .status()?;
            println!("✅ [{}] 服务已重启", SERVICE_NAME);
        }
        "status" => {
            Command::new("systemctl")
                .args(["status", SERVICE_NAME])
                .status()?;
        }
        _ => {
            return Err(format!(
                "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
                action
            )
            .into());
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn handle_macos_service(
    action: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let plist_path = "/Library/LaunchDaemons/com.mangerle.rddns.plist";

    match action {
        "install" => {
            println!("🔧 正在生成 launchd 配置文件 [{}]...", plist_path);
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

            fs::write(plist_path, plist_content)?;
            Command::new("launchctl")
                .args(["load", "-w", plist_path])
                .status()?;

            println!("==========================================");
            println!("✅ RDDNS macOS launchd 服务已成功安装并启动！");
            println!("📌 配置文件: {}", plist_path);
            println!("==========================================");
        }
        "uninstall" => {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", plist_path])
                .status();
            if Path::new(plist_path).exists() {
                fs::remove_file(plist_path)?;
            }
            println!("✅ RDDNS macOS launchd 服务已成功卸载！");
        }
        "start" => {
            Command::new("launchctl")
                .args(["start", "com.mangerle.rddns"])
                .status()?;
        }
        "stop" => {
            Command::new("launchctl")
                .args(["stop", "com.mangerle.rddns"])
                .status()?;
        }
        "restart" => {
            let _ = Command::new("launchctl")
                .args(["stop", "com.mangerle.rddns"])
                .status();
            Command::new("launchctl")
                .args(["start", "com.mangerle.rddns"])
                .status()?;
        }
        "status" => {
            Command::new("launchctl")
                .args(["list", "com.mangerle.rddns"])
                .status()?;
        }
        _ => {
            return Err(format!(
                "未知的服务指令: {} (支持指令: install, uninstall, start, stop, restart, status)",
                action
            )
            .into());
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

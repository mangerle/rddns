use std::env;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
use std::fs;

const SERVICE_NAME: &str = "rddns";
#[allow(dead_code)]
const SERVICE_DISPLAY_NAME: &str = "RDDNS Dynamic DNS Service";
#[allow(dead_code)]
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
    let exe_str = exe_path.to_string_lossy();
    let cfg_str = config_path.to_string_lossy();
    let run_cmd = format!("\"{}\" -c \"{}\" -d", exe_str, cfg_str);

    match action {
        "install" => {
            println!("🔧 正在配置 Windows 开机自启服务 [{}]...", SERVICE_NAME);

            // 1. 添加当前用户开机自启注册表项 (Run)
            let _ = Command::new("reg.exe")
                .args([
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    SERVICE_NAME,
                    "/t",
                    "REG_SZ",
                    "/d",
                    &run_cmd,
                    "/f",
                ])
                .output();

            // 2. 尝试创建 Windows 高权限计划任务 (登录自启与防休眠恢复)
            let sch_out = Command::new("schtasks.exe")
                .args([
                    "/create",
                    "/tn",
                    SERVICE_NAME,
                    "/tr",
                    &run_cmd,
                    "/sc",
                    "onlogon",
                    "/rl",
                    "highest",
                    "/f",
                ])
                .output();

            if let Ok(out) = sch_out
                && !out.status.success()
            {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stderr.is_empty() {
                    println!(
                        "ℹ️ 提示: 计划任务注册跳过 ({})，已通过用户注册表 Run 键配置开机自启",
                        stderr.trim()
                    );
                }
            }

            // 3. 立即拉起后台守护进程
            println!("🚀 正在启动后台守护进程...");
            let mut spawn_cmd = Command::new(exe_path);
            spawn_cmd.args(["-c", &cfg_str, "-d"]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                spawn_cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let _ = spawn_cmd.spawn();

            println!("==========================================");
            println!("✅ RDDNS 已成功安装并设置为 Windows 开机自启！");
            println!("📌 服务名称: {}", SERVICE_NAME);
            println!("📌 运行程序: {}", exe_path.display());
            println!("📌 配置文件: {}", config_path.display());
            println!("📌 Web 控制台: http://localhost:9876");
            println!("==========================================");
        }
        "uninstall" => {
            println!("🛑 正在停止并卸载 Windows 自启服务 [{}]...", SERVICE_NAME);

            // 1. 清理计划任务
            let _ = Command::new("schtasks.exe")
                .args(["/delete", "/tn", SERVICE_NAME, "/f"])
                .output();

            // 2. 清理注册表 Run 项
            let _ = Command::new("reg.exe")
                .args([
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    SERVICE_NAME,
                    "/f",
                ])
                .output();

            // 3. 停止后台正在运行的进程
            let _ = Command::new("taskkill.exe")
                .args(["/f", "/im", "rddns.exe"])
                .output();

            println!(
                "✅ [{}] Windows 自启服务与运行实例已成功清除！",
                SERVICE_NAME
            );
        }
        "start" => {
            println!("🚀 正在启动 [{}] 后台守护进程...", SERVICE_NAME);
            let mut spawn_cmd = Command::new(exe_path);
            spawn_cmd.args(["-c", &cfg_str, "-d"]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                spawn_cmd.creation_flags(CREATE_NO_WINDOW);
            }
            spawn_cmd.spawn()?;
            println!("✅ [{}] 后台进程已成功启动！", SERVICE_NAME);
        }
        "stop" => {
            println!("🛑 正在停止 [{}] 后台守护进程...", SERVICE_NAME);
            let out = Command::new("taskkill.exe")
                .args(["/f", "/im", "rddns.exe"])
                .output()?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            println!("{}", stdout.trim());
        }
        "restart" => {
            let _ = Command::new("taskkill.exe")
                .args(["/f", "/im", "rddns.exe"])
                .output();
            std::thread::sleep(std::time::Duration::from_millis(800));
            let mut spawn_cmd = Command::new(exe_path);
            spawn_cmd.args(["-c", &cfg_str, "-d"]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                spawn_cmd.creation_flags(CREATE_NO_WINDOW);
            }
            spawn_cmd.spawn()?;
            println!("✅ [{}] 后台守护进程已完成重启！", SERVICE_NAME);
        }
        "status" => {
            println!("🔎 正在查询 [{}] 进程与自启状态...", SERVICE_NAME);
            let out = Command::new("tasklist.exe")
                .args(["/fi", "IMAGENAME eq rddns.exe"])
                .output()?;
            println!("{}", String::from_utf8_lossy(&out.stdout));

            let reg_out = Command::new("reg.exe")
                .args([
                    "query",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    SERVICE_NAME,
                ])
                .output();
            if let Ok(r) = reg_out {
                if r.status.success() {
                    println!("📌 开机自启注册表: 已启用");
                } else {
                    println!("📌 开机自启注册表: 未启用");
                }
            }
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

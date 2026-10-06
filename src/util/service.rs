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

#[cfg(any(windows, test))]
fn clean_windows_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

/// 将命令输出字节流解码为 UTF-8 字符串。
///
/// # 设计原理
/// Windows 控制台实用程序默认使用系统本地 OEM/ANSI 代码页（如 CP936/GBK）输出。
/// 优先尝试标准 UTF-8；若校验失败则利用 Windows 原生系统 API `MultiByteToWideChar`
/// 无依赖地转换为宽字符再转为 UTF-8，彻底消除控制台乱码。
#[cfg(any(windows, test))]
fn decode_output(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn MultiByteToWideChar(
                code_page: u32,
                flags: u32,
                multi_byte_str: *const u8,
                multi_byte_len: i32,
                wide_char_str: *mut u16,
                wide_char_len: i32,
            ) -> i32;
        }

        const MB_ERR_INVALID_CHARS: u32 = 0x0000_0008;

        // 非 UTF-8 输出在 Windows 下极大概率来自中文本地控制台（CP936/GBK）。
        // 优先使用 CP936 结合严格无效字符校验 (MB_ERR_INVALID_CHARS) 进行判定，
        // 杜绝英文 Windows 系统（如 CI Runner ACP=1252 单字节代码页）错误将多字节字符识别为西欧拉丁符号；
        // 若非合法 GBK，再依序回退尝试系统默认 ANSI (0)、控制台 OEM (1) 以及宽松 GBK。
        for &(cp, flags) in &[
            (936u32, MB_ERR_INVALID_CHARS),
            (0u32, 0u32),
            (1u32, 0u32),
            (936u32, 0u32),
        ] {
            let len = unsafe {
                MultiByteToWideChar(
                    cp,
                    flags,
                    bytes.as_ptr(),
                    bytes.len() as i32,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if len > 0 {
                let mut wide = vec![0u16; len as usize];
                let written = unsafe {
                    MultiByteToWideChar(
                        cp,
                        flags,
                        bytes.as_ptr(),
                        bytes.len() as i32,
                        wide.as_mut_ptr(),
                        len,
                    )
                };
                if written > 0 {
                    return String::from_utf16_lossy(&wide);
                }
            }
        }
    }
    String::from_utf8_lossy(bytes).to_string()
}

/// 构造用于注册 Windows 服务的 sc.exe create 命令。
///
/// # 设计原理
/// Windows 原生 `sc.exe` 命令行解析器遵循特殊的选项解析规则：
/// 1. 每个配置项的键与值在命令行参数数组中必须分别独立传递（例如 `"binPath="` 与路径值分开，`"start="` 与 `"auto"` 分开），
///    不可将键值拼接到单个参数中（如 `"binPath= ..."`），否则会导致内部参数解析错位并报错（如 `: 4 start=`）。
/// 2. 当可执行文件或配置文件路径包含空格时（如 `C:\Program Files\...`），
///    必须将整个启动命令行用双引号整体包裹，且可执行文件与参数内部各自使用双引号，
///    确保 SCM 在拉起服务时能精准界定带空格的可执行程序路径。
#[cfg(any(windows, test))]
pub(crate) fn build_sc_create_command(
    service_name: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Command {
    let exe_str = clean_windows_path(exe_path);
    let cfg_str = clean_windows_path(config_path);
    let bin_path_val = format!(r#""{}" -c "{}" --windows-service"#, exe_str, cfg_str);

    let mut cmd = Command::new("sc.exe");
    cmd.args([
        "create",
        service_name,
        "binPath=",
        &bin_path_val,
        "start=",
        "auto",
        "DisplayName=",
        "RDDNS Dynamic DNS Service",
    ]);
    cmd
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
    let mut create_cmd = build_sc_create_command(SERVICE_NAME, exe_path, config_path);
    let create_out = create_cmd
        .output()
        .context("调用 sc.exe 创建系统服务失败")?;

    if !create_out.status.success() {
        let out_msg = decode_output(&create_out.stdout);
        let err_msg = decode_output(&create_out.stderr);
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

    // 4. 配置 SCM 故障恢复策略：异常崩溃或任务管理器强杀后 2 秒自动拉活重启，稳定运行 60 秒后自动清零重置失败计数
    let failure_out = Command::new("sc.exe")
        .args([
            "failure",
            SERVICE_NAME,
            "reset=",
            "60",
            "actions=",
            "restart/2000/restart/2000/restart/2000",
        ])
        .output();
    if let Ok(ref f) = failure_out
        && !f.status.success()
    {
        warn!(
            "配置服务故障恢复策略告警: {}",
            decode_output(&f.stdout).trim()
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
    let start_msg = decode_output(&start_out.stdout);

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
        let msg = decode_output(&delete_out.stdout);
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
    let stdout = decode_output(&out.stdout);
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
    let stdout = decode_output(&out.stdout);
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
    let stdout = decode_output(&out.stdout);
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
    info!("服务状态查询结果:\n{}", decode_output(&out.stdout).trim());
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
            let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("/"));
            info!("正在生成 systemd 服务配置文件 [{}]...", service_file_path);
            let service_content = format!(
                r#"[Unit]
Description={}
Documentation=https://github.com/mangerle/rddns
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={}
ExecStart="{}" -c "{}"
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#,
                SERVICE_DESCRIPTION,
                exe_dir.display(),
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
            info!("工作目录: {}", exe_dir.display());
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
            let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("/"));
            info!("正在生成 launchd 配置文件 [{}]...", plist_path);
            let plist_content = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mangerle.rddns</string>
    <key>WorkingDirectory</key>
    <string>{}</string>
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
                exe_dir.display(),
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
            info!("工作目录: {}", exe_dir.display());
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

    #[test]
    fn test_clean_windows_path() {
        let unc_path = Path::new(r"\\?\C:\Program Files\rddns\rddns.exe");
        assert_eq!(
            clean_windows_path(unc_path),
            r"C:\Program Files\rddns\rddns.exe"
        );

        let normal_path = Path::new(r"C:\rddns\rddns.exe");
        assert_eq!(clean_windows_path(normal_path), r"C:\rddns\rddns.exe");
    }

    #[test]
    fn test_decode_output() {
        // 1. 空字节测试
        assert_eq!(decode_output(b""), "");

        // 2. 标准 UTF-8 中文测试
        let utf8_bytes = "RDDNS 服务运行正常".as_bytes();
        assert_eq!(decode_output(utf8_bytes), "RDDNS 服务运行正常");

        // 3. GBK 编码转换测试
        #[cfg(windows)]
        {
            unsafe extern "system" {
                fn WideCharToMultiByte(
                    code_page: u32,
                    flags: u32,
                    wide_char_str: *const u16,
                    wide_char_len: i32,
                    multi_byte_str: *mut u8,
                    multi_byte_len: i32,
                    default_char: *const u8,
                    used_default_char: *mut i32,
                ) -> i32;
            }
            let original = "拒绝访问。提示：注册 Windows 系统服务需要管理员权限。";
            let wide: Vec<u16> = original.encode_utf16().collect();
            let len = unsafe {
                WideCharToMultiByte(
                    936,
                    0,
                    wide.as_ptr(),
                    wide.len() as i32,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                )
            };
            assert!(len > 0);
            let mut gbk_bytes = vec![0u8; len as usize];
            unsafe {
                WideCharToMultiByte(
                    936,
                    0,
                    wide.as_ptr(),
                    wide.len() as i32,
                    gbk_bytes.as_mut_ptr(),
                    len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                );
            }
            assert_eq!(decode_output(&gbk_bytes), original);
        }
    }

    #[test]
    fn test_build_sc_create_command() {
        let exe = Path::new(r"C:\Program Files\rddns\rddns.exe");
        let cfg = Path::new(r"C:\Program Files\rddns\config.json");
        let cmd = build_sc_create_command("rddns", exe, cfg);
        let cmd_str = format!("{:?}", cmd);

        // 验证 sc.exe 指令结构与独立键值参数
        assert!(cmd_str.contains("\"sc.exe\""));
        assert!(cmd_str.contains("\"create\""));
        assert!(cmd_str.contains("\"rddns\""));
        assert!(cmd_str.contains("\"binPath=\""));
        assert!(cmd_str.contains("\"start=\""));
        assert!(cmd_str.contains("\"auto\""));
        assert!(cmd_str.contains("\"DisplayName=\""));
        assert!(cmd_str.contains(r#""C:\\Program Files\\rddns\\rddns.exe\" -c \"C:\\Program Files\\rddns\\config.json\" --windows-service"#));
    }
}

#[path = "service_unix.rs"]
mod service_unix;

#[cfg(any(windows, not(any(target_os = "linux", target_os = "macos"))))]
use anyhow::bail;
use anyhow::{Context, Result};
#[cfg(windows)]
use log::{info, warn};
#[cfg(any(target_os = "linux", target_os = "macos", test))]
use service_unix::*;
use std::env;
use std::path::Path;
#[cfg(any(windows, test))]
use std::process::Command;
#[cfg(windows)]
use std::thread::sleep;
#[cfg(windows)]
use std::time::Duration;

#[cfg(any(windows, target_os = "linux"))]
pub(crate) const SERVICE_NAME: &str = "rddns";

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
        if let Some(decoded) = try_decode_win32_codepages(bytes) {
            return decoded;
        }
    }
    String::from_utf8_lossy(bytes).to_string()
}

#[cfg(windows)]
fn try_decode_win32_codepages(bytes: &[u8]) -> Option<String> {
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

    // 优先使用 CP936 结合严格无效字符校验 (MB_ERR_INVALID_CHARS) 进行判定，
    // 杜绝英文 Windows 系统错误将多字节字符识别为西欧拉丁符号；
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
                return Some(String::from_utf16_lossy(&wide));
            }
        }
    }
    None
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
fn cleanup_legacy_windows_autostart() {
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
}

#[cfg(windows)]
fn configure_windows_service_recovery() {
    let _ = Command::new("sc.exe")
        .args([
            "description",
            SERVICE_NAME,
            "基于 Rust 的高性能动态域名解析 (DDNS) 系统自启与故障自愈守护服务",
        ])
        .output();

    // 配置 SCM 故障恢复策略：异常崩溃或任务管理器强杀后 2 秒自动拉活重启，稳定运行 60 秒后自动清零重置失败计数
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
}

#[cfg(windows)]
fn install_windows_service(exe_path: &Path, config_path: &Path) -> Result<()> {
    info!("正在配置 Windows NT 原生自愈服务 [{}]...", SERVICE_NAME);

    cleanup_legacy_windows_autostart();

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

    configure_windows_service_recovery();

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

#[cfg(test)]
#[path = "service_tests.rs"]
mod service_tests;

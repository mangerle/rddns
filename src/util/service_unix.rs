#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use log::info;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

#[cfg(target_os = "linux")]
use super::SERVICE_NAME;

#[cfg(target_os = "linux")]
const SERVICE_DESCRIPTION: &str = "基于 Rust 的高性能动态域名解析 (DDNS) 系统自启守护服务";

/// 转义路径，使其可安全嵌入 systemd unit 的 `ExecStart=` 行 (P1-10)
///
/// # 设计原理
/// - **实现初衷**: `ExecStart=` 的值支持双引号包裹，但 systemd 的引号解析
///   **不处理嵌入的换行符**。配置文件路径由用户通过 `-c` 参数完全控制，
///   若路径含换行，后续文本将被 systemd 当作新的 unit 指令解析——攻击者
///   可借此注入 `User=root`、`ExecStartPre=` 等任意指令实现提权。
/// - **核心优势**: 采用与 systemd 引号语义一致的反斜杠转义：显式剔除
///   控制字符（换行、回车、制表符等一律无法进入 unit 文件），并对
///   反斜杠与双引号做转义。
///
/// # 不变式保证
/// 返回值**必定**为单行且不含裸换行符，可安全嵌入 unit 指令值。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn escape_systemd_exec_arg(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            // 控制字符一律剔除（含换行/回车/制表符），杜绝指令注入
            c if c.is_control() => {}
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // 空格需保留在引号内，仅剔除可能导致 unit 结构异常的字符
            '$' => out.push_str("\\$"),
            '%' => out.push_str("\\%"),
            c => out.push(c),
        }
    }
    out
}

/// 转义字符串，使其可安全嵌入 XML 文本节点 (P1-10)
///
/// # 设计原理
/// - **实现初衷**: launchd plist 将程序路径与配置路径直接嵌入 XML 文本节点。
///   macOS 路径可合法包含 `&` 与 `<`（如 `/Applications/A&B/rddns`），直接
///   嵌入会产生格式错误的 plist，进而导致 launchd 拒绝加载；更严重的是
///   恶意构造的路径可注入额外 XML 节点改写服务定义。
/// - **核心优势**: 按 XML 规范对四类保留字符做实体转义。
///
/// # 不变式保证
/// 返回值**必定**为合法 XML 文本节点内容，不含裸 `&`、`<`、`>`。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn escape_xml_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn install_linux_service(
    service_file_path: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<()> {
    let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("/"));
    info!("正在生成 systemd 服务配置文件 [{}]...", service_file_path);

    let exe_dir_safe = escape_systemd_exec_arg(&exe_dir.display().to_string());
    let exe_safe = escape_systemd_exec_arg(&exe_path.display().to_string());
    let config_safe = escape_systemd_exec_arg(&config_path.display().to_string());

    let service_content = format!(
        "[Unit]\nDescription={}\nDocumentation=https://github.com/mangerle/rddns\nAfter=network.target network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory=\"{}\"\nExecStart=\"{}\" -c \"{}\"\nRestart=always\nRestartSec=5s\nLimitNOFILE=65535\n\n[Install]\nWantedBy=multi-user.target\n",
        SERVICE_DESCRIPTION, exe_dir_safe, exe_safe, config_safe
    );

    fs::write(service_file_path, service_content).context("写入 systemd 服务文件失败")?;
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
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn handle_linux_service(
    action: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<()> {
    let service_file_path = "/etc/systemd/system/rddns.service";

    match action {
        "install" => install_linux_service(service_file_path, exe_path, config_path)?,
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
fn install_macos_service(plist_path: &str, exe_path: &Path, config_path: &Path) -> Result<()> {
    let exe_dir = exe_path.parent().unwrap_or_else(|| Path::new("/"));
    info!("正在生成 launchd 配置文件 [{}]...", plist_path);

    let exe_dir_xml = escape_xml_text(&exe_dir.display().to_string());
    let exe_xml = escape_xml_text(&exe_path.display().to_string());
    let config_xml = escape_xml_text(&config_path.display().to_string());

    let plist_content = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>com.mangerle.rddns</string>\n    <key>WorkingDirectory</key>\n    <string>{}</string>\n    <key>ProgramArguments</key>\n    <array>\n        <string>{}</string>\n        <string>-c</string>\n        <string>{}</string>\n    </array>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n    <key>StandardErrorPath</key>\n    <string>/var/log/rddns.err</string>\n    <key>StandardOutPath</key>\n    <string>/var/log/rddns.log</string>\n</dict>\n</plist>\n",
        exe_dir_xml, exe_xml, config_xml
    );

    fs::write(plist_path, plist_content).context("写入 launchd plist 失败")?;
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
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn handle_macos_service(
    action: &str,
    exe_path: &Path,
    config_path: &Path,
) -> Result<()> {
    let plist_path = "/Library/LaunchDaemons/com.mangerle.rddns.plist";

    match action {
        "install" => install_macos_service(plist_path, exe_path, config_path)?,
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

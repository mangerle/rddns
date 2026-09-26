use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use shipup::{UpdateEvent, Updater};
use std::env;
use std::process::{Command, exit};
use std::time::Duration;
use tokio::spawn;
use tokio::task::spawn_blocking;
use tokio::time::sleep;

use crate::util::daemon::configure_daemon_command;

/// 版本检查结果信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// 当前正在运行的程序版本
    pub current_version: String,
    /// 远端发布的最新版本 Tag
    pub latest_version: String,
    /// 是否存在可用新版本更新
    pub has_update: bool,
    /// 远端 Release 页面 Web 链接
    pub release_url: String,
    /// 远端发布说明日志 Markdown
    pub release_notes: String,
}

/// 构造全局统一配置的 shipup 更新器实例
///
/// # 设计原理
/// - **实现初衷**：收敛自更新配置（发布源、超时时间、平台架构与签名校验策略），避免在检测与升级两处重复构造。
/// - **核心优势**：基于 GitHubProvider 直接获取静态清单，并结合编译期 TARGET 变量实现精确架构路由。
/// - **代价与局限**：当前未配置 Ed25519 强制私钥签名，通过 HTTPS 与 SHA-256 校验包体完整性。
fn build_updater(timeout: Duration) -> Result<Updater> {
    let current_version = env!("CARGO_PKG_VERSION");
    let target = env!("TARGET");

    let mut builder = Updater::builder()
        .current_version(current_version)
        .context("当前程序版本号格式不符合 SemVer 规范")?
        .github_releases("mangerle", "rddns")
        .require_signature(false)
        .timeout(timeout);

    if !target.is_empty() {
        builder = builder.target(target);
    }

    builder.build().context("构建自更新器实例失败")
}

/// 检查 GitHub Releases 最新版本信息
///
/// # 设计原理
/// - **实现初衷**：通过 shipup 统一接口检查远端发布清单，获取最新版本号、发布日志与升级状态。
/// - **核心优势**：直接拉取 Release 静态清单，免受 GitHub API Rate Limit 限流影响；异步非阻塞探测。
///
/// # Errors
/// 当网络通信中断或清单解析异常时返回错误。
pub async fn check_version() -> Result<VersionInfo> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let updater = build_updater(Duration::from_secs(15))?;

    match updater.check_async().await? {
        Some(update) => {
            let latest_version = format!("v{}", update.version());
            let release_url = format!(
                "https://github.com/mangerle/rddns/releases/tag/{}",
                latest_version
            );
            Ok(VersionInfo {
                current_version,
                latest_version,
                has_update: true,
                release_url,
                release_notes: update.notes().unwrap_or("").to_string(),
            })
        }
        None => {
            let latest_version = format!("v{}", current_version);
            let release_url = format!(
                "https://github.com/mangerle/rddns/releases/tag/{}",
                latest_version
            );
            Ok(VersionInfo {
                current_version,
                latest_version,
                has_update: false,
                release_url,
                release_notes: String::new(),
            })
        }
    }
}

/// 执行原地一键热升级（下载最新发布包 -> SHA256校验 -> 解压 -> 安全备份与原子替换）
///
/// # 设计原理
/// - **实现初衷**：在无包管理器或容器编排的环境下，为各系统平台提供安全的自升级能力。
/// - **核心优势**：
///   - 委托 shipup 处理断点续传、SHA-256 完整性校验、防 Zip Slip 解压沙箱与同卷原子替换；
///   - 异步下载、阻塞安装隔离，不阻塞 Tokio 工作线程。
///
/// # Errors
/// 当网络中断、校验失败或无文件写入权限时返回错误。
pub async fn upgrade_self() -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    info!(
        "正在检查最新发布版本并准备原地自更新 (当前版本: v{})...",
        current_version
    );

    let updater = build_updater(Duration::from_secs(60))?;
    let update = updater
        .check_async()
        .await?
        .ok_or_else(|| anyhow::anyhow!("当前已是最新版本 (v{})，无需更新", current_version))?;

    info!(
        "检测到新版本 v{}，正在下载并校验安装包...",
        update.version()
    );
    let downloaded = update
        .download_async(|event| match event {
            UpdateEvent::DownloadProgress {
                percent: Some(p),
                speed_bytes_per_sec,
                ..
            } => {
                let speed_kb = speed_bytes_per_sec.unwrap_or(0) / 1024;
                info!("更新包下载进度: {:.1}% (当前速度: {} KB/s)", p, speed_kb);
            }
            UpdateEvent::VerifyingChecksum => {
                info!("正在校验更新包 SHA-256 完整性哈希...");
            }
            UpdateEvent::VerifyingSignature => {
                info!("正在校验更新包数字签名...");
            }
            _ => {}
        })
        .await
        .context("下载或校验更新包失败")?;

    info!("更新包校验通过，正在执行程序安全替换...");
    spawn_blocking(move || {
        downloaded.install(|event| {
            if let UpdateEvent::Installing = event {
                info!("正在解压并执行程序二进制替换...");
            }
        })
    })
    .await
    .context("调度安装任务异常")?
    .context("执行程序替换失败")?;

    info!(
        "RDDNS 成功更新至最新版本 v{}！请重启程序或服务以使更新完全生效。",
        update.version()
    );
    Ok(())
}

/// 重启当前程序进程以加载新升级的二进制文件
///
/// # 设计原理
/// - **实现初衷**：在热替换二进制文件后平滑拉起新版本进程，自动继承原有启动参数。
/// - **核心优势**：跨平台兼容（Windows 采用 PowerShell 规避 cmd 转义注入，Unix 采用 sh exec 释放旧端口），并保留 300ms 退出缓冲以确保 Web 响应成功返回。
///
/// # Errors
/// 当当前程序路径获取失败或派生辅助进程异常时返回错误。
pub fn restart_process() -> Result<()> {
    let current_exe = env::current_exe().context("获取当前程序路径失败")?;
    let args: Vec<String> = env::args().skip(1).collect();

    info!("正在重启程序以使更新生效: {}", current_exe.display());

    #[cfg(target_os = "windows")]
    {
        let mut launcher = Command::new("powershell");
        let ps_script = format!(
            "Start-Sleep -Milliseconds 1000; Start-Process -FilePath '{}' -ArgumentList @({})",
            current_exe.to_string_lossy().replace('\'', "''"),
            args.iter()
                .map(|a| format!("'{}'", a.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",")
        );

        launcher.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps_script,
        ]);
        configure_daemon_command(&mut launcher);
        launcher.spawn().context("派生重启辅助进程失败")?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut launcher = Command::new("sh");
        let mut sh_cmd = format!("sleep 1 && exec \"{}\"", current_exe.to_string_lossy());
        for arg in &args {
            sh_cmd.push_str(&format!(" '{}'", arg.replace('\'', "'\\''")));
        }
        launcher.args(["-c", &sh_cmd]);
        configure_daemon_command(&mut launcher);
        launcher.spawn().context("派生重启辅助进程失败")?;
    }

    spawn(async {
        sleep(Duration::from_millis(300)).await;
        exit(0);
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_updater() {
        let updater = build_updater(Duration::from_secs(10));
        assert!(updater.is_ok());
    }
}

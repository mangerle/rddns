use anyhow::{Context, Result};
use log::info;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use shipup::{DownloadedUpdate, RestartOptions, Update, UpdateEvent, Updater, schedule_restart};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::task::spawn_blocking;

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

/// 官方发布的 Ed25519 签名验证公钥（Base64 编码，32 字节）
const OFFICIAL_UPDATE_PUBLIC_KEY: &str = "I2/rMK9CRnRY3qr3IBfYhelfNaqvDIBX/FfVYQQ8C80=";

/// 构造全局统一配置的 shipup 更新器实例
///
/// # 设计原理
/// - **实现初衷**：收敛自更新配置（发布源、超时时间、平台架构与签名校验策略），避免在检测与升级两处重复构造。
/// - **核心优势**：基于 GitHubProvider 直接获取静态清单，并结合编译期 TARGET 变量实现精确架构路由。
/// - **代价与局限**：强制要求远端发布包携带官方 Ed25519 签名，若签名缺失或公钥不匹配将拒绝升级。
fn build_updater(timeout: Duration) -> Result<Updater> {
    let current_version = env!("CARGO_PKG_VERSION");
    let target = env!("TARGET");

    let mut builder = Updater::builder()
        .current_version(current_version)
        .context("当前程序版本号格式不符合 SemVer 规范")?
        .github_releases("mangerle", "rddns")
        .public_key(OFFICIAL_UPDATE_PUBLIC_KEY)
        .require_signature(true)
        .timeout(timeout);

    if !target.is_empty() {
        builder = builder.target(target);
    }

    builder.build().context("构建自更新器实例失败")
}

/// 远端版本检查缓存生存时间（5 分钟）
///
/// # 设计原理
/// - **实现初衷**: 避免前端高频请求版本接口触发 GitHub 频控限制或引入请求等待延迟。
/// - **核心优势**: 内存级命中返回，毫秒级响应，并在远端网络抖动时提供已缓存结果降级。
const VERSION_CACHE_TTL: Duration = Duration::from_secs(300);

static VERSION_CACHE: LazyLock<RwLock<Option<(Instant, VersionInfo)>>> =
    LazyLock::new(|| RwLock::new(None));

/// 检查 GitHub Releases 最新版本信息 (支持 5 分钟内存缓存与优雅降级)
///
/// # 设计原理
/// - **实现初衷**：通过 shipup 统一接口检查远端发布清单，获取最新版本号、发布日志与升级状态。
/// - **核心优势**：直接拉取 Release 静态清单，配合本地 5 分钟缓存杜绝频繁出站请求；异步非阻塞探测。
///
/// # Errors
/// 当网络通信中断或清单解析异常且无旧缓存可用时返回错误。
pub async fn check_version() -> Result<VersionInfo> {
    // 1. 尝试从缓存中命中有效结果
    {
        let cache = VERSION_CACHE.read();
        if let Some((cached_at, ref info)) = *cache
            && cached_at.elapsed() < VERSION_CACHE_TTL
        {
            return Ok(info.clone());
        }
    }

    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let updater = build_updater(Duration::from_secs(15))?;

    let check_res = updater.check_async().await;
    match check_res {
        Ok(Some(update)) => {
            let latest_version = format!("v{}", update.version());
            let release_url = format!(
                "https://github.com/mangerle/rddns/releases/tag/{}",
                latest_version
            );
            let info = VersionInfo {
                current_version,
                latest_version,
                has_update: true,
                release_url,
                release_notes: update.notes().unwrap_or("").to_string(),
            };
            *VERSION_CACHE.write() = Some((Instant::now(), info.clone()));
            Ok(info)
        }
        Ok(None) => {
            let latest_version = format!("v{}", current_version);
            let release_url = format!(
                "https://github.com/mangerle/rddns/releases/tag/{}",
                latest_version
            );
            let info = VersionInfo {
                current_version,
                latest_version,
                has_update: false,
                release_url,
                release_notes: String::new(),
            };
            *VERSION_CACHE.write() = Some((Instant::now(), info.clone()));
            Ok(info)
        }
        Err(e) => {
            // 网络异常时，若缓存中存在旧数据，降级返回旧数据
            let cache = VERSION_CACHE.read();
            if let Some((_, ref info)) = *cache {
                log::debug!("获取 GitHub 版本失败，降级使用旧缓存: {:#}", e);
                return Ok(info.clone());
            }
            Err(e).context("检查远端版本信息失败")
        }
    }
}

/// 执行原地一键热升级（下载最新发布包 -> SHA256校验 -> 解压 -> 安全备份与原子替换）
///
/// # 设计原理
/// - **实现初衷**：在无包管理器或容器编排的环境下，为各系统平台提供安全的自升级能力。
/// - **核心优势**：
///   - 委托 shipup 0.5.0 处理断点续传、SHA-256 完整性校验、防 Zip Slip 解压沙箱与同卷原子替换；
///   - shipup 0.5.0 已实现全链路异步任务堆化，彻底规避 Windows 平台单线程运行时栈溢出（0xc00000fd）；
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

    let target_version = update.version().clone();
    info!("检测到新版本 v{}，正在下载并校验安装包...", target_version);

    let downloaded = download_package(&update).await?;
    install_package(downloaded).await?;

    info!(
        "RDDNS 成功更新至最新版本 v{}！请重启程序或服务以使更新完全生效。",
        target_version
    );
    Ok(())
}

/// 异步下载更新包并执行 SHA-256 与数字签名校验
async fn download_package(update: &Update) -> Result<DownloadedUpdate> {
    update
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
        .context("下载或校验更新包失败")
}

/// 在阻塞工作线程池中执行解压与程序二进制安全替换
async fn install_package(downloaded: DownloadedUpdate) -> Result<()> {
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
    .context("执行程序替换失败")
}

/// 重启当前程序进程以加载新升级的二进制文件
///
/// # 设计原理
/// - **实现初衷**：在热替换二进制文件后平滑拉起新版本进程，避免网络端口冲突与 Web 响应截断。
/// - **核心优势**：
///   - 若处于 Windows NT 服务模式，优先委托 SCM 服务调度器协调重启，确保新进程依然受系统自愈拉活保护；
///   - 普通运行模式下委托 shipup 内置跨平台平滑交接引擎，Windows 下采用轻量 cmd/ping 守护，Unix 下采用 sh 守护；
///   - 自动预留启动缓冲释放 9876 端口与系统锁，保障 Web 响应完整发送。
///
/// # Errors
/// 当外部延迟拉起命令无法派生时返回错误。
pub fn restart_process() -> Result<()> {
    #[cfg(windows)]
    if crate::util::windows_service::is_running_as_service() {
        return crate::util::windows_service::restart_windows_service_after_update();
    }

    info!("正在调度平滑重启服务以使更新生效...");
    schedule_restart(&RestartOptions::new()).context("调度自更新平滑重启服务失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_updater() {
        let updater = build_updater(Duration::from_secs(10));
        assert!(updater.is_ok());
    }

    #[test]
    fn test_official_public_key_format() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        let decoded = BASE64
            .decode(OFFICIAL_UPDATE_PUBLIC_KEY)
            .expect("官方更新公钥必须是合法的 Base64 编码");
        assert_eq!(
            decoded.len(),
            32,
            "Ed25519 签名验证公钥长度必须严格为 32 字节"
        );
    }

    #[test]
    fn test_signature_verification_flow() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use shipup::signature::verify_ed25519;

        let dummy_sig = BASE64.encode([0u8; 64]);
        let dummy_digest = [1u8; 32];
        let verify_result = verify_ed25519(&dummy_digest, &dummy_sig, OFFICIAL_UPDATE_PUBLIC_KEY);
        assert!(verify_result.is_err(), "伪造签名必须被拒绝");
    }

    #[tokio::test]
    async fn test_version_cache_flow() {
        let cached_info = VersionInfo {
            current_version: "v9.9.9".to_string(),
            latest_version: "v9.9.9".to_string(),
            has_update: false,
            release_url: "https://example.com".to_string(),
            release_notes: "测试备注".to_string(),
        };
        *VERSION_CACHE.write() = Some((Instant::now(), cached_info.clone()));

        let result = check_version().await;
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.current_version, "v9.9.9");
        assert_eq!(info.release_notes, "测试备注");

        *VERSION_CACHE.write() = None;
    }
}

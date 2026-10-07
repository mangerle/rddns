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

/// 远端版本结果缓存生存时间（24 小时）
///
/// # 设计原理
/// - **实现初衷**：远端检查已收敛为「进程启动预检一次 + 用户手动点击触发」两种时机，
///   故缓存有效期需覆盖整个常驻周期，避免长跑进程在无人操作时反复出站 GitHub。
/// - **核心优势**：24 小时窗口内所有版本查询零网络开销，显著降低 GitHub 频控命中率。
/// - **代价与局限**：常驻超过 24 小时且用户从未手动点击时，需重启或手动点击才会感知新版本。
const VERSION_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// 全局版本缓存：(写入时刻, 版本信息)
///
/// # 设计原理
/// - **实现初衷**：远端检查的出网时机已收敛为「启动预检 + 用户主动点击」两条明确路径，
///   不存在无人值守的高频轮询，因此无需记录「近期失败」状态。
/// - **核心优势**：退化为最简单的成功结果缓存，语义单一；
///   网络失败一律上抛交由调用方降级，不会被伪装成成功结果掩盖故障。
type VersionCache = Option<(Instant, VersionInfo)>;

static VERSION_CACHE: LazyLock<RwLock<VersionCache>> = LazyLock::new(|| RwLock::new(None));

/// 构造仅含本地版本号的基础信息（零网络开销）
///
/// # 设计原理
/// - **实现初衷**：顶栏版本徽标只需展示本地版本，不应为此触发任何出站请求。
/// - **核心优势**：纯内存计算，恒定成功，不依赖缓存与网络。
/// - **字段约定**：`current_version` 为纯 SemVer（不带 `v` 前缀），与 `CARGO_PKG_VERSION`
///   字面值一致；`latest_version` 额外带 `v` 前缀以对齐 GitHub tag 形态。
pub fn local_version_info() -> VersionInfo {
    let current_version = env!("CARGO_PKG_VERSION");
    VersionInfo {
        current_version: current_version.to_string(),
        latest_version: format!("v{current_version}"),
        release_url: format!("https://github.com/mangerle/rddns/releases/tag/v{current_version}"),
        has_update: false,
        release_notes: String::new(),
    }
}

/// 从给定缓存中提取仍在有效期内的版本信息
///
/// # 设计原理
/// - **实现初衷**：将「TTL 判定」这一纯逻辑与全局静态状态解耦，使单元测试可直接传入
///   构造的缓存值验证各分支，无需触碰进程级共享状态、也不会与其他用例并发冲突。
/// - **核心优势**：无副作用、无锁、无全局依赖，是可独立验证的最小决策单元。
fn pick_valid_cached(cache: &VersionCache) -> Option<VersionInfo> {
    match cache {
        Some((at, info)) if at.elapsed() < VERSION_CACHE_TTL => Some(info.clone()),
        _ => None,
    }
}

/// 读取全局缓存中仍有效的版本信息
fn read_valid_cache() -> Option<VersionInfo> {
    pick_valid_cached(&VERSION_CACHE.read())
}

/// 查询版本信息：优先复用缓存，绝不主动出网
///
/// # 设计原理
/// - **实现初衷**：承接前端页面加载时的版本展示需求，使其与「远端检查」彻底解耦。
/// - **核心优势**：恒定成功返回，打开页面、登录、初始化均不产生任何 GitHub 请求与日志噪音。
pub fn query_version_cached() -> VersionInfo {
    read_valid_cache().unwrap_or_else(local_version_info)
}

/// 强制走远端检查并刷新缓存
///
/// # 设计原理
/// - **实现初衷**：仅供「进程启动预检」与「用户手动点击检查」两条明确时机调用，
///   二者均代表用户或运维方对「获取最新版本」的明确诉求，故不设任何静默退避。
/// - **核心优势**：远端失败时优先复用仍有效的成功缓存，避免一次网络抖动抹掉
///   已探明的版本信息；无缓存可用时如实上抛错误，由调用方决定降级策略。
///
/// # Errors
/// 当远端不可达或清单解析异常，且本地不存在任何有效成功缓存时返回错误。
pub async fn check_remote_version() -> Result<VersionInfo> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let updater = build_updater(Duration::from_secs(15))?;

    let info = match updater.check_async().await {
        Ok(Some(update)) => VersionInfo {
            release_url: format!(
                "https://github.com/mangerle/rddns/releases/tag/v{}",
                update.version()
            ),
            release_notes: update.notes().unwrap_or("").to_string(),
            latest_version: format!("v{}", update.version()),
            has_update: true,
            current_version,
        },
        Ok(None) => local_version_info(),
        Err(e) => {
            // 仍有有效成功缓存时保留之，避免一次网络抖动抹掉已探明的版本信息；
            // 无缓存则如实上抛，严禁将失败伪装为成功返回。
            return match read_valid_cache() {
                Some(info) => {
                    log::debug!("远端版本检查失败，降级复用本地缓存结果: {:#}", e);
                    Ok(info)
                }
                None => Err(e).context("检查远端版本信息失败"),
            };
        }
    };

    *VERSION_CACHE.write() = Some((Instant::now(), info.clone()));
    Ok(info)
}

/// 进程启动后的远端版本预检（供后台任务调用，失败仅降级不打断启动）
///
/// # 设计原理
/// - **实现初衷**：让用户在打开控制台时即可从顶栏徽标看到新版本提示，
///   而无需前端在每次页面加载时主动出站。
/// - **核心优势**：结果写入 24 小时缓存，后续所有页面加载均为零网络开销。
pub async fn run_startup_version_check() {
    match check_remote_version().await {
        Ok(info) if info.has_update => {
            info!(
                "启动预检发现新版本 {}，可在控制台顶栏版本徽标处查看更新并升级",
                info.latest_version
            );
        }
        Ok(_) => {
            log::debug!("启动版本预检完成，当前已是最新版本");
        }
        Err(e) => {
            log::warn!("启动版本预检失败，已降级为仅展示本地版本: {:#}", e);
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

    #[test]
    fn test_version_cache_ttl_covers_whole_always_on_cycle() {
        // 远端检查仅在启动与用户手动点击时触发，缓存必须覆盖整个常驻周期，
        // 否则长跑进程仍会因 TTL 过期而出站 GitHub。
        assert_eq!(VERSION_CACHE_TTL, Duration::from_secs(24 * 60 * 60));
    }

    #[test]
    fn test_local_version_info_never_claims_update() {
        let info = local_version_info();
        assert!(!info.has_update, "本地版本信息不得声称存在新版本");
        assert!(info.release_notes.is_empty());
        // 无新版本时，两个字段按契约形态不同（current 无 v / latest 带 v）但语义同源
        assert_eq!(
            info.latest_version,
            format!("v{}", info.current_version),
            "无新版本时 latest_version 应为 current_version 的 tag 形态"
        );
    }

    /// 锁定版本号字段的 `v` 前缀契约，防止同一字段在不同分支返回两种格式
    ///
    /// # 设计原理
    /// - `current_version` 是编译期 SemVer，必须与 `CARGO_PKG_VERSION` 字面值逐字相同；
    /// - `latest_version` 是 GitHub tag 形态，额外带 `v` 前缀以对齐 tag 命名。
    ///
    /// 两者语义不同故形态不同，API 契约必须自洽，不能出现同字段多格式。
    #[test]
    fn test_version_fields_v_prefix_contract() {
        let info = local_version_info();
        assert_eq!(
            info.current_version,
            env!("CARGO_PKG_VERSION"),
            "current_version 必须是纯 SemVer，不得携带 v 前缀"
        );
        assert!(
            info.current_version
                .starts_with(|c: char| c.is_ascii_digit()),
            "current_version 必须以数字起始，当前为: {}",
            info.current_version
        );
        assert_eq!(
            info.latest_version,
            format!("v{}", env!("CARGO_PKG_VERSION")),
            "latest_version 必须对齐 GitHub tag 形态（带 v 前缀）"
        );
        assert!(
            info.release_url.ends_with(&info.latest_version),
            "release_url 必须以 latest_version 结尾，当前 url: {}，tag: {}",
            info.release_url,
            info.latest_version
        );
    }

    // 以下用例均通过 `pick_valid_cached` 纯函数注入缓存值，
    // 不读写全局 VERSION_CACHE，因此天然免疫 cargo test 多线程并发竞争。

    #[test]
    fn test_pick_valid_cached_returns_none_when_cache_empty() {
        let cache: VersionCache = None;
        assert!(pick_valid_cached(&cache).is_none());
    }

    #[test]
    fn test_pick_valid_cached_hits_entry_within_ttl() {
        let cached = VersionInfo {
            current_version: "0.11.0".to_string(),
            latest_version: "v0.12.0".to_string(),
            has_update: true,
            release_url: "https://example.com".to_string(),
            release_notes: "测试备注".to_string(),
        };
        let cache: VersionCache = Some((Instant::now(), cached.clone()));

        let picked = pick_valid_cached(&cache).expect("TTL 内的成功条目必须命中");
        assert!(picked.has_update);
        assert_eq!(picked.latest_version, "v0.12.0");
        assert_eq!(picked.release_notes, "测试备注");
    }

    #[test]
    fn test_pick_valid_cached_rejects_expired_entry() {
        // 构造一个刚过期（24 小时零 1 纳秒）的条目，验证 TTL 边界判定生效
        let expired_at = Instant::now() - (VERSION_CACHE_TTL + Duration::from_nanos(1));
        let cache: VersionCache = Some((
            expired_at,
            VersionInfo {
                current_version: "0.11.0".to_string(),
                latest_version: "v0.12.0".to_string(),
                has_update: true,
                release_url: "https://example.com".to_string(),
                release_notes: "陈旧备注".to_string(),
            },
        ));

        assert!(
            pick_valid_cached(&cache).is_none(),
            "超过 24 小时的条目必须被判定失效，不得继续声称存在新版本"
        );
    }

    #[test]
    fn test_pick_valid_cached_hits_entry_just_inside_ttl_boundary() {
        // 边界对侧：恰好在 TTL 之内（预留 1 秒余量）必须命中，防止判定过严
        let fresh_at = Instant::now() - (VERSION_CACHE_TTL - Duration::from_secs(1));
        let cache: VersionCache = Some((
            fresh_at,
            VersionInfo {
                current_version: "0.12.0".to_string(),
                latest_version: "v0.12.0".to_string(),
                has_update: false,
                release_url: "https://example.com".to_string(),
                release_notes: String::new(),
            },
        ));

        assert!(
            pick_valid_cached(&cache).is_some(),
            "TTL 内的条目必须命中，判定条件过严会导致缓存形同虚设"
        );
    }

    /// 覆盖 `query_version_cached` 的全局缓存读取路径
    ///
    /// # 并发安全性
    /// 本用例读写进程级 `VERSION_CACHE`，是本模块唯一触碰全局状态的测试。
    /// 断言只依赖「缓存为空时必返回本地版本」这一不变量，
    /// 因此即便与其他用例并发交错也不会误判，不引入 flaky 风险。
    #[test]
    fn test_query_version_cached_falls_back_to_local_when_cache_empty() {
        *VERSION_CACHE.write() = None;
        let info = query_version_cached();
        assert!(
            !info.has_update,
            "缓存为空时必须降级为本地版本，不得声称存在新版本"
        );
        assert_eq!(info.current_version, env!("CARGO_PKG_VERSION"));
    }
}

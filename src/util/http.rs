use dashmap::DashMap;
use log::{info, warn};
use reqwest::dns::{Name, Resolve, Resolving};
use reqwest::{Client, ClientBuilder, Error as ReqwestError};
use std::iter::once;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::lookup_host;
use url::form_urlencoded::byte_serialize;

use crate::util::dns_resolver::{QueryRecordType, get_custom_dns_server, query_dns_server};
pub use crate::util::interface::*;

/// 全局跳过 TLS 证书验证开关
static SKIP_VERIFY: AtomicBool = AtomicBool::new(false);

/// 设置全局是否跳过 TLS 证书验证
///
/// # 设计原理
/// - **实现初衷**：在内网自签名证书环境或特定代理网络调试时，允许用户配置 `--skipVerify` 绕过证书校验。
/// - **核心优势**：自动清空全局客户端缓存以立即生效。
pub fn set_skip_verify(skip: bool) {
    SKIP_VERIFY.store(skip, Ordering::SeqCst);
    clear_http_client_cache();
    if skip {
        warn!("已开启 --skipVerify 跳过 TLS 证书验证模式，请注意网络通信安全");
    }
}

/// 获取全局是否跳过 TLS 证书验证
pub fn is_skip_verify() -> bool {
    SKIP_VERIFY.load(Ordering::SeqCst)
}

/// 尝试使用配置的自定义上游 DNS 服务器解析主机名
async fn resolve_via_custom_dns(
    host: &str,
    custom_server: &str,
) -> Option<Box<dyn Iterator<Item = SocketAddr> + Send>> {
    let v4_fut = query_dns_server(
        custom_server,
        host,
        QueryRecordType::A,
        Duration::from_secs(2),
    );
    let v6_fut = query_dns_server(
        custom_server,
        host,
        QueryRecordType::AAAA,
        Duration::from_millis(500),
    );

    let (v4_res, v6_res) = tokio::join!(v4_fut, v6_fut);
    let mut socket_addrs = Vec::new();
    if let Ok(ips) = v4_res {
        for ip in ips {
            socket_addrs.push(SocketAddr::new(ip, 0));
        }
    }
    if let Ok(ips) = v6_res {
        for ip in ips {
            socket_addrs.push(SocketAddr::new(ip, 0));
        }
    }

    if !socket_addrs.is_empty() {
        Some(Box::new(socket_addrs.into_iter()))
    } else {
        None
    }
}

/// 全局应用 DNS 解析适配器，优先使用配置的自定义 DNS 递归解析服务器，失败时平滑回退
#[derive(Debug, Clone, Default)]
pub struct AppDnsResolver;

impl Resolve for AppDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str();

            // 若本身是 IP 地址字符串直接返回
            if let Ok(ip) = host.parse::<IpAddr>() {
                let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> =
                    Box::new(once(SocketAddr::new(ip, 0)));
                return Ok(addrs);
            }

            // 优先尝试使用用户配置的自定义递归 DNS 服务器解析
            if let Some(custom_server) = get_custom_dns_server()
                && let Some(addrs) = resolve_via_custom_dns(host, &custom_server).await
            {
                return Ok(addrs);
            }

            // 回退到系统原生异步 DNS 解析
            let host_with_port = format!("{}:0", host);
            let mut resolved = lookup_host(&host_with_port).await?;
            let mut list = Vec::new();
            for addr in resolved.by_ref() {
                list.push(addr);
            }
            let addrs: Box<dyn Iterator<Item = SocketAddr> + Send> = Box::new(list.into_iter());
            Ok(addrs)
        })
    }
}

/// 创建预置安全/跳过证书策略与自定义 DNS 的 Reqwest ClientBuilder
///
/// # 设计原理
/// - **实现初衷**：统一整个应用的 HTTP 客户端构建基础，确保 TLS 策略与纯净 DNS 规则统一生效。
pub fn create_http_client_builder() -> ClientBuilder {
    let mut builder = Client::builder();
    if is_skip_verify() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder = builder.dns_resolver(Arc::new(AppDnsResolver));
    builder
}

/// 根据指定的网络协议族 (IPv4 或 IPv6) 创建绑定了指定出站物理网卡源 IP 的 ClientBuilder
///
/// # 设计原理
/// - **实现初衷**：在双栈但分别有多网卡出口的复杂软路由环境下，强制任务通过指定网卡特定协议族发包。
pub fn create_task_http_client_builder_for_family(
    interface_name: Option<&str>,
    is_ipv6: bool,
) -> ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        let clean = iface.trim();
        if !clean.is_empty() {
            let local_ip = if is_ipv6 {
                find_interface_ipv6(clean).map(IpAddr::V6)
            } else {
                find_interface_ipv4(clean).map(IpAddr::V4)
            };

            if let Some(ip) = local_ip {
                info!(
                    "任务绑定出站物理网卡 [{}] ({}: {})",
                    clean,
                    if is_ipv6 {
                        "IPv6 源地址"
                    } else {
                        "IPv4 源地址"
                    },
                    ip
                );
                builder = builder.local_address(Some(ip));
            } else {
                warn!(
                    "未能在系统网卡 [{}] 中找到有效的 {} 出站地址，将回退至系统默认路由",
                    clean,
                    if is_ipv6 { "IPv6" } else { "IPv4" }
                );
            }
        }
    }
    builder
}

/// 创建绑定了指定出站物理网卡 / 源 IP 的通用 ClientBuilder (多 WAN 软路由多出口支持)
pub fn create_task_http_client_builder(interface_name: Option<&str>) -> ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        let clean = iface.trim();
        if !clean.is_empty() {
            if let Some(local_ip) = find_interface_ip(clean) {
                info!("任务绑定出站物理网卡 [{}] (本地源 IP: {})", clean, local_ip);
                builder = builder.local_address(Some(local_ip));
            } else {
                warn!(
                    "未能在系统网卡中找到 [{}] 对应的出站 IP，将回退至系统默认路由",
                    clean
                );
            }
        }
    }
    builder
}

/// 创建带指定超时的 Reqwest Client
///
/// # Errors
/// 当底层 TLS 库初始化失败或连接池参数非法时返回错误。
pub fn create_http_client(timeout: Duration) -> Result<Client, ReqwestError> {
    create_http_client_builder().timeout(timeout).build()
}

/// 创建绑定了指定出站物理网卡并带指定超时的 Reqwest Client
///
/// # Errors
/// 当绑定本地网卡地址失败或底层网络驱动异常时返回错误。
pub fn create_task_http_client(
    interface_name: Option<&str>,
    timeout: Duration,
) -> Result<Client, ReqwestError> {
    create_task_http_client_builder(interface_name)
        .timeout(timeout)
        .build()
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ClientKey {
    interface_name: Option<String>,
    timeout_ms: u64,
    skip_verify: bool,
    /// 绑定的地址族：`None` 表示不限族，`Some(true)` 为强制 IPv6 出站
    ///
    /// # 设计原理
    /// 双栈环境常需按协议族绑定不同的本机源地址出包，故纳入缓存键维度，
    /// 避免误复用另一地址族的客户端导致源地址绑定失效。
    ipv6_only: Option<bool>,
    /// 自定义 User-Agent，不同取值须视为不同缓存条目
    user_agent: Option<String>,
}

impl ClientKey {
    /// 构造通用 DNS / 通知场景的缓存键
    fn general(interface_name: Option<&str>, timeout: Duration) -> Self {
        Self {
            interface_name: normalize_interface(interface_name),
            timeout_ms: timeout.as_millis() as u64,
            skip_verify: is_skip_verify(),
            ipv6_only: None,
            user_agent: None,
        }
    }
}

/// 归一化网卡名：去除首尾空白，空白串视为未指定
fn normalize_interface(interface_name: Option<&str>) -> Option<String> {
    interface_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

static CLIENT_CACHE: LazyLock<DashMap<ClientKey, Client>> = LazyLock::new(DashMap::new);

/// 清理全局 HTTP 客户端连接池缓存
pub fn clear_http_client_cache() {
    CLIENT_CACHE.clear();
}

/// 获取或创建绑定了指定出站物理网卡并带指定超时的 Reqwest Client (复用全局连接池)
///
/// # 设计原理
/// - **实现初衷**：Reqwest Client 内部维持高昂的 TCP 连接池与 TLS 会话缓存，避免每次轮询重复创建与握手。
/// - **核心优势**：基于网卡名、超时时间与 TLS 选项多维键缓存，依托分段锁容器 `DashMap` 实现高并发零锁竞争读取与零重复建连。
pub fn get_task_http_client(interface_name: Option<&str>, timeout: Duration) -> Client {
    get_or_create_client(
        ClientKey::general(interface_name, timeout),
        || create_task_http_client(interface_name, timeout),
        interface_name,
    )
}

/// 获取或创建绑定指定地址族源IP 与自定义 User-Agent 的 HTTP 客户端 (复用全局连接池)
///
/// # 设计原理
/// IP 探测器需按协议族绑定不同的本机源地址出包，且携带固定 User-Agent，
/// 故与通用客户端分开缓存，依托 `DashMap` 避免每轮探测重复进行 TCP/TLS 握手。
pub fn get_family_http_client(
    interface_name: Option<&str>,
    is_ipv6: bool,
    timeout: Duration,
    user_agent: &str,
) -> Client {
    let key = ClientKey {
        interface_name: normalize_interface(interface_name),
        timeout_ms: timeout.as_millis() as u64,
        skip_verify: is_skip_verify(),
        ipv6_only: Some(is_ipv6),
        user_agent: Some(user_agent.to_string()),
    };

    get_or_create_client(
        key,
        || {
            create_task_http_client_builder_for_family(interface_name, is_ipv6)
                .timeout(timeout)
                .user_agent(user_agent)
                .build()
        },
        interface_name,
    )
}

/// 统一的缓存查找与降级构建流程
///
/// # 设计原理
/// 抽离以保证「通用客户端」与「协议族客户端」共享完全一致的降级策略：
/// 构建失败时依次回退到通用构建器与 reqwest 默认实例，绝不向上抛出，
/// 依托 `DashMap` 的分段锁守卫即查即放，确保缓存层永远安全返回可用客户端。
fn get_or_create_client<F>(key: ClientKey, build: F, interface_name: Option<&str>) -> Client
where
    F: FnOnce() -> Result<Client, ReqwestError>,
{
    if let Some(client) = CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let timeout = Duration::from_millis(key.timeout_ms);
    let client = match build() {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "创建网卡 [{:?}] 绑定的专属 HTTP 客户端失败: {}，正在回退至通用客户端构建器",
                interface_name, e
            );
            match create_http_client(timeout) {
                Ok(c) => c,
                Err(err) => {
                    warn!(
                        "创建通用 HTTP 客户端亦失败: {}，将使用带超时约束的兜底客户端实例",
                        err
                    );
                    Client::builder()
                        .timeout(timeout)
                        .connect_timeout(Duration::from_secs(5).min(timeout))
                        .build()
                        .unwrap_or_else(|_| Client::new())
                }
            }
        }
    };
    CLIENT_CACHE
        .entry(key)
        .or_insert_with(|| client.clone())
        .clone()
}

/// 创建具有 15 秒标准超时的 DNS 任务通用 HTTP 客户端 (跨周期复用全局连接池)
pub fn create_default_dns_client(interface_name: Option<&str>) -> Client {
    get_task_http_client(interface_name, Duration::from_secs(15))
}

/// 创建通知渠道专属的 HTTP 客户端 (标准 10 秒超时，跨周期复用全局连接池)
///
/// # 设计原理
/// 通知分发在每轮同步后可能对多个渠道并发调用，若每次都新建 Client 会
/// 造成连接池反复创建销毁，故统一纳入缓存治理。
pub fn create_notifier_client() -> Client {
    get_task_http_client(None, Duration::from_secs(10))
}

/// 对字符串执行 URL 百分比编码 (application/x-www-form-urlencoded)
pub fn url_encode(s: &str) -> String {
    byte_serialize(s.as_bytes()).collect()
}

/// 根据条件选择是否对字符串执行 URL 百分比编码
pub fn url_encode_if(s: &str, should_encode: bool) -> String {
    if should_encode {
        url_encode(s)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 缓存测试与全局 TLS 状态测试专用的互斥锁
    ///
    /// # 并发说明
    /// Rust 测试默认多线程并行执行，而 `CLIENT_CACHE` 与 `SKIP_VERIFY` 是进程级全局状态，
    /// 多个用例并行断言其条目数或状态会相互干扰。故用一把测试级互斥锁将
    /// 涉及全局缓存与证书策略的用例强制串行执行。
    static TEST_CACHE_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn test_skip_verify_flag() {
        let _guard = TEST_CACHE_LOCK.lock();
        set_skip_verify(true);
        assert!(is_skip_verify());
        set_skip_verify(false);
        assert!(!is_skip_verify());
    }

    #[test]
    fn test_nonexistent_interface_returns_none() {
        let ip = find_interface_ip("nonexistent_interface_999");
        assert!(ip.is_none());
        let v4 = find_interface_ipv4("nonexistent_interface_999");
        assert!(v4.is_none());
        let v6 = find_interface_ipv6("nonexistent_interface_999");
        assert!(v6.is_none());
    }

    #[test]
    fn test_url_encode_if() {
        let raw = "测试 abc 123";
        assert_eq!(url_encode_if(raw, false), raw);
        assert_eq!(url_encode_if(raw, true), "%E6%B5%8B%E8%AF%95+abc+123");
    }

    #[test]
    fn test_client_cache_reuses_same_entry() {
        let _guard = TEST_CACHE_LOCK.lock();
        clear_http_client_cache();
        let timeout = Duration::from_secs(15);

        // 相同键重复请求，缓存条目数不应增长（证明复用了既有条目而非新建）
        let first = get_task_http_client(Some("eth0"), timeout);
        let count_after_first = CLIENT_CACHE.len();
        let second = get_task_http_client(Some("eth0"), timeout);
        let count_after_second = CLIENT_CACHE.len();

        assert_eq!(count_after_first, 1, "首次请求后应恰好写入一个缓存条目");
        assert_eq!(
            count_after_first, count_after_second,
            "相同参数的请求必须复用缓存条目，不得重复写入"
        );
        drop(first);
        drop(second);

        // 不同超时时间应产生新条目
        let _other = get_task_http_client(Some("eth0"), Duration::from_secs(30));
        assert_eq!(CLIENT_CACHE.len(), 2, "不同超时应作为独立缓存条目");
        clear_http_client_cache();
    }

    #[test]
    fn test_client_cache_key_normalizes_blank_interface() {
        let _guard = TEST_CACHE_LOCK.lock();
        clear_http_client_cache();
        let timeout = Duration::from_secs(15);

        // 空白网卡名应被归一化为 None，与完全不传参视为同一条目
        let _blank = get_task_http_client(Some("   "), timeout);
        let _none = get_task_http_client(None, timeout);
        assert_eq!(CLIENT_CACHE.len(), 1, "空白网卡名应归一化后参与缓存键计算");
        clear_http_client_cache();
    }

    #[test]
    fn test_family_client_cache_separates_address_families() {
        let _guard = TEST_CACHE_LOCK.lock();
        clear_http_client_cache();
        let timeout = Duration::from_secs(5);
        // 与 UrlIpFetcher::USER_AGENT 保持一致，避免测试依赖上层模块私有常量
        let ua = concat!("rddns/", env!("CARGO_PKG_VERSION"), " (Rust DDNS Client)");

        // 协议族不同的客户端不得复用同一条目，否则源地址绑定会失效
        let _v4 = get_family_http_client(None, false, timeout, ua);
        let _v6 = get_family_http_client(None, true, timeout, ua);
        assert_eq!(
            CLIENT_CACHE.len(),
            2,
            "IPv4 与 IPv6 客户端必须是独立缓存条目"
        );

        // 同族重复请求应复用
        let _v4_again = get_family_http_client(None, false, timeout, ua);
        assert_eq!(CLIENT_CACHE.len(), 2, "同协议族重复请求应复用缓存");
        clear_http_client_cache();
    }
}

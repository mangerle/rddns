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

/// 全局统一的应用客户端 User-Agent (P2-22)
pub const APP_USER_AGENT: &str = concat!("rddns/", env!("CARGO_PKG_VERSION"));

/// 创建预置安全/跳过证书策略与自定义 DNS 的 Reqwest ClientBuilder
///
/// # 设计原理
/// - **实现初衷**：统一整个应用的 HTTP 客户端构建基础，确保 TLS 策略与纯净 DNS 规则统一生效。
/// - **核心优势**：默认携带规范的 User-Agent，防止云服务商或 WAF 因空客户端标识误拒 (403)。
pub fn create_http_client_builder() -> ClientBuilder {
    let mut builder = Client::builder().user_agent(APP_USER_AGENT);
    if is_skip_verify() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder = builder.dns_resolver(Arc::new(AppDnsResolver));
    builder
}

/// 内部根据具体解析出的本地源 IP 创建绑定网卡的 ClientBuilder
fn create_task_http_client_builder_for_family_with_ip(
    interface_name: Option<&str>,
    bound_ip: Option<IpAddr>,
    is_ipv6: bool,
) -> ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        if let Some(ip) = bound_ip {
            info!(
                "任务绑定出站物理网卡 [{}] ({}: {})",
                iface,
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
                iface,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
        }
    }
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
    let clean = interface_name.map(str::trim).filter(|s| !s.is_empty());
    let bound_ip = clean.and_then(|c| {
        if is_ipv6 {
            find_interface_ipv6(c).map(IpAddr::V6)
        } else {
            find_interface_ipv4(c).map(IpAddr::V4)
        }
    });
    create_task_http_client_builder_for_family_with_ip(clean, bound_ip, is_ipv6)
}

/// 内部根据具体解析出的本地源 IP 创建通用 ClientBuilder
fn create_task_http_client_builder_with_ip(
    interface_name: Option<&str>,
    bound_ip: Option<IpAddr>,
) -> ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        if let Some(local_ip) = bound_ip {
            info!("任务绑定出站物理网卡 [{}] (本地源 IP: {})", iface, local_ip);
            builder = builder.local_address(Some(local_ip));
        } else {
            warn!(
                "未能在系统网卡中找到 [{}] 对应的出站 IP，将回退至系统默认路由",
                iface
            );
        }
    }
    builder
}

/// 创建绑定了指定出站物理网卡 / 源 IP 的通用 ClientBuilder (多 WAN 软路由多出口支持)
pub fn create_task_http_client_builder(interface_name: Option<&str>) -> ClientBuilder {
    let clean = interface_name.map(str::trim).filter(|s| !s.is_empty());
    let bound_ip = clean.and_then(find_interface_ip);
    create_task_http_client_builder_with_ip(clean, bound_ip)
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
    let clean = interface_name.map(str::trim).filter(|s| !s.is_empty());
    let bound_ip = clean.and_then(find_interface_ip);
    create_task_http_client_builder_with_ip(clean, bound_ip)
        .timeout(timeout)
        .build()
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ClientKey {
    interface_name: Option<String>,
    /// 绑定的本地网卡实际源 IP，拨号重新分配后变化以确保旧客户端自动淘汰 (P1-2)
    bound_ip: Option<IpAddr>,
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
    fn general(interface_name: Option<&str>, bound_ip: Option<IpAddr>, timeout: Duration) -> Self {
        Self {
            interface_name: normalize_interface(interface_name),
            bound_ip,
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
/// - **核心优势**：基于网卡名、本地绑定 IP、超时时间与 TLS 选项多维键缓存，依托分段锁容器 `DashMap` 实现高并发零锁竞争读取与零重复建连。
pub fn get_task_http_client(interface_name: Option<&str>, timeout: Duration) -> Client {
    let clean = interface_name.map(str::trim).filter(|s| !s.is_empty());
    let bound_ip = clean.and_then(find_interface_ip);
    let key = ClientKey::general(interface_name, bound_ip, timeout);

    get_or_create_client(
        key,
        || {
            create_task_http_client_builder_with_ip(clean, bound_ip)
                .timeout(timeout)
                .build()
        },
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
    let clean = interface_name.map(str::trim).filter(|s| !s.is_empty());
    let bound_ip = clean.and_then(|c| {
        if is_ipv6 {
            find_interface_ipv6(c).map(IpAddr::V6)
        } else {
            find_interface_ipv4(c).map(IpAddr::V4)
        }
    });

    let key = ClientKey {
        interface_name: normalize_interface(interface_name),
        bound_ip,
        timeout_ms: timeout.as_millis() as u64,
        skip_verify: is_skip_verify(),
        ipv6_only: Some(is_ipv6),
        user_agent: Some(user_agent.to_string()),
    };

    get_or_create_client(
        key,
        || {
            create_task_http_client_builder_for_family_with_ip(clean, bound_ip, is_ipv6)
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
                        .user_agent(APP_USER_AGENT)
                        .timeout(timeout)
                        .connect_timeout(Duration::from_secs(5).min(timeout))
                        .build()
                        .unwrap_or_else(|_| Client::new())
                }
            }
        }
    };

    // 若同一网卡且同协议族存在历史绑定的旧 IP 客户端，主动淘汰以释放套接字与内存 (P1-2)
    if key.interface_name.is_some() {
        CLIENT_CACHE.retain(|k, _| {
            !(k.interface_name == key.interface_name
                && k.ipv6_only == key.ipv6_only
                && k.bound_ip != key.bound_ip)
        });
    }

    CLIENT_CACHE
        .entry(key)
        .or_insert_with(|| client.clone())
        .clone()
}

/// DNS 提供商同步接口通用默认超时时间 (15 秒)
pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(15);

/// 通知渠道推送接口通用默认超时时间 (10 秒)
pub const DEFAULT_NOTIFIER_TIMEOUT: Duration = Duration::from_secs(10);

/// 创建具有标准超时的 DNS 任务通用 HTTP 客户端 (跨周期复用全局连接池)
pub fn create_default_dns_client(interface_name: Option<&str>) -> Client {
    get_task_http_client(interface_name, DEFAULT_DNS_TIMEOUT)
}

/// 创建通知渠道专属的 HTTP 客户端 (标准超时，跨周期复用全局连接池)
///
/// # 设计原理
/// 通知分发在每轮同步后可能对多个渠道并发调用，若每次都新建 Client 会
/// 造成连接池反复创建销毁，故统一纳入缓存治理。
pub fn create_notifier_client() -> Client {
    get_task_http_client(None, DEFAULT_NOTIFIER_TIMEOUT)
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
        let timeout = Duration::from_secs(15);
        let iface = "unique_test_eth0_for_cache_reuse";
        let bound_ip = find_interface_ip(iface);
        let key1 = ClientKey::general(Some(iface), bound_ip, timeout);
        CLIENT_CACHE.remove(&key1);

        let _first = get_task_http_client(Some(iface), timeout);
        assert!(CLIENT_CACHE.contains_key(&key1), "首次请求后应写入缓存条目");

        let _second = get_task_http_client(Some(iface), timeout);
        assert!(
            CLIENT_CACHE.contains_key(&key1),
            "相同参数请求应复用既有缓存条目"
        );

        // 不同超时时间应产生新条目
        let key2 = ClientKey::general(Some(iface), bound_ip, Duration::from_secs(30));
        CLIENT_CACHE.remove(&key2);
        let _other = get_task_http_client(Some(iface), Duration::from_secs(30));
        assert!(
            CLIENT_CACHE.contains_key(&key2),
            "不同超时应作为独立缓存条目"
        );
        assert_ne!(key1, key2);

        CLIENT_CACHE.remove(&key1);
        CLIENT_CACHE.remove(&key2);
    }

    #[test]
    fn test_client_cache_key_normalizes_blank_interface() {
        let _guard = TEST_CACHE_LOCK.lock();
        let timeout = Duration::from_secs(15);
        let key = ClientKey::general(None, None, timeout);
        let key_blank = ClientKey::general(Some("   "), None, timeout);
        assert_eq!(key, key_blank, "空白网卡名与 None 生成的缓存键必须完全一致");

        let _blank = get_task_http_client(Some("   "), timeout);
        assert!(
            CLIENT_CACHE.contains_key(&key),
            "空白网卡名应以 None 键存入缓存"
        );
        let _none = get_task_http_client(None, timeout);
        assert!(
            CLIENT_CACHE.contains_key(&key),
            "None 传参应命中同一缓存条目"
        );
    }

    #[test]
    fn test_family_client_cache_separates_address_families() {
        let _guard = TEST_CACHE_LOCK.lock();
        let timeout = Duration::from_secs(5);
        let iface = "unique_family_test_iface";
        let ua = concat!("rddns/", env!("CARGO_PKG_VERSION"), " (Rust DDNS Client)");

        let key_v4 = ClientKey {
            interface_name: Some(iface.to_string()),
            bound_ip: find_interface_ipv4(iface).map(IpAddr::V4),
            timeout_ms: timeout.as_millis() as u64,
            skip_verify: is_skip_verify(),
            ipv6_only: Some(false),
            user_agent: Some(ua.to_string()),
        };
        let key_v6 = ClientKey {
            interface_name: Some(iface.to_string()),
            bound_ip: find_interface_ipv6(iface).map(IpAddr::V6),
            timeout_ms: timeout.as_millis() as u64,
            skip_verify: is_skip_verify(),
            ipv6_only: Some(true),
            user_agent: Some(ua.to_string()),
        };
        CLIENT_CACHE.remove(&key_v4);
        CLIENT_CACHE.remove(&key_v6);

        let _v4 = get_family_http_client(Some(iface), false, timeout, ua);
        let _v6 = get_family_http_client(Some(iface), true, timeout, ua);
        assert!(
            CLIENT_CACHE.contains_key(&key_v4),
            "IPv4 客户端必须存在于独立键中"
        );
        assert!(
            CLIENT_CACHE.contains_key(&key_v6),
            "IPv6 客户端必须存在于独立键中"
        );
        assert_ne!(key_v4, key_v6, "IPv4 与 IPv6 缓存键必须严格区分");

        CLIENT_CACHE.remove(&key_v4);
        CLIENT_CACHE.remove(&key_v6);
    }

    #[test]
    fn test_client_cache_invalidates_old_ip_on_rebind() {
        let _guard = TEST_CACHE_LOCK.lock();
        let timeout = Duration::from_secs(15);
        let iface = "dialup_eth0_test";
        let old_ip = "192.168.1.10".parse::<IpAddr>().unwrap();
        let new_ip = "192.168.1.20".parse::<IpAddr>().unwrap();

        let old_key = ClientKey::general(Some(iface), Some(old_ip), timeout);
        let new_key = ClientKey::general(Some(iface), Some(new_ip), timeout);

        // 模拟旧 IP 客户端写入
        let _old_client =
            get_or_create_client(old_key.clone(), || create_http_client(timeout), Some(iface));
        assert!(CLIENT_CACHE.contains_key(&old_key));

        // 模拟重新拨号后使用新 IP 获取客户端
        let _new_client =
            get_or_create_client(new_key.clone(), || create_http_client(timeout), Some(iface));
        assert!(CLIENT_CACHE.contains_key(&new_key));
        assert!(
            !CLIENT_CACHE.contains_key(&old_key),
            "网卡重新绑定新 IP 后，旧 IP 客户端必须被自动淘汰"
        );

        CLIENT_CACHE.remove(&new_key);
    }

    #[test]
    fn test_default_user_agent_format() {
        assert!(APP_USER_AGENT.starts_with("rddns/"));
        assert!(APP_USER_AGENT.contains(env!("CARGO_PKG_VERSION")));
    }
}

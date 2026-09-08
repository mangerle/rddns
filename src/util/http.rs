use log::{info, warn};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use parking_lot::RwLock;
use reqwest::dns::{Name, Resolve, Resolving};
use reqwest::{Client, ClientBuilder, Error as ReqwestError};
use std::collections::HashMap;
use std::iter::once;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::lookup_host;
use url::form_urlencoded::byte_serialize;

use crate::util::dns_resolver::{QueryRecordType, get_custom_dns_server, query_dns_server};
use crate::util::net::{is_global_unicast_ipv6, is_public_ipv4, select_best_ipv6};

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

/// 根据指定网卡设备名称寻找出站 IPv4 地址 (排除 Loopback 与未指定地址)
///
/// # 设计原理
/// - **实现初衷**：在多网卡/软路由多 WAN 环境下，精确获取用户指定的出口网卡当前绑定的 IPv4 地址。
/// - **核心优势**：优先选取公网 IPv4，在无公网时安全降级为局域网首个有效地址。
pub fn find_interface_ipv4(iface_name: &str) -> Option<Ipv4Addr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                let mut fallback = None;
                for addr in iface.addr {
                    if let Addr::V4(v4) = addr
                        && !v4.ip.is_loopback()
                        && !v4.ip.is_unspecified()
                    {
                        if is_public_ipv4(&v4.ip) {
                            return Some(v4.ip);
                        }
                        if fallback.is_none() {
                            fallback = Some(v4.ip);
                        }
                    }
                }
                if fallback.is_some() {
                    return fallback;
                }
            }
        }
    }
    None
}

/// 根据指定网卡设备名称寻找出站 IPv6 地址 (必须为全球单播地址，过滤 Link-Local 与 ULA)
///
/// # 设计原理
/// - **实现初衷**：针对双栈或纯 IPv6 宽带环境，挑选出该网卡绑定的最稳定全球单播 IPv6（避开临时隐私地址）。
pub fn find_interface_ipv6(iface_name: &str) -> Option<Ipv6Addr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                let mut v6_candidates = Vec::new();
                for addr in iface.addr {
                    if let Addr::V6(v6) = addr
                        && is_global_unicast_ipv6(&v6.ip)
                    {
                        v6_candidates.push(v6.ip);
                    }
                }
                if let Some(best) = select_best_ipv6(&v6_candidates) {
                    return Some(best);
                }
            }
        }
    }
    None
}

/// 根据指定网卡设备名称寻找最佳出站 IP 地址 (智能优选: 公网 IPv4 > 全球单播 IPv6 > 局域网 IPv4)
///
/// # 设计原理
/// - **实现初衷**：为多 WAN 出口绑定提供通用的本地 IP 探测机制，无需外部配置即可自动选用最优出口协议。
pub fn find_interface_ip(iface_name: &str) -> Option<IpAddr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                let mut public_v4 = None;
                let mut private_v4 = None;
                let mut v6_candidates = Vec::new();

                for addr in iface.addr {
                    match addr {
                        Addr::V4(v4) => {
                            if !v4.ip.is_loopback() && !v4.ip.is_unspecified() {
                                if is_public_ipv4(&v4.ip) {
                                    if public_v4.is_none() {
                                        public_v4 = Some(v4.ip);
                                    }
                                } else if private_v4.is_none() {
                                    private_v4 = Some(v4.ip);
                                }
                            }
                        }
                        Addr::V6(v6) => {
                            if is_global_unicast_ipv6(&v6.ip) {
                                v6_candidates.push(v6.ip);
                            }
                        }
                    }
                }

                // 1. 优先使用公网 IPv4
                if let Some(pub_v4) = public_v4 {
                    return Some(IpAddr::V4(pub_v4));
                }

                // 2. 其次使用优选的全球单播 IPv6 (智能避开临时隐私地址)
                if let Some(best_v6) = select_best_ipv6(&v6_candidates) {
                    return Some(IpAddr::V6(best_v6));
                }

                // 3. 兜底使用局域网/私网 IPv4
                if let Some(priv_v4) = private_v4 {
                    return Some(IpAddr::V4(priv_v4));
                }
            }
        }
    }
    None
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
}

static CLIENT_CACHE: LazyLock<RwLock<HashMap<ClientKey, Client>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 清理全局 HTTP 客户端连接池缓存
pub fn clear_http_client_cache() {
    CLIENT_CACHE.write().clear();
}

/// 获取或创建绑定了指定出站物理网卡并带指定超时的 Reqwest Client (复用全局连接池)
///
/// # 设计原理
/// - **实现初衷**：Reqwest Client 内部维持高昂的 TCP 连接池与 TLS 会话缓存，避免每次轮询重复创建与握手。
/// - **核心优势**：基于网卡名、超时时间与 TLS 选项多维键缓存，零重复建连。
pub fn get_task_http_client(interface_name: Option<&str>, timeout: Duration) -> Client {
    let key = ClientKey {
        interface_name: interface_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        timeout_ms: timeout.as_millis() as u64,
        skip_verify: is_skip_verify(),
    };

    {
        let read_guard = CLIENT_CACHE.read();
        if let Some(client) = read_guard.get(&key) {
            return client.clone();
        }
    }

    let client = match create_task_http_client(interface_name, timeout) {
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
                        "创建通用 HTTP 客户端亦失败: {}，将使用 reqwest 默认实例兜底",
                        err
                    );
                    Client::new()
                }
            }
        }
    };
    let mut write_guard = CLIENT_CACHE.write();
    write_guard
        .entry(key)
        .or_insert_with(|| client.clone())
        .clone()
}

/// 创建具有 15 秒标准超时的 DNS 任务通用 HTTP 客户端 (跨周期复用全局连接池)
pub fn create_default_dns_client(interface_name: Option<&str>) -> Client {
    get_task_http_client(interface_name, Duration::from_secs(15))
}

/// 创建通知渠道专属的 HTTP 客户端 (标准 10 秒超时，带构建失败告警与优雅降级)
pub fn create_notifier_client() -> Client {
    match create_http_client(Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "构建通知渠道专属 HTTP 客户端失败: {}，将使用带超时的基础实例兜底",
                e
            );
            Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default()
        }
    }
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

    #[test]
    fn test_skip_verify_flag() {
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
}

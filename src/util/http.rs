use log::{info, warn};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

/// 全局跳过 TLS 证书验证开关
static SKIP_VERIFY: AtomicBool = AtomicBool::new(false);

/// 设置全局是否跳过 TLS 证书验证
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

use reqwest::dns::{Name, Resolve, Resolving};

/// 全局应用 DNS 解析适配器，优先使用配置的自定义 DNS 递归解析服务器，失败时平滑回退
#[derive(Debug, Clone, Default)]
pub struct AppDnsResolver;

impl Resolve for AppDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let host = name.as_str();

            // 若本身是 IP 地址字符串直接返回
            if let Ok(ip) = host.parse::<IpAddr>() {
                let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> =
                    Box::new(std::iter::once(std::net::SocketAddr::new(ip, 0)));
                return Ok(addrs);
            }

            // 优先尝试使用用户配置的自定义递归 DNS 服务器解析
            if let Some(custom_server) = crate::util::dns_resolver::get_custom_dns_server() {
                let v4_fut = crate::util::dns_resolver::query_dns_server(
                    &custom_server,
                    host,
                    crate::util::dns_resolver::QueryRecordType::A,
                    Duration::from_secs(2),
                );
                // AAAA 记录设置较短超时 (500ms)，避免无 IPv6 环境拖慢整个 HTTP 客户端
                let v6_fut = crate::util::dns_resolver::query_dns_server(
                    &custom_server,
                    host,
                    crate::util::dns_resolver::QueryRecordType::AAAA,
                    Duration::from_millis(500),
                );

                let (v4_res, v6_res) = tokio::join!(v4_fut, v6_fut);
                let mut socket_addrs = Vec::new();
                if let Ok(ips) = v4_res {
                    for ip in ips {
                        socket_addrs.push(std::net::SocketAddr::new(ip, 0));
                    }
                }
                if let Ok(ips) = v6_res {
                    for ip in ips {
                        socket_addrs.push(std::net::SocketAddr::new(ip, 0));
                    }
                }

                if !socket_addrs.is_empty() {
                    let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> =
                        Box::new(socket_addrs.into_iter());
                    return Ok(addrs);
                }
            }

            // 回退到系统原生异步 DNS 解析
            let host_with_port = format!("{}:0", host);
            let mut resolved = tokio::net::lookup_host(&host_with_port).await?;
            let mut list = Vec::new();
            for addr in resolved.by_ref() {
                list.push(addr);
            }
            let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> =
                Box::new(list.into_iter());
            Ok(addrs)
        })
    }
}

/// 创建预置安全/跳过证书策略与自定义 DNS 的 Reqwest ClientBuilder
pub fn create_http_client_builder() -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder();
    if is_skip_verify() {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder = builder.dns_resolver(Arc::new(AppDnsResolver));
    builder
}

/// 根据指定网卡设备名称寻找出站 IPv4 地址 (排除 Loopback 与未指定地址)
pub fn find_interface_ipv4(iface_name: &str) -> Option<std::net::Ipv4Addr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                let mut fallback = None;
                for addr in iface.addr {
                    if let Addr::V4(v4) = addr
                        && !v4.ip.is_loopback()
                        && !v4.ip.is_unspecified()
                    {
                        if crate::util::net::is_public_ipv4(&v4.ip) {
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
pub fn find_interface_ipv6(iface_name: &str) -> Option<std::net::Ipv6Addr> {
    if let Ok(interfaces) = NetworkInterface::show() {
        for iface in interfaces {
            if iface.name.eq_ignore_ascii_case(iface_name) {
                let mut v6_candidates = Vec::new();
                for addr in iface.addr {
                    if let Addr::V6(v6) = addr
                        && crate::util::net::is_global_unicast_ipv6(&v6.ip)
                    {
                        v6_candidates.push(v6.ip);
                    }
                }
                if let Some(best) = crate::util::net::select_best_ipv6(&v6_candidates) {
                    return Some(best);
                }
            }
        }
    }
    None
}

/// 根据指定网卡设备名称寻找最佳出站 IP 地址 (智能优选: 公网 IPv4 > 全球单播 IPv6 > 局域网 IPv4)
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
                                if crate::util::net::is_public_ipv4(&v4.ip) {
                                    if public_v4.is_none() {
                                        public_v4 = Some(v4.ip);
                                    }
                                } else if private_v4.is_none() {
                                    private_v4 = Some(v4.ip);
                                }
                            }
                        }
                        Addr::V6(v6) => {
                            if crate::util::net::is_global_unicast_ipv6(&v6.ip) {
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
                if let Some(best_v6) = crate::util::net::select_best_ipv6(&v6_candidates) {
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
pub fn create_task_http_client_builder_for_family(
    interface_name: Option<&str>,
    is_ipv6: bool,
) -> reqwest::ClientBuilder {
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
pub fn create_task_http_client_builder(interface_name: Option<&str>) -> reqwest::ClientBuilder {
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
pub fn create_http_client(timeout: Duration) -> Result<reqwest::Client, reqwest::Error> {
    create_http_client_builder().timeout(timeout).build()
}

/// 创建绑定了指定出站物理网卡并带指定超时的 Reqwest Client
pub fn create_task_http_client(
    interface_name: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Client, reqwest::Error> {
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

static CLIENT_CACHE: LazyLock<RwLock<HashMap<ClientKey, reqwest::Client>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 清理全局 HTTP 客户端连接池缓存
pub fn clear_http_client_cache() {
    CLIENT_CACHE.write().clear();
}

/// 获取或创建绑定了指定出站物理网卡并带指定超时的 Reqwest Client (复用全局连接池)
pub fn get_task_http_client(interface_name: Option<&str>, timeout: Duration) -> reqwest::Client {
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

    let client = create_task_http_client(interface_name, timeout).unwrap_or_default();
    let mut write_guard = CLIENT_CACHE.write();
    write_guard
        .entry(key)
        .or_insert_with(|| client.clone())
        .clone()
}

/// 创建具有 15 秒标准超时的 DNS 任务通用 HTTP 客户端 (跨周期复用全局连接池)
pub fn create_default_dns_client(interface_name: Option<&str>) -> reqwest::Client {
    get_task_http_client(interface_name, Duration::from_secs(15))
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
}

use log::{info, warn};
use network_interface::{Addr, NetworkInterface, NetworkInterfaceConfig};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// 全局跳过 TLS 证书验证开关
static SKIP_VERIFY: AtomicBool = AtomicBool::new(false);

/// 设置全局是否跳过 TLS 证书验证
pub fn set_skip_verify(skip: bool) {
    SKIP_VERIFY.store(skip, Ordering::SeqCst);
    if skip {
        warn!("⚠️ 已开启 --skipVerify 跳过 TLS 证书验证模式，请注意网络通信安全");
    }
}

/// 获取全局是否跳过 TLS 证书验证
pub fn is_skip_verify() -> bool {
    SKIP_VERIFY.load(Ordering::SeqCst)
}

use reqwest::dns::{Name, Resolve, Resolving};
use std::sync::Arc;

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

/// 根据指定网卡设备名称寻找最佳出站 IP 地址 (优先有效 IPv4，其次全球单播 IPv6，严格过滤 fe80:: 链路本地地址)
pub fn find_interface_ip(iface_name: &str) -> Option<IpAddr> {
    if let Some(v4) = find_interface_ipv4(iface_name) {
        return Some(IpAddr::V4(v4));
    }
    if let Some(v6) = find_interface_ipv6(iface_name) {
        return Some(IpAddr::V6(v6));
    }
    None
}

/// 创建绑定了指定出站物理网卡 / 源 IP 的 ClientBuilder (多 WAN 软路由多出口支持)
pub fn create_task_http_client_builder(interface_name: Option<&str>) -> reqwest::ClientBuilder {
    let mut builder = create_http_client_builder();
    if let Some(iface) = interface_name {
        let clean = iface.trim();
        if !clean.is_empty() {
            if let Some(local_ip) = find_interface_ip(clean) {
                info!(
                    "🔗 任务绑定出站物理网卡 [{}] (本地源 IP: {})",
                    clean, local_ip
                );
                builder = builder.local_address(Some(local_ip));
            } else {
                warn!(
                    "⚠️ 未能在系统网卡中找到 [{}] 对应的出站 IP，将回退至系统默认路由",
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

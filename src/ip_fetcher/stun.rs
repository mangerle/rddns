use crate::ip_fetcher::stun_proto;
use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::dns_resolver::{QueryRecordType, query_dns_server};
use crate::util::http::{find_interface_ipv4, find_interface_ipv6};
use crate::util::net::{is_global_unicast_ipv6, is_public_ipv4};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::timeout;
/// 默认公共高可用 STUN 节点池 (严格按照：国内高可用节点优先 -> 全球 Anycast 节点 -> 海外知名节点)
const DEFAULT_IPV4_STUN_SERVERS: &[&str] = &[
    // 1. 国内大厂低延迟节点 (优先)
    "stun.miwifi.com:3478",        // 小米
    "stun.qq.com:3478",            // 腾讯
    "stun.chat.bilibili.com:3478", // 哔哩哔哩
    "stun.baidu.com:3478",         // 百度
    // 2. 全球 Anycast / 海外高可用节点 (兜底)
    "stun.cloudflare.com:3478", // Cloudflare
    "stun.synology.com:3478",   // 群晖
];

const DEFAULT_IPV6_STUN_SERVERS: &[&str] = &[
    // 原生支持 AAAA 记录的双栈/全球高可用节点
    "stun.nextcloud.com:3478",
    "stun.freeswitch.org:3478",
    "stun.sipgate.net:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.fitauto.ru:3478",
];

/// 基于 STUN 协议 (RFC 5389) 的轻量级 UDP 公网 IP 探测器
pub struct StunIpFetcher {
    custom_server: Option<String>,
    http_interface: Option<String>,
    timeout: Duration,
}

impl StunIpFetcher {
    /// 创建基于 STUN 协议的公网 IP 探测器
    ///
    /// # 设计原理
    /// - **实现初衷**: 当上级路由器开启 NAT 且无公网 IP 暴露在本地网卡、亦或不依赖第三方 HTTP 接口探测时，通过标准 STUN 协议与全球公共服务器通信，能够极低延迟、零解析成本地获取本端映射的外网公网 IP。
    /// - **核心优势**: 采用零堆分配的 20 字节原生 UDP 数据包，无需 TLS 握手与 HTTP 协议层编解码开销；支持国内高可用节点与双栈 fallback。
    /// - **代价与局限**: 依赖公网 UDP 3478 出站端口连通性；在对称 NAT (Symmetric NAT) 下探测到的端口可能与常规端口不同（但不影响 DDNS 提取宿主 IP）。
    pub fn new(custom_server: Option<String>, http_interface: Option<&str>) -> Self {
        Self {
            custom_server: custom_server
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            http_interface: http_interface
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            timeout: Duration::from_secs(2),
        }
    }

    /// 规范化 STUN 服务器地址 (默认补全 3478 端口)
    fn normalize_server_addr(server: &str) -> String {
        let trimmed = server.trim();
        if trimmed.starts_with('[') {
            // IPv6 字面量地址，如 [2400:...]:3478
            if trimmed.contains("]:") {
                trimmed.to_string()
            } else {
                format!("{}:3478", trimmed)
            }
        } else if trimmed.matches(':').count() == 1 {
            // 已带有端口，如 stun.example.com:3478 或 1.2.3.4:3478
            trimmed.to_string()
        } else if trimmed.contains(':') {
            // 纯 IPv6 无端口字面量，如 2400:...
            format!("[{}]:3478", trimmed)
        } else {
            // 域名或 IPv4 无端口
            format!("{}:3478", trimmed)
        }
    }

    /// 构建 STUN 20 字节 Binding Request 报文与 12 字节随机 Transaction ID (纯栈分配零堆开销)
    pub fn build_binding_request() -> ([u8; 20], [u8; 12]) {
        stun_proto::build_binding_request()
    }

    /// 解析 STUN 响应二进制报文 (支持 XOR-MAPPED-ADDRESS 与传统 MAPPED-ADDRESS)
    pub fn parse_binding_response(
        buf: &[u8],
        expected_tx_id: &[u8; 12],
    ) -> Result<IpAddr, FetchError> {
        stun_proto::parse_binding_response(buf, expected_tx_id)
    }

    /// 解析 STUN 服务器地址字符串为主机与端口元组
    fn parse_server_host_port(norm_server: &str) -> (&str, u16) {
        if norm_server.starts_with('[') {
            if let Some(bracket_end) = norm_server.find("]:") {
                (
                    &norm_server[1..bracket_end],
                    norm_server[bracket_end + 2..]
                        .parse::<u16>()
                        .unwrap_or(3478),
                )
            } else {
                (norm_server.trim_matches(|c| c == '[' || c == ']'), 3478)
            }
        } else if let Some(idx) = norm_server.rfind(':') {
            (
                &norm_server[..idx],
                norm_server[idx + 1..].parse::<u16>().unwrap_or(3478),
            )
        } else {
            (norm_server, 3478)
        }
    }

    /// 使用公共递归 DNS 并发兜底查询 STUN 服务器的 AAAA 记录 (P-4)
    async fn resolve_fallback_ipv6(norm_server: &str) -> Vec<SocketAddr> {
        let (host, port) = Self::parse_server_host_port(norm_server);
        let host_clean = host.trim();
        if let Ok(ip) = host_clean.parse::<IpAddr>() {
            if ip.is_ipv6() {
                return vec![SocketAddr::new(ip, port)];
            }
            return Vec::new();
        }

        let (f1, f2, f3) = tokio::join!(
            query_dns_server(
                "223.5.5.5:53",
                host_clean,
                QueryRecordType::AAAA,
                Duration::from_secs(2)
            ),
            query_dns_server(
                "119.29.29.29:53",
                host_clean,
                QueryRecordType::AAAA,
                Duration::from_secs(2)
            ),
            query_dns_server(
                "1.1.1.1:53",
                host_clean,
                QueryRecordType::AAAA,
                Duration::from_secs(2)
            ),
        );

        let mut results = Vec::new();
        for res in [f1, f2, f3] {
            if let Ok(ips) = res {
                for ip in ips {
                    if let IpAddr::V6(v6) = ip {
                        results.push(SocketAddr::new(IpAddr::V6(v6), port));
                    }
                }
            }
            if !results.is_empty() {
                break;
            }
        }
        results
    }

    /// 解析 STUN 服务器为候选目标 Socket 地址列表 (支持多 A/AAAA 记录遍历)
    async fn resolve_stun_target_addrs(
        norm_server: &str,
        is_ipv6: bool,
    ) -> Result<Vec<SocketAddr>, FetchError> {
        let lookup_fut = tokio::time::timeout(Duration::from_secs(3), lookup_host(norm_server));
        let mut target_addrs: Vec<SocketAddr> = match lookup_fut.await {
            Ok(Ok(iter)) => iter
                .filter(|a| if is_ipv6 { a.is_ipv6() } else { a.is_ipv4() })
                .collect(),
            Ok(Err(e)) => {
                debug!("系统原生 DNS 解析 [{}] 失败: {}", norm_server, e);
                Vec::new()
            }
            Err(_) => {
                debug!("系统原生 DNS 解析 [{}] 超时 (3s)", norm_server);
                Vec::new()
            }
        };

        if target_addrs.is_empty() && is_ipv6 {
            target_addrs = Self::resolve_fallback_ipv6(norm_server).await;
        }

        if target_addrs.is_empty() {
            Err(FetchError::Other(format!(
                "未能解析到 STUN 服务器 [{}] 对应的 {} 地址 (请检查网络 DNS 或该服务器是否支持双栈)",
                norm_server,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            )))
        } else {
            Ok(target_addrs)
        }
    }

    /// 确定本地出站 UDP Socket 绑定地址
    fn determine_bind_addr(http_interface: Option<&str>, is_ipv6: bool) -> SocketAddr {
        if is_ipv6 {
            if let Some(iface) = http_interface
                && let Some(src_v6) = find_interface_ipv6(iface)
            {
                SocketAddr::new(IpAddr::V6(src_v6), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        } else if let Some(iface) = http_interface
            && let Some(src_v4) = find_interface_ipv4(iface)
        {
            SocketAddr::new(IpAddr::V4(src_v4), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        }
    }

    /// 向单个 STUN 服务器发送 UDP 请求并接收解析 IP (支持多解析候选地址遍历与 Anycast 兼容)
    async fn probe_single_server(&self, server: &str, is_ipv6: bool) -> Result<IpAddr, FetchError> {
        let norm_server = Self::normalize_server_addr(server);
        let target_addrs = Self::resolve_stun_target_addrs(&norm_server, is_ipv6).await?;
        let bind_addr = Self::determine_bind_addr(self.http_interface.as_deref(), is_ipv6);

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            if is_ipv6 {
                FetchError::Other(format!(
                    "绑定本地 IPv6 UDP 失败: 本地网络可能未分配公网 IPv6 地址或无 IPv6 协议栈 (错误: {})",
                    e
                ))
            } else {
                FetchError::Io(e)
            }
        })?;

        let mut last_err = None;

        for target_addr in target_addrs {
            let (req_bytes, tx_id) = Self::build_binding_request();
            if let Err(e) = socket.send_to(&req_bytes, target_addr).await {
                debug!("向 STUN 目标 [{}] 发送数据包失败: {}", target_addr, e);
                last_err = Some(FetchError::Io(e));
                continue;
            }

            let mut recv_buf = [0u8; 1024];
            let recv_future = socket.recv_from(&mut recv_buf);

            let recv_result = timeout(self.timeout, recv_future).await;
            let (len, from_addr) = match recv_result {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    debug!("从 STUN 目标 [{}] 接收数据失败: {}", target_addr, e);
                    last_err = Some(FetchError::Io(e));
                    continue;
                }
                Err(_) => {
                    debug!("STUN 目标 [{}] 响应超时", target_addr);
                    last_err = Some(FetchError::Timeout);
                    continue;
                }
            };

            // 严格保证响应来自同协议族
            if from_addr.is_ipv6() != target_addr.is_ipv6() {
                debug!(
                    "STUN 响应协议族不匹配: 期望 {}, 实际 {}",
                    target_addr, from_addr
                );
                last_err = Some(FetchError::Other(format!(
                    "STUN 响应协议族不匹配: 期望 {}, 实际 {}",
                    target_addr, from_addr
                )));
                continue;
            }

            // 对于 Anycast/集群部署的 STUN 服务，源地址可能与发往的目的 VIP 不完全一致，
            // RFC 5389 核心依靠 96 位密码学 Transaction ID 进行响应归属绑定
            if from_addr != target_addr {
                debug!(
                    "STUN 响应来源地址与目标不完全一致 (Anycast/多宿主节点特性): 目标 {}, 来源 {}",
                    target_addr, from_addr
                );
            }

            match Self::parse_binding_response(&recv_buf[..len], &tx_id) {
                Ok(ip) => return Ok(ip),
                Err(e) => {
                    debug!("解析 STUN 目标 [{}] 响应失败: {}", target_addr, e);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(FetchError::Timeout))
    }

    /// 获取默认的公共 STUN 服务器列表
    fn default_servers(is_ipv6: bool) -> Vec<String> {
        let pool = if is_ipv6 {
            DEFAULT_IPV6_STUN_SERVERS
        } else {
            DEFAULT_IPV4_STUN_SERVERS
        };
        pool.iter().map(|s| s.to_string()).collect()
    }

    /// 执行多节点故障转移轮询探测
    async fn fetch_ip_with_fallback(&self, is_ipv6: bool) -> Result<IpAddr, FetchError> {
        let server_list: Vec<String> = if let Some(ref custom) = self.custom_server {
            let list: Vec<String> = custom
                .split([',', ';', ' '])
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if list.is_empty() {
                Self::default_servers(is_ipv6)
            } else {
                list
            }
        } else {
            Self::default_servers(is_ipv6)
        };

        let mut last_err = None;
        for server in &server_list {
            debug!(
                "尝试通过 STUN 服务器 [{}] 探测公网 {}...",
                server,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            );
            match self.probe_single_server(server, is_ipv6).await {
                Ok(ip) => {
                    info!(
                        "通过 STUN 服务器 [{}] 成功探测到公网 {}: {}",
                        server,
                        if is_ipv6 { "IPv6" } else { "IPv4" },
                        ip
                    );
                    return Ok(ip);
                }
                Err(e) => {
                    warn!(
                        "通过 STUN 服务器 [{}] 探测 {} 失败: {}",
                        server,
                        if is_ipv6 { "IPv6" } else { "IPv4" },
                        e
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| FetchError::Other("所有配置的 STUN 服务器均探测失败".to_string())))
    }
}

#[async_trait]
impl IpFetcher for StunIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        match self.fetch_ip_with_fallback(false).await {
            Ok(IpAddr::V4(v4)) => {
                // 必须校验为公网单播地址：STUN 服务器返回的映射地址若为 RFC1918 私网
                // 或运营商 CGNAT(100.64.0.0/10)，提交到公网 DNS 后会导致域名对外不可达。
                if is_public_ipv4(&v4) {
                    Ok(Some(v4))
                } else {
                    Err(FetchError::NoValidIpv4(format!(
                        "STUN 返回的 IPv4 非公网单播地址: {}",
                        v4
                    )))
                }
            }
            Ok(IpAddr::V6(v6)) => Err(FetchError::NoValidIpv4(format!(
                "预期 IPv4 但 STUN 返回了 IPv6: {}",
                v6
            ))),
            Err(e) => Err(e),
        }
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        match self.fetch_ip_with_fallback(true).await {
            Ok(IpAddr::V6(v6)) => {
                if is_global_unicast_ipv6(&v6) {
                    Ok(Some(v6))
                } else {
                    Err(FetchError::NoValidIpv6(format!(
                        "STUN 返回的 IPv6 非全球单播地址: {}",
                        v6
                    )))
                }
            }
            Ok(IpAddr::V4(v4)) => Err(FetchError::NoValidIpv6(format!(
                "预期 IPv6 但 STUN 返回了 IPv4: {}",
                v4
            ))),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_server_addr() {
        assert_eq!(
            StunIpFetcher::normalize_server_addr("stun.cloudflare.com"),
            "stun.cloudflare.com:3478"
        );
        assert_eq!(
            StunIpFetcher::normalize_server_addr("stun.cloudflare.com:19302"),
            "stun.cloudflare.com:19302"
        );
        assert_eq!(
            StunIpFetcher::normalize_server_addr("1.1.1.1"),
            "1.1.1.1:3478"
        );
        assert_eq!(
            StunIpFetcher::normalize_server_addr("[2400:cb00::1]:3478"),
            "[2400:cb00::1]:3478"
        );
    }
}

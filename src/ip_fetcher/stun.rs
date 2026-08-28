use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::dns_resolver::{QueryRecordType, query_dns_server};
use crate::util::http::{find_interface_ipv4, find_interface_ipv6};
use crate::util::net::is_global_unicast_ipv6;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// STUN 协议核心常量定义 (RFC 5389)
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_MAGIC_COOKIE_BYTES: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;

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
        let mut req = [0u8; 20];
        // 1. Message Type (2 字节): 0x0001 (Binding Request)
        req[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        // 2. Message Length (2 字节): 0x0000 (无附加属性)
        req[2..4].copy_from_slice(&0u16.to_be_bytes());
        // 3. Magic Cookie (4 字节): 0x2112A442
        req[4..8].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);

        // 4. Transaction ID (12 字节密码学安全随机数)
        let mut tx_id = [0u8; 12];
        crate::util::crypto::fill_random_bytes(&mut tx_id);
        req[8..20].copy_from_slice(&tx_id);

        (req, tx_id)
    }

    /// 解析 STUN 响应二进制报文 (支持 XOR-MAPPED-ADDRESS 与传统 MAPPED-ADDRESS)
    pub fn parse_binding_response(
        buf: &[u8],
        expected_tx_id: &[u8; 12],
    ) -> Result<IpAddr, FetchError> {
        // 基础长度校验
        if buf.len() < 20 {
            return Err(FetchError::Other(format!(
                "STUN 响应报文长度不足 20 字节 (实际: {} 字节)",
                buf.len()
            )));
        }

        // 校验 Message Type
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(FetchError::Other(format!(
                "STUN 响应消息类型异常: 0x{:04x} (预期: 0x{:04x})",
                msg_type, STUN_BINDING_RESPONSE
            )));
        }

        // 校验 Magic Cookie
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(FetchError::Other(format!(
                "STUN 响应 Magic Cookie 校验失败: 0x{:08x}",
                cookie
            )));
        }

        // 校验 Transaction ID
        if &buf[8..20] != expected_tx_id {
            return Err(FetchError::Other(
                "STUN 响应 Transaction ID 与发出的请求不匹配".to_string(),
            ));
        }

        let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let total_available = buf.len() - 20;
        let attr_data_len = msg_len.min(total_available);

        let mut offset = 20;
        let end_offset = 20 + attr_data_len;

        let mut mapped_ip: Option<IpAddr> = None;
        let mut xor_mapped_ip: Option<IpAddr> = None;

        // 遍历 TLV (Type-Length-Value) 属性
        while offset + 4 <= end_offset {
            let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
            let val_start = offset + 4;
            let val_end = val_start + attr_len;

            if val_end > end_offset {
                break;
            }

            let val_bytes = &buf[val_start..val_end];

            if (attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_XOR_MAPPED_ADDRESS_ALT)
                && val_bytes.len() >= 4
            {
                let family = val_bytes[1];
                if family == 0x01 && val_bytes.len() >= 8 {
                    // IPv4: 4 字节地址与 Magic Cookie 逐字节异或
                    let mut ip_octets = [0u8; 4];
                    for i in 0..4 {
                        ip_octets[i] = val_bytes[4 + i] ^ STUN_MAGIC_COOKIE_BYTES[i];
                    }
                    xor_mapped_ip = Some(IpAddr::V4(Ipv4Addr::from(ip_octets)));
                } else if family == 0x02 && val_bytes.len() >= 20 {
                    // IPv6: 16 字节地址与 [Magic Cookie (4字节) + Transaction ID (12字节)] 逐字节异或
                    let mut key = [0u8; 16];
                    key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
                    key[4..16].copy_from_slice(expected_tx_id);

                    let mut ip_octets = [0u8; 16];
                    for i in 0..16 {
                        ip_octets[i] = val_bytes[4 + i] ^ key[i];
                    }
                    xor_mapped_ip = Some(IpAddr::V6(Ipv6Addr::from(ip_octets)));
                }
            } else if attr_type == ATTR_MAPPED_ADDRESS && val_bytes.len() >= 4 {
                let family = val_bytes[1];
                if family == 0x01 && val_bytes.len() >= 8 {
                    let ip_octets = [val_bytes[4], val_bytes[5], val_bytes[6], val_bytes[7]];
                    mapped_ip = Some(IpAddr::V4(Ipv4Addr::from(ip_octets)));
                } else if family == 0x02 && val_bytes.len() >= 20 {
                    let mut ip_octets = [0u8; 16];
                    ip_octets.copy_from_slice(&val_bytes[4..20]);
                    mapped_ip = Some(IpAddr::V6(Ipv6Addr::from(ip_octets)));
                }
            }

            // 根据 RFC 5389，每个属性按 4 字节边界对齐
            let padding = (4 - (attr_len % 4)) % 4;
            offset = val_end + padding;
        }

        // 首选 XOR-MAPPED-ADDRESS，次选 MAPPED-ADDRESS
        xor_mapped_ip.or(mapped_ip).ok_or_else(|| {
            FetchError::Other("STUN 响应中未找到有效的 (XOR-)MAPPED-ADDRESS 属性".to_string())
        })
    }

    /// 向单个 STUN 服务器发送 UDP 请求并接收解析 IP
    async fn probe_single_server(&self, server: &str, is_ipv6: bool) -> Result<IpAddr, FetchError> {
        let norm_server = Self::normalize_server_addr(server);

        // 1. 域名解析为目标 SocketAddr (支持系统原生解析与内置纯 Rust 递归 DNS 兜底)
        let mut target_addrs: Vec<SocketAddr> = match tokio::net::lookup_host(&norm_server).await {
            Ok(iter) => iter
                .filter(|a| if is_ipv6 { a.is_ipv6() } else { a.is_ipv4() })
                .collect(),
            Err(e) => {
                debug!("系统原生 DNS 解析 [{}] 失败: {}", norm_server, e);
                Vec::new()
            }
        };

        // 如果系统 DNS 针对 IPv6 未返回记录 (例如 Windows 在本地无公网 IPv6 时过滤了 AAAA)，
        // 尝试通过内置纯 Rust 递归 DNS 查询器强制解析 AAAA 记录
        if target_addrs.is_empty() && is_ipv6 {
            let (host, port) = if norm_server.starts_with('[') {
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
                (norm_server.as_str(), 3478)
            };
            let host_clean = host.trim();
            if let Ok(ip) = host_clean.parse::<IpAddr>() {
                if ip.is_ipv6() {
                    target_addrs.push(SocketAddr::new(ip, port));
                }
            } else {
                // 依次尝试向公共 DNS (阿里 223.5.5.5 / 腾讯 119.29.29.29 / Cloudflare 1.1.1.1) 强制查询 AAAA 记录
                let dns_servers = ["223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"];
                for dns in dns_servers {
                    if let Ok(ips) = query_dns_server(
                        dns,
                        host_clean,
                        QueryRecordType::AAAA,
                        Duration::from_secs(2),
                    )
                    .await
                    {
                        for ip in ips {
                            if let IpAddr::V6(v6) = ip {
                                target_addrs.push(SocketAddr::new(IpAddr::V6(v6), port));
                            }
                        }
                        if !target_addrs.is_empty() {
                            break;
                        }
                    }
                }
            }
        }

        if target_addrs.is_empty() {
            return Err(FetchError::Other(format!(
                "未能解析到 STUN 服务器 [{}] 对应的 {} 地址 (请检查网络 DNS 或该服务器是否支持双栈)",
                norm_server,
                if is_ipv6 { "IPv6" } else { "IPv4" }
            )));
        }

        let target_addr = target_addrs[0];

        // 2. 绑定本地出站 UDP Socket (支持绑定到指定网卡源 IP)
        let bind_addr: SocketAddr = if is_ipv6 {
            if let Some(ref iface) = self.http_interface
                && let Some(src_v6) = find_interface_ipv6(iface)
            {
                SocketAddr::new(IpAddr::V6(src_v6), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            }
        } else if let Some(ref iface) = self.http_interface
            && let Some(src_v4) = find_interface_ipv4(iface)
        {
            SocketAddr::new(IpAddr::V4(src_v4), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };

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

        // 3. 构建并发送 STUN 请求
        let (req_bytes, tx_id) = Self::build_binding_request();
        socket.send_to(&req_bytes, target_addr).await.map_err(|e| {
            if is_ipv6 {
                FetchError::Other(format!(
                    "向 STUN 目标 [{}] 发送 IPv6 数据包失败: 本地网络无 IPv6 出站路由或不可达 (错误: {})",
                    target_addr, e
                ))
            } else {
                FetchError::Io(e)
            }
        })?;

        // 4. 等待回包并设置超时控制
        let mut recv_buf = [0u8; 1024];
        let recv_future = socket.recv_from(&mut recv_buf);

        let (len, _from_addr) = tokio::time::timeout(self.timeout, recv_future)
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(FetchError::Io)?;

        // 5. 解析回包字节
        Self::parse_binding_response(&recv_buf[..len], &tx_id)
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
                if !v4.is_unspecified() && !v4.is_loopback() {
                    Ok(Some(v4))
                } else {
                    Err(FetchError::NoValidIpv4(format!(
                        "STUN 返回了非法的 IPv4: {}",
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
    fn test_build_binding_request_structure() {
        let (req, tx_id) = StunIpFetcher::build_binding_request();
        assert_eq!(req.len(), 20);
        // 校验 Message Type
        assert_eq!(&req[0..2], &[0x00, 0x01]);
        // 校验 Message Length
        assert_eq!(&req[2..4], &[0x00, 0x00]);
        // 校验 Magic Cookie
        assert_eq!(&req[4..8], &[0x21, 0x12, 0xa4, 0x42]);
        // 校验 Transaction ID
        assert_eq!(&req[8..20], &tx_id);
    }

    #[test]
    fn test_parse_xor_mapped_ipv4() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut resp = vec![0u8; 32];
        // Header
        resp[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp[2..4].copy_from_slice(&12u16.to_be_bytes()); // length 12
        resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
        resp[8..20].copy_from_slice(&tx_id);

        // Attribute: XOR-MAPPED-ADDRESS (0x0020), length = 8
        resp[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp[22..24].copy_from_slice(&8u16.to_be_bytes());
        resp[24] = 0x00; // reserved
        resp[25] = 0x01; // IPv4 family
        resp[26..28].copy_from_slice(&[0x12, 0x34]); // X-Port

        // 目标 IP: 114.114.114.114
        let target_ip = [114, 114, 114, 114];
        let xor_ip = [
            target_ip[0] ^ 0x21,
            target_ip[1] ^ 0x12,
            target_ip[2] ^ 0xa4,
            target_ip[3] ^ 0x42,
        ];
        resp[28..32].copy_from_slice(&xor_ip);

        let parsed = StunIpFetcher::parse_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)));
    }

    #[test]
    fn test_parse_xor_mapped_ipv6() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut resp = vec![0u8; 44];
        // Header
        resp[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp[2..4].copy_from_slice(&24u16.to_be_bytes()); // length 24
        resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
        resp[8..20].copy_from_slice(&tx_id);

        // Attribute: XOR-MAPPED-ADDRESS (0x0020), length = 20
        resp[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp[22..24].copy_from_slice(&20u16.to_be_bytes());
        resp[24] = 0x00; // reserved
        resp[25] = 0x02; // IPv6 family
        resp[26..28].copy_from_slice(&[0x12, 0x34]); // X-Port

        // 目标 IPv6: 2408:8207:7880:1234::1
        let target_v6: Ipv6Addr = "2408:8207:7880:1234::1".parse().unwrap();
        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
        key[4..16].copy_from_slice(&tx_id);

        let target_octets = target_v6.octets();
        let mut xor_v6 = [0u8; 16];
        for i in 0..16 {
            xor_v6[i] = target_octets[i] ^ key[i];
        }
        resp[28..44].copy_from_slice(&xor_v6);

        let parsed = StunIpFetcher::parse_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed, IpAddr::V6(target_v6));
    }

    #[test]
    fn test_parse_mapped_address_fallback() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut resp = vec![0u8; 32];
        // Header
        resp[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        resp[2..4].copy_from_slice(&12u16.to_be_bytes());
        resp[4..8].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
        resp[8..20].copy_from_slice(&tx_id);

        // Attribute: MAPPED-ADDRESS (0x0001), length = 8
        resp[20..22].copy_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        resp[22..24].copy_from_slice(&8u16.to_be_bytes());
        resp[24] = 0x00;
        resp[25] = 0x01; // IPv4
        resp[26..28].copy_from_slice(&[0x12, 0x34]);
        resp[28..32].copy_from_slice(&[223, 5, 5, 5]); // 明文 223.5.5.5

        let parsed = StunIpFetcher::parse_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
    }

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

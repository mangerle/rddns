use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// 全局自定义 DNS 递归解析服务器地址 (如 "223.5.5.5" 或 "1.1.1.1:53")
static CUSTOM_DNS_SERVER: RwLock<Option<String>> = RwLock::new(None);

/// DNS 缓存条目
#[derive(Debug, Clone)]
struct DnsCacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

type DnsCacheKey = (String, String, u8);
type DnsCacheMap = RwLock<HashMap<DnsCacheKey, DnsCacheEntry>>;

/// 全局 DNS 解析内存缓存池 (Key: (dns_server, domain, qtype))
static GLOBAL_DNS_CACHE: std::sync::LazyLock<DnsCacheMap> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

/// 设置全局自定义 DNS 解析服务器
pub fn set_custom_dns_server(server: String) {
    let clean = server.trim().to_string();
    if !clean.is_empty() {
        tracing::info!("🌐 已配置自定义 DNS 递归解析服务器: {}", clean);
        *CUSTOM_DNS_SERVER.write() = Some(clean);
    }
}

/// 清空全局自定义 DNS 解析服务器（恢复系统默认解析）
pub fn clear_custom_dns_server() {
    tracing::info!("🌐 已清空自定义 DNS 递归解析服务器，恢复系统原生 DNS 解析");
    *CUSTOM_DNS_SERVER.write() = None;
}

/// 获取全局自定义 DNS 解析服务器
#[allow(dead_code)]
pub fn get_custom_dns_server() -> Option<String> {
    CUSTOM_DNS_SERVER.read().clone()
}

/// 标准 DNS 记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum QueryRecordType {
    A = 1,
    AAAA = 28,
}

/// 构造标准 DNS 查询请求数据包 (UDP 格式)
#[allow(dead_code)]
fn build_dns_query_packet(
    domain: &str,
    qtype: QueryRecordType,
    query_id: u16,
) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(64);

    // 1. Header (12 字节)
    // ID
    packet.extend_from_slice(&query_id.to_be_bytes());
    // Flags: 标准递归查询 RD=1 -> 0x0100
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // 2. Question Section: QNAME
    let clean_domain = domain.trim_end_matches('.');
    if clean_domain.is_empty() {
        return Err("域名不能为空".to_string());
    }

    for label in clean_domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("域名标签不合法: [{}]", label));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // QNAME 结尾 0 长度

    // QTYPE (A: 0x0001, AAAA: 0x001C)
    packet.extend_from_slice(&(qtype as u16).to_be_bytes());
    // QCLASS (IN: 0x0001)
    packet.extend_from_slice(&[0x00, 0x01]);

    Ok(packet)
}

/// 安全跳过 DNS 域名标签或压缩指针 (带越界与防死循环保护)
fn skip_dns_name(buf: &[u8], offset: &mut usize) -> Result<(), String> {
    let mut steps = 0;
    while *offset < buf.len() {
        steps += 1;
        if steps > 128 {
            return Err("DNS 域名解析嵌套层级超出限制".to_string());
        }
        let len = buf[*offset] as usize;
        if len == 0 {
            *offset += 1;
            return Ok(());
        }
        if (len & 0xC0) == 0xC0 {
            if *offset + 2 > buf.len() {
                return Err("DNS 压缩指针截断".to_string());
            }
            *offset += 2;
            return Ok(());
        }
        if *offset + 1 + len > buf.len() {
            return Err("DNS 域名 Label 长度超出数据包边界".to_string());
        }
        *offset += 1 + len;
    }
    Err("DNS 域名数据包意外截断".to_string())
}

/// 解析 DNS 响应数据包提取 IP 列表与最小 TTL (秒)
fn parse_dns_response_packet(
    buf: &[u8],
    query_id: u16,
    qtype: QueryRecordType,
) -> Result<(Vec<IpAddr>, u32), String> {
    if buf.len() < 12 {
        return Err("DNS 响应包长度过短".to_string());
    }

    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != query_id {
        return Err(format!(
            "DNS 响应 ID 不匹配: 期望 {}, 实际 {}",
            query_id, resp_id
        ));
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let tc = (flags & 0x0200) != 0;
    if tc {
        tracing::warn!("DNS 响应报文被服务器截断 (TC=1)，可能仅包含部分 IP 记录");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(format!("DNS 解析服务器返回错误码 (RCODE={})", rcode));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;

    // 跳过 Question 部分
    for _ in 0..qdcount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 4 > buf.len() {
            return Err("DNS Question 区段被截断".to_string());
        }
        offset += 4; // QTYPE (2B) + QCLASS (2B)
    }

    let mut ips = Vec::new();
    let mut min_ttl = 300u32;

    // 解析 Answer 部分
    for _ in 0..ancount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 10 > buf.len() {
            return Err("DNS Answer 区段被截断".to_string());
        }

        let atype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            return Err("DNS Answer RDATA 数据区被截断".to_string());
        }

        if atype == (qtype as u16) {
            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }
            if qtype == QueryRecordType::A && rdlength == 4 {
                let ipv4 = Ipv4Addr::new(
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                );
                ips.push(IpAddr::V4(ipv4));
            } else if qtype == QueryRecordType::AAAA && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[offset..offset + 16]);
                let ipv6 = Ipv6Addr::from(octets);
                ips.push(IpAddr::V6(ipv6));
            }
        }

        offset += rdlength;
    }

    Ok((ips, min_ttl.clamp(5, 3600)))
}

/// 执行自定义 DNS 递归查询 (防本地运营商 DNS 污染，带并发内存缓存)
pub async fn query_dns_server(
    server_addr: &str,
    domain: &str,
    qtype: QueryRecordType,
    timeout_duration: Duration,
) -> Result<Vec<IpAddr>, String> {
    let clean_domain = domain.trim_end_matches('.').to_lowercase();
    let cache_key = (server_addr.to_string(), clean_domain.clone(), qtype as u8);

    // 1. 检查全局内存缓存
    if let Some(entry) = GLOBAL_DNS_CACHE.read().get(&cache_key)
        && entry.expires_at > Instant::now()
    {
        return Ok(entry.ips.clone());
    }

    let target_server: SocketAddr = if let Ok(addr) = server_addr.parse() {
        addr
    } else if let Ok(ip) = server_addr.parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else {
        return Err(format!("无法解析 DNS 服务器地址 [{}]", server_addr));
    };

    // 绑定随机本地 UDP 端口
    let bind_addr = if target_server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let mut last_err = None;
    for attempt in 1..=2 {
        let query_id = fastrand::u16(..);
        let packet = build_dns_query_packet(&clean_domain, qtype, query_id)?;

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => return Err(format!("绑定本地 UDP 失败: {}", e)),
        };

        if let Err(e) = socket.send_to(&packet, target_server).await {
            last_err = Some(format!(
                "向 DNS 服务器 {} 发送查询失败: {}",
                target_server, e
            ));
            continue;
        }

        let mut buf = [0u8; 512];
        let recv_fut = socket.recv_from(&mut buf);

        let (len, src_addr) = match tokio::time::timeout(timeout_duration, recv_fut).await {
            Ok(Ok((l, addr))) => (l, addr),
            Ok(Err(e)) => {
                last_err = Some(format!("接收 DNS 响应失败: {}", e));
                continue;
            }
            Err(_) => {
                last_err = Some(format!("DNS 查询超时 (第 {} 次尝试)", attempt));
                continue;
            }
        };

        if src_addr != target_server {
            last_err = Some(format!(
                "DNS 响应来源地址不匹配: 期望 {}, 实际 {}",
                target_server, src_addr
            ));
            continue;
        }

        match parse_dns_response_packet(&buf[..len], query_id, qtype) {
            Ok((ips, ttl_secs)) => {
                if !ips.is_empty() {
                    let expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
                    let mut cache = GLOBAL_DNS_CACHE.write();
                    if cache.len() >= 512 {
                        let now = Instant::now();
                        cache.retain(|_, entry| entry.expires_at > now);
                    }
                    cache.insert(
                        cache_key,
                        DnsCacheEntry {
                            ips: ips.clone(),
                            expires_at,
                        },
                    );
                }
                return Ok(ips);
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "DNS 查询失败".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_parse_dns_packet() {
        let packet_a = build_dns_query_packet("example.com", QueryRecordType::A, 12345).unwrap();
        assert!(packet_a.len() > 12);
        assert_eq!(&packet_a[0..2], &[0x30, 0x39]); // 12345 in hex is 0x3039

        let packet_aaaa =
            build_dns_query_packet("test.example.com", QueryRecordType::AAAA, 54321).unwrap();
        assert!(packet_aaaa.len() > 12);
        assert_eq!(&packet_aaaa[0..2], &[0xD4, 0x31]); // 54321 in hex is 0xD431
    }

    #[test]
    fn test_custom_dns_server_setter_getter() {
        set_custom_dns_server("223.5.5.5:53".to_string());
        assert_eq!(get_custom_dns_server(), Some("223.5.5.5:53".to_string()));
    }

    #[test]
    fn test_truncated_dns_packet() {
        // 截断的数据包应安全返回 Err 而不是发生 panic
        let short_packet = vec![0x12, 0x34, 0x81, 0x80];
        let res = parse_dns_response_packet(&short_packet, 0x1234, QueryRecordType::A);
        assert!(res.is_err());

        // 包含无效超长 label 的数据包
        let mut malformed_packet = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00];
        malformed_packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x3F, 0x61, 0x62]); // label 声明 63 字节但后续只有 2 字节
        let res2 = parse_dns_response_packet(&malformed_packet, 0x1234, QueryRecordType::A);
        assert!(res2.is_err());
    }
}

use anyhow::{Result, anyhow, bail};
use log::{debug, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

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
        info!("已配置自定义 DNS 递归解析服务器: {}", clean);
        *CUSTOM_DNS_SERVER.write() = Some(clean);
    }
}

/// 清空全局自定义 DNS 解析服务器（恢复系统默认解析）
pub fn clear_custom_dns_server() {
    info!("已清空自定义 DNS 递归解析服务器，恢复系统原生 DNS 解析");
    *CUSTOM_DNS_SERVER.write() = None;
}

/// 获取全局自定义 DNS 解析服务器
pub fn get_custom_dns_server() -> Option<String> {
    CUSTOM_DNS_SERVER.read().clone()
}

/// 标准 DNS 记录类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum QueryRecordType {
    A = 1,
    AAAA = 28,
}

/// 构造标准 DNS 查询请求数据包 (UDP 格式)
fn build_dns_query_packet(domain: &str, qtype: QueryRecordType, query_id: u16) -> Result<Vec<u8>> {
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
        bail!("域名不能为空");
    }

    for label in clean_domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("域名标签不合法: [{}]", label);
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
fn skip_dns_name(buf: &[u8], offset: &mut usize) -> Result<()> {
    let mut steps = 0;
    while *offset < buf.len() {
        steps += 1;
        if steps > 128 {
            bail!("DNS 域名解析嵌套层级超出限制");
        }
        let len = buf[*offset] as usize;
        if len == 0 {
            *offset += 1;
            return Ok(());
        }
        if (len & 0xC0) == 0xC0 {
            if *offset + 2 > buf.len() {
                bail!("DNS 压缩指针截断");
            }
            *offset += 2;
            return Ok(());
        }
        if *offset + 1 + len > buf.len() {
            bail!("DNS 域名 Label 长度超出数据包边界");
        }
        *offset += 1 + len;
    }
    bail!("DNS 域名数据包意外截断")
}

/// 安全读取 DNS 域名字符串（支持 RFC 1035 压缩指针与防死循环保护）
fn read_dns_name_at(buf: &[u8], mut offset: usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut steps = 0;

    while offset < buf.len() {
        steps += 1;
        if steps > 128 {
            bail!("DNS 域名解析嵌套层级超出限制");
        }
        let len = buf[offset] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 2 > buf.len() {
                bail!("DNS 压缩指针截断");
            }
            let ptr = ((len & 0x3F) << 8) | (buf[offset + 1] as usize);
            if ptr >= buf.len() {
                bail!("DNS 压缩指针指向超出数据包边界");
            }
            offset = ptr;
            continue;
        }

        offset += 1;
        if offset + len > buf.len() {
            bail!("DNS 域名 Label 长度超出数据包边界");
        }
        let label_str = std::str::from_utf8(&buf[offset..offset + len])
            .map_err(|e| anyhow!("DNS Label UTF-8 解析失败: {}", e))?;
        labels.push(label_str);
        offset += len;
    }

    Ok(labels.join("."))
}

/// 解析 DNS 响应数据包提取 IP 列表、最小 TTL (秒)、可能存在的 CNAME 别名目标以及是否被截断 (TC 标志)
fn parse_dns_response_packet(
    buf: &[u8],
    query_id: u16,
    qtype: QueryRecordType,
) -> Result<(Vec<IpAddr>, u32, Option<String>, bool)> {
    if buf.len() < 12 {
        bail!("DNS 响应包长度过短");
    }

    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != query_id {
        bail!("DNS 响应 ID 不匹配: 期望 {}, 实际 {}", query_id, resp_id);
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let tc = (flags & 0x0200) != 0;
    if tc {
        warn!("DNS 响应报文被服务器截断 (TC=1)，将尝试回退至 TCP 查询完整记录");
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        bail!("DNS 解析服务器返回错误码 (RCODE={})", rcode);
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut offset = 12;

    // 跳过 Question 部分
    for _ in 0..qdcount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 4 > buf.len() {
            bail!("DNS Question 区段被截断");
        }
        offset += 4; // QTYPE (2B) + QCLASS (2B)
    }

    let mut ips = Vec::new();
    let mut min_ttl = 300u32;
    let mut cname_target: Option<String> = None;

    // 解析 Answer 部分
    for _ in 0..ancount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 10 > buf.len() {
            bail!("DNS Answer 区段被截断");
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
            bail!("DNS Answer RDATA 数据区被截断");
        }

        if atype == (qtype as u16) {
            // RFC 2181: 若 TTL 最高位为 1 (大于 2^31 - 1)，应视为 0
            let valid_ttl = if ttl <= 0x7FFFFFFF { ttl } else { 0 };
            if valid_ttl < min_ttl {
                min_ttl = valid_ttl;
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
        } else if atype == 5 {
            // CNAME 别名记录类型
            if let Ok(cname) = read_dns_name_at(buf, offset)
                && !cname.trim().is_empty()
            {
                cname_target = Some(cname);
            }
        }

        offset += rdlength;
    }

    Ok((ips, min_ttl.clamp(5, 3600), cname_target, tc))
}

/// 执行 TCP 53 端口 DNS 查询 (RFC 1035: 带 2 字节报文长度前缀，用于大包响应或截断兜底)
pub async fn query_dns_server_tcp(
    target_server: SocketAddr,
    clean_domain: &str,
    qtype: QueryRecordType,
    query_id: u16,
    timeout_duration: Duration,
) -> Result<(Vec<IpAddr>, u32, Option<String>)> {
    let packet = build_dns_query_packet(clean_domain, qtype, query_id)?;
    let mut tcp_stream =
        match tokio::time::timeout(timeout_duration, TcpStream::connect(target_server)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => bail!("连接 DNS 服务器 {} (TCP:53) 失败: {}", target_server, e),
            Err(_) => bail!("连接 DNS 服务器 {} (TCP:53) 超时", target_server),
        };

    // RFC 1035: TCP 报文发送前须包含 2 字节的大端长度前缀
    let len_prefix = (packet.len() as u16).to_be_bytes();
    let mut send_buf = Vec::with_capacity(2 + packet.len());
    send_buf.extend_from_slice(&len_prefix);
    send_buf.extend_from_slice(&packet);

    let write_and_read = async {
        tcp_stream.write_all(&send_buf).await?;
        tcp_stream.flush().await?;

        let mut len_bytes = [0u8; 2];
        tcp_stream.read_exact(&mut len_bytes).await?;
        let resp_len = u16::from_be_bytes(len_bytes) as usize;
        if !(12..=65535).contains(&resp_len) {
            bail!("DNS TCP 响应报文长度非法: {}", resp_len);
        }

        let mut resp_buf = vec![0u8; resp_len];
        tcp_stream.read_exact(&mut resp_buf).await?;
        Ok::<Vec<u8>, anyhow::Error>(resp_buf)
    };

    let resp_bytes = match tokio::time::timeout(timeout_duration, write_and_read).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => bail!("TCP DNS 报文收发失败: {}", e),
        Err(_) => bail!("TCP DNS 请求超时"),
    };

    let (ips, ttl_secs, cname, _) = parse_dns_response_packet(&resp_bytes, query_id, qtype)?;
    Ok((ips, ttl_secs, cname))
}

/// 执行自定义 DNS 递归查询 (防本地运营商 DNS 污染，带并发内存缓存、CNAME 追溯与 TCP 截断兜底)
pub async fn query_dns_server(
    server_addr: &str,
    domain: &str,
    qtype: QueryRecordType,
    timeout_duration: Duration,
) -> Result<Vec<IpAddr>> {
    query_dns_server_recursive(server_addr, domain, qtype, timeout_duration, 0).await
}

/// 内部带深度限制的 DNS 递归查询实现 (最大递归 3 层以防别名死循环)
async fn query_dns_server_recursive(
    server_addr: &str,
    domain: &str,
    qtype: QueryRecordType,
    timeout_duration: Duration,
    depth: u8,
) -> Result<Vec<IpAddr>> {
    if depth > 3 {
        bail!("DNS CNAME 别名递归追溯层级超过限制 (最大 3 层)");
    }

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
        bail!("无法解析 DNS 服务器地址 [{}]", server_addr);
    };

    // 绑定随机本地 UDP 端口
    let bind_addr = if target_server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let mut last_err = None;
    for attempt in 1..=2 {
        let query_id = crate::util::crypto::random_u16();
        let packet = build_dns_query_packet(&clean_domain, qtype, query_id)?;

        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => s,
            Err(e) => bail!("绑定本地 UDP 失败: {}", e),
        };

        if let Err(e) = socket.send_to(&packet, target_server).await {
            last_err = Some(anyhow!(
                "向 DNS 服务器 {} 发送查询失败: {}",
                target_server,
                e
            ));
            continue;
        }

        let mut buf = [0u8; 512];
        let recv_fut = socket.recv_from(&mut buf);

        let (len, src_addr) = match tokio::time::timeout(timeout_duration, recv_fut).await {
            Ok(Ok((l, addr))) => (l, addr),
            Ok(Err(e)) => {
                last_err = Some(anyhow!("接收 DNS 响应失败: {}", e));
                continue;
            }
            Err(_) => {
                last_err = Some(anyhow!("DNS 查询超时 (第 {} 次尝试)", attempt));
                continue;
            }
        };

        if src_addr != target_server {
            last_err = Some(anyhow!(
                "DNS 响应来源地址不匹配: 期望 {}, 实际 {}",
                target_server,
                src_addr
            ));
            continue;
        }

        match parse_dns_response_packet(&buf[..len], query_id, qtype) {
            Ok((mut ips, mut ttl_secs, mut cname_target, is_truncated)) => {
                // 若 UDP 响应被截断 (TC=1)，自动回退至 TCP 53 端口获取完整数据
                if is_truncated {
                    info!(
                        "DNS 查询 [{}] 响应被截断 (TC=1)，正在自动回退至 TCP 53 端口获取完整数据...",
                        clean_domain
                    );
                    if let Ok((tcp_ips, tcp_ttl, tcp_cname)) = query_dns_server_tcp(
                        target_server,
                        &clean_domain,
                        qtype,
                        query_id,
                        timeout_duration,
                    )
                    .await
                    {
                        ips = tcp_ips;
                        ttl_secs = tcp_ttl;
                        cname_target = tcp_cname;
                    }
                }

                // 如果直接解析到了目标 IP 地址
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
                    return Ok(ips);
                }

                // 如果未直接返回 IP 但携带了 CNAME 别名记录，递归查询别名目标
                if let Some(cname) = cname_target {
                    debug!(
                        "DNS 查询 [{}] 收到 CNAME 别名 [{}]，正在发起追溯查询...",
                        clean_domain, cname
                    );
                    match Box::pin(query_dns_server_recursive(
                        server_addr,
                        &cname,
                        qtype,
                        timeout_duration,
                        depth + 1,
                    ))
                    .await
                    {
                        Ok(resolved_ips) => {
                            if !resolved_ips.is_empty() {
                                let expires_at =
                                    Instant::now() + Duration::from_secs(ttl_secs as u64);
                                let mut cache = GLOBAL_DNS_CACHE.write();
                                cache.insert(
                                    cache_key,
                                    DnsCacheEntry {
                                        ips: resolved_ips.clone(),
                                        expires_at,
                                    },
                                );
                            }
                            return Ok(resolved_ips);
                        }
                        Err(e) => {
                            last_err = Some(anyhow!("递归追溯 CNAME [{}] 失败: {}", cname, e));
                            continue;
                        }
                    }
                }

                return Ok(Vec::new());
            }
            Err(e) => {
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("DNS 查询失败")))
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

    #[test]
    fn test_read_dns_name_at() {
        // 构造域名 "foo.bar.com" -> [3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 3, 'c', 'o', 'm', 0]
        let name_bytes = b"\x03foo\x03bar\x03com\x00";
        let parsed = read_dns_name_at(name_bytes, 0).unwrap();
        assert_eq!(parsed, "foo.bar.com");
    }
}

use anyhow::{Result, anyhow, bail};
use log::{debug, info, warn};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::from_utf8;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::util::crypto::random_u16;

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
static GLOBAL_DNS_CACHE: LazyLock<DnsCacheMap> = LazyLock::new(|| RwLock::new(HashMap::new()));

/// 设置全局自定义 DNS 解析服务器
///
/// # 设计原理
/// - **实现初衷**：在运营商本地 DNS 存在劫持、投毒或缓存严重滞后的网络环境下，
///   允许用户指定可靠的上游公共 DNS（如阿里 223.5.5.5、腾讯 119.29.29.29 或 Cloudflare 1.1.1.1）进行纯净解析。
/// - **核心优势**：直接影响所有任务的当前解析 IP 查询，无需重启进程。
pub fn set_custom_dns_server(server: String) {
    let clean = server.trim().to_string();
    if !clean.is_empty() {
        info!("已配置自定义 DNS 递归解析服务器: {}", clean);
        *CUSTOM_DNS_SERVER.write() = Some(clean);
    }
}

/// 清空全局自定义 DNS 解析服务器（恢复系统默认解析）
///
/// # 设计原理
/// - **实现初衷**：用户移除自定义 DNS 后无缝回退至操作系统原生 libc/socket 解析。
pub fn clear_custom_dns_server() {
    info!("已清空自定义 DNS 递归解析服务器，恢复系统原生 DNS 解析");
    *CUSTOM_DNS_SERVER.write() = None;
}

/// 获取当前配置的全局自定义 DNS 解析服务器
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
        let label_str = from_utf8(&buf[offset..offset + len])
            .map_err(|e| anyhow!("DNS Label UTF-8 解析失败: {}", e))?;
        labels.push(label_str);
        offset += len;
    }

    Ok(labels.join("."))
}

/// 校验 DNS 响应报文头部（包含 ID、截断标志与返回码）并返回 Question 和 Answer 数量
fn validate_dns_header(buf: &[u8], query_id: u16) -> Result<(usize, usize, bool)> {
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
    Ok((qdcount, ancount, tc))
}

/// 解析 Answer 区段中的单个资源记录
fn parse_single_answer(
    buf: &[u8],
    offset: &mut usize,
    qtype: QueryRecordType,
    ips: &mut Vec<IpAddr>,
    min_ttl: &mut u32,
    cname_target: &mut Option<String>,
) -> Result<()> {
    skip_dns_name(buf, offset)?;
    if *offset + 10 > buf.len() {
        bail!("DNS Answer 区段被截断");
    }

    let atype = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
    let ttl = u32::from_be_bytes([
        buf[*offset + 4],
        buf[*offset + 5],
        buf[*offset + 6],
        buf[*offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([buf[*offset + 8], buf[*offset + 9]]) as usize;
    *offset += 10;

    if *offset + rdlength > buf.len() {
        bail!("DNS Answer RDATA 数据区被截断");
    }

    if atype == (qtype as u16) {
        let valid_ttl = if ttl <= 0x7FFFFFFF { ttl } else { 0 };
        if valid_ttl < *min_ttl {
            *min_ttl = valid_ttl;
        }
        if qtype == QueryRecordType::A && rdlength == 4 {
            let ipv4 = Ipv4Addr::new(
                buf[*offset],
                buf[*offset + 1],
                buf[*offset + 2],
                buf[*offset + 3],
            );
            ips.push(IpAddr::V4(ipv4));
        } else if qtype == QueryRecordType::AAAA && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[*offset..*offset + 16]);
            ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    } else if atype == 5
        && let Ok(cname) = read_dns_name_at(buf, *offset)
        && !cname.trim().is_empty()
    {
        *cname_target = Some(cname);
    }

    *offset += rdlength;
    Ok(())
}

/// 解析 DNS 响应数据包提取 IP 列表、最小 TTL (秒)、可能存在的 CNAME 别名目标以及是否被截断 (TC 标志)
fn parse_dns_response_packet(
    buf: &[u8],
    query_id: u16,
    qtype: QueryRecordType,
) -> Result<(Vec<IpAddr>, u32, Option<String>, bool)> {
    let (qdcount, ancount, tc) = validate_dns_header(buf, query_id)?;
    let mut offset = 12;

    // 跳过 Question 部分
    for _ in 0..qdcount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 4 > buf.len() {
            bail!("DNS Question 区段被截断");
        }
        offset += 4;
    }

    let mut ips = Vec::new();
    let mut min_ttl = 300u32;
    let mut cname_target = None;

    // 解析 Answer 部分
    for _ in 0..ancount {
        parse_single_answer(
            buf,
            &mut offset,
            qtype,
            &mut ips,
            &mut min_ttl,
            &mut cname_target,
        )?;
    }

    Ok((ips, min_ttl.clamp(5, 3600), cname_target, tc))
}

/// 读取 TCP 53 端口响应报文
async fn read_tcp_dns_response(
    tcp_stream: &mut TcpStream,
    timeout_duration: Duration,
) -> Result<Vec<u8>> {
    let read_fut = async {
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

    match timeout(timeout_duration, read_fut).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(e)) => bail!("TCP DNS 报文收发失败: {}", e),
        Err(_) => bail!("TCP DNS 请求超时"),
    }
}

/// 执行 TCP 53 端口 DNS 查询 (RFC 1035: 带 2 字节报文长度前缀，用于大包响应或截断兜底)
///
/// # 设计原理
/// - **实现初衷**：当 UDP 响应报文超出 512 字节触发截断 (TC=1) 时，RFC 1035 要求回退至 TCP 查询完整应答。
/// - **核心优势**：自动构造 RFC 规定的 2 字节前缀并完整读取流式响应。
///
/// # Errors
/// 当 TCP 连接超时、建连被拒或报文格式截断时返回错误。
pub async fn query_dns_server_tcp(
    target_server: SocketAddr,
    clean_domain: &str,
    qtype: QueryRecordType,
    query_id: u16,
    timeout_duration: Duration,
) -> Result<(Vec<IpAddr>, u32, Option<String>)> {
    let packet = build_dns_query_packet(clean_domain, qtype, query_id)?;
    let mut tcp_stream = match timeout(timeout_duration, TcpStream::connect(target_server)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => bail!("连接 DNS 服务器 {} (TCP:53) 失败: {}", target_server, e),
        Err(_) => bail!("连接 DNS 服务器 {} (TCP:53) 超时", target_server),
    };

    let len_prefix = (packet.len() as u16).to_be_bytes();
    let mut send_buf = Vec::with_capacity(2 + packet.len());
    send_buf.extend_from_slice(&len_prefix);
    send_buf.extend_from_slice(&packet);

    tcp_stream.write_all(&send_buf).await?;
    tcp_stream.flush().await?;

    let resp_bytes = read_tcp_dns_response(&mut tcp_stream, timeout_duration).await?;
    let (ips, ttl_secs, cname, _) = parse_dns_response_packet(&resp_bytes, query_id, qtype)?;
    Ok((ips, ttl_secs, cname))
}

/// 解析 DNS 服务器的主机与端口为标准套接字地址
fn resolve_dns_server_addr(server_addr: &str) -> Result<SocketAddr> {
    if let Ok(addr) = server_addr.parse() {
        Ok(addr)
    } else if let Ok(ip) = server_addr.parse::<IpAddr>() {
        Ok(SocketAddr::new(ip, 53))
    } else {
        bail!("无法解析 DNS 服务器地址 [{}]", server_addr);
    }
}

/// 将成功解析的 DNS 记录写入全局内存缓存
fn cache_dns_result(key: DnsCacheKey, ips: &[IpAddr], ttl_secs: u32) {
    if ips.is_empty() {
        return;
    }
    let expires_at = Instant::now() + Duration::from_secs(ttl_secs as u64);
    let mut cache = GLOBAL_DNS_CACHE.write();
    if cache.len() >= 512 {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
    }
    cache.insert(
        key,
        DnsCacheEntry {
            ips: ips.to_vec(),
            expires_at,
        },
    );
}

/// 执行单次 UDP DNS 发送与接收
async fn perform_udp_attempt(
    target_server: SocketAddr,
    packet: &[u8],
    timeout_duration: Duration,
) -> Result<(Vec<u8>, SocketAddr)> {
    let bind_addr = if target_server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| anyhow!("绑定本地 UDP 失败: {}", e))?;

    socket
        .send_to(packet, target_server)
        .await
        .map_err(|e| anyhow!("向 DNS 服务器 {} 发送查询失败: {}", target_server, e))?;

    let mut buf = [0u8; 512];
    let (len, src_addr) = timeout(timeout_duration, socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("DNS 查询超时"))?
        .map_err(|e| anyhow!("接收 DNS 响应失败: {}", e))?;

    Ok((buf[..len].to_vec(), src_addr))
}

/// 执行自定义 DNS 递归查询 (防本地运营商 DNS 污染，带并发内存缓存、CNAME 追溯与 TCP 截断兜底)
///
/// # 设计原理
/// - **实现初衷**：防止本地运营商 DNS 污染或缓存未刷新导致误报已同步，支持直连上游 DNS 权威服务器。
/// - **核心优势**：内置内存 TTL 缓存池、支持 CNAME 别名自动追溯与 UDP 截断自动 TCP 回退。
///
/// # Errors
/// 当网络不可达、DNS 超时、递归深度超限或返回非零 RCODE 错误码时返回错误。
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

    // 1. 优先命中内存缓存
    if let Some(entry) = GLOBAL_DNS_CACHE.read().get(&cache_key)
        && entry.expires_at > Instant::now()
    {
        return Ok(entry.ips.clone());
    }

    let target_server = resolve_dns_server_addr(server_addr)?;
    let mut last_err = None;

    for attempt in 1..=2 {
        let query_id = random_u16();
        let packet = build_dns_query_packet(&clean_domain, qtype, query_id)?;

        let (resp_bytes, src_addr) =
            match perform_udp_attempt(target_server, &packet, timeout_duration).await {
                Ok(res) => res,
                Err(e) => {
                    last_err = Some(anyhow!("第 {} 次查询失败: {}", attempt, e));
                    continue;
                }
            };

        if src_addr != target_server {
            last_err = Some(anyhow!(
                "DNS 响应来源不匹配: 期望 {}, 实际 {}",
                target_server,
                src_addr
            ));
            continue;
        }

        match parse_dns_response_packet(&resp_bytes, query_id, qtype) {
            Ok((mut ips, mut ttl_secs, mut cname_target, is_truncated)) => {
                if is_truncated {
                    info!(
                        "DNS 查询 [{}] 响应被截断 (TC=1)，正在回退至 TCP 53 获取完整数据...",
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

                if !ips.is_empty() {
                    cache_dns_result(cache_key, &ips, ttl_secs);
                    return Ok(ips);
                }

                if let Some(cname) = cname_target {
                    debug!(
                        "DNS 查询 [{}] 收到 CNAME 别名 [{}]，追溯查询中...",
                        clean_domain, cname
                    );
                    let resolved = Box::pin(query_dns_server_recursive(
                        server_addr,
                        &cname,
                        qtype,
                        timeout_duration,
                        depth + 1,
                    ))
                    .await?;
                    if !resolved.is_empty() {
                        cache_dns_result(cache_key, &resolved, ttl_secs);
                    }
                    return Ok(resolved);
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
        let old = get_custom_dns_server();
        set_custom_dns_server("223.5.5.5:53".to_string());
        assert_eq!(get_custom_dns_server(), Some("223.5.5.5:53".to_string()));
        clear_custom_dns_server();
        assert_eq!(get_custom_dns_server(), None);
        if let Some(prev) = old {
            set_custom_dns_server(prev);
        }
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

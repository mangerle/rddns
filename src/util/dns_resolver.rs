use crate::util::crypto::random_u16;
use crate::util::dns_packet::{build_dns_query_packet, parse_dns_response_packet};
use anyhow::{Result, anyhow, bail};
use log::{debug, info};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

pub use crate::util::dns_packet::QueryRecordType;

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
}

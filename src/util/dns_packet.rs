use anyhow::{Result, anyhow, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

/// 标准 DNS 记录类型
///
/// # 设计原理
/// - **实现初衷**: 适配 RFC 1035 标准中针对 IPv4 (A) 与 IPv6 (AAAA) 的查询类型编号。
/// - **核心优势**: 强类型枚举映射，明确协议魔数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub enum QueryRecordType {
    A = 1,
    AAAA = 28,
}

/// DNS Answer 区段解析累加器
struct AnswerAccumulator {
    ips: Vec<IpAddr>,
    min_ttl: u32,
    cname_target: Option<String>,
}

impl AnswerAccumulator {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            ips: Vec::with_capacity(capacity),
            min_ttl: 300,
            cname_target: None,
        }
    }
}

/// 构造标准 DNS 查询请求数据包 (UDP/TCP 通用载荷)
///
/// # 设计原理
/// - **实现初衷**: 手工构建符合 RFC 1035 标准的轻量级二进制 DNS 查询请求，避免引入庞大的外部第三方 DNS 库。
/// - **核心优势**: 预分配 64 字节缓冲区，严格按 Label 长度前缀打包域名，支持防格式注入检测。
/// - **代价与局限**: 仅支持标准 IN 类的 A 与 AAAA 单次查询。
///
/// # Errors
/// 当域名为空或标签长度超过 63 字节时返回错误。
pub fn build_dns_query_packet(
    domain: &str,
    qtype: QueryRecordType,
    query_id: u16,
) -> Result<Vec<u8>> {
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
pub fn read_dns_name_at(buf: &[u8], mut offset: usize) -> Result<String> {
    let mut labels = Vec::with_capacity(4);
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
    acc: &mut AnswerAccumulator,
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
        if valid_ttl < acc.min_ttl {
            acc.min_ttl = valid_ttl;
        }
        if qtype == QueryRecordType::A && rdlength == 4 {
            let ipv4 = Ipv4Addr::new(
                buf[*offset],
                buf[*offset + 1],
                buf[*offset + 2],
                buf[*offset + 3],
            );
            acc.ips.push(IpAddr::V4(ipv4));
        } else if qtype == QueryRecordType::AAAA && rdlength == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[*offset..*offset + 16]);
            acc.ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
    } else if atype == 5
        && let Ok(cname) = read_dns_name_at(buf, *offset)
        && !cname.trim().is_empty()
    {
        acc.cname_target = Some(cname);
    }

    *offset += rdlength;
    Ok(())
}

/// 解析 DNS 响应数据包提取 IP 列表、最小 TTL (秒)、可能存在的 CNAME 别名目标以及是否被截断 (TC 标志)
///
/// # Errors
/// 当响应包被意外截断、ID 不匹配或返回非零 RCODE 错误码时返回错误。
pub fn parse_dns_response_packet(
    buf: &[u8],
    query_id: u16,
    qtype: QueryRecordType,
) -> Result<(Vec<IpAddr>, u32, Option<String>, bool)> {
    let (qdcount, ancount, tc) = validate_dns_header(buf, query_id)?;
    if tc {
        return Ok((Vec::new(), 300, None, true));
    }

    let mut offset = 12;

    // 跳过 Question 部分
    for _ in 0..qdcount {
        skip_dns_name(buf, &mut offset)?;
        if offset + 4 > buf.len() {
            bail!("DNS Question 区段被截断");
        }
        offset += 4;
    }

    let mut acc = AnswerAccumulator::with_capacity(ancount.min(16));

    // 解析 Answer 部分
    for _ in 0..ancount {
        parse_single_answer(buf, &mut offset, qtype, &mut acc)?;
    }

    Ok((acc.ips, acc.min_ttl.clamp(5, 3600), acc.cname_target, false))
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
    fn test_tc_flag_returns_truncated_without_failing_on_partial_answer() {
        // 头部声明 TC=1 (0x8380) 且 ANCOUNT=5，但后续载荷被 UDP 截断不完整
        let tc_packet = vec![
            0x12, 0x34, // ID
            0x83, 0x80, // Flags: QR=1, RD=1, RA=1, TC=1, RCODE=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x05, // ANCOUNT=5 (实际未包含完整 Answer)
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        let (ips, ttl, cname, is_truncated) =
            parse_dns_response_packet(&tc_packet, 0x1234, QueryRecordType::A).unwrap();
        assert!(is_truncated);
        assert!(ips.is_empty());
        assert_eq!(ttl, 300);
        assert!(cname.is_none());
    }

    #[test]
    fn test_read_dns_name_at() {
        // 构造域名 "foo.bar.com" -> [3, 'f', 'o', 'o', 3, 'b', 'a', 'r', 3, 'c', 'o', 'm', 0]
        let name_bytes = b"\x03foo\x03bar\x03com\x00";
        let parsed = read_dns_name_at(name_bytes, 0).unwrap();
        assert_eq!(parsed, "foo.bar.com");
    }
}

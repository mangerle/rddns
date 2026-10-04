use crate::ip_fetcher::trait_def::FetchError;
use crate::util::crypto::fill_random_bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// STUN 协议核心常量定义 (RFC 5389 / RFC 3489)
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
pub const STUN_MAGIC_COOKIE_BYTES: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
pub const ATTR_XOR_MAPPED_ADDRESS_ALT: u16 = 0x8020;

/// 构建 STUN 20 字节 Binding Request 报文与 12 字节随机 Transaction ID (纯栈分配零堆开销)
///
/// # 设计原理
/// - **实现初衷**: 遵循 RFC 5389 构建精简的 STUN 绑定请求报文，仅包含 20 字节标准固定头部，不附加非必要的扩展属性。
/// - **核心优势**: 采用固定大小栈数组 `[u8; 20]` 与 `[u8; 12]`，实现零堆内存分配；Transaction ID 采用密码学安全伪随机数防范反射放大与报文伪造。
/// - **代价与局限**: 不包含 MESSAGE-INTEGRITY 等鉴权扩展属性，适用于公开免费 STUN 服务器的无状态 NAT 反射探测。
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
    fill_random_bytes(&mut tx_id);
    req[8..20].copy_from_slice(&tx_id);

    (req, tx_id)
}

/// 解析 XOR-MAPPED-ADDRESS 属性 (RFC 5389)
fn parse_xor_mapped_address(val_bytes: &[u8], expected_tx_id: &[u8; 12]) -> Option<IpAddr> {
    if val_bytes.len() < 4 {
        return None;
    }
    let family = val_bytes[1];
    if family == 0x01 && val_bytes.len() >= 8 {
        // IPv4: 4 字节地址与 Magic Cookie 逐字节异或
        let mut ip_octets = [0u8; 4];
        for i in 0..4 {
            ip_octets[i] = val_bytes[4 + i] ^ STUN_MAGIC_COOKIE_BYTES[i];
        }
        Some(IpAddr::V4(Ipv4Addr::from(ip_octets)))
    } else if family == 0x02 && val_bytes.len() >= 20 {
        // IPv6: 16 字节地址与 [Magic Cookie (4字节) + Transaction ID (12字节)] 逐字节异或
        let mut key = [0u8; 16];
        key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE_BYTES);
        key[4..16].copy_from_slice(expected_tx_id);

        let mut ip_octets = [0u8; 16];
        for i in 0..16 {
            ip_octets[i] = val_bytes[4 + i] ^ key[i];
        }
        Some(IpAddr::V6(Ipv6Addr::from(ip_octets)))
    } else {
        None
    }
}

/// 解析传统 MAPPED-ADDRESS 属性 (RFC 3489)
fn parse_mapped_address(val_bytes: &[u8]) -> Option<IpAddr> {
    if val_bytes.len() < 4 {
        return None;
    }
    let family = val_bytes[1];
    if family == 0x01 && val_bytes.len() >= 8 {
        let ip_octets = [val_bytes[4], val_bytes[5], val_bytes[6], val_bytes[7]];
        Some(IpAddr::V4(Ipv4Addr::from(ip_octets)))
    } else if family == 0x02 && val_bytes.len() >= 20 {
        let mut ip_octets = [0u8; 16];
        ip_octets.copy_from_slice(&val_bytes[4..20]);
        Some(IpAddr::V6(Ipv6Addr::from(ip_octets)))
    } else {
        None
    }
}

/// 解析 STUN 响应二进制报文 (支持 XOR-MAPPED-ADDRESS 与传统 MAPPED-ADDRESS)
///
/// # Errors
///
/// - 报文长度不足 20 字节
/// - 消息类型非 Binding Response
/// - Magic Cookie 或 Transaction ID 校验失败
/// - 报文中不存在有效的反射地址属性
pub fn parse_binding_response(buf: &[u8], expected_tx_id: &[u8; 12]) -> Result<IpAddr, FetchError> {
    if buf.len() < 20 {
        return Err(FetchError::Other(format!(
            "STUN 响应报文长度不足 20 字节 (实际: {} 字节)",
            buf.len()
        )));
    }

    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(FetchError::Other(format!(
            "STUN 响应消息类型异常: 0x{:04x} (预期: 0x{:04x})",
            msg_type, STUN_BINDING_RESPONSE
        )));
    }

    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(FetchError::Other(format!(
            "STUN 响应 Magic Cookie 校验失败: 0x{:08x}",
            cookie
        )));
    }

    if &buf[8..20] != expected_tx_id {
        return Err(FetchError::Other(
            "STUN 响应 Transaction ID 与发出的请求不匹配".to_string(),
        ));
    }

    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end_offset = 20 + msg_len.min(buf.len() - 20);
    let mut offset = 20;

    let mut mapped_ip: Option<IpAddr> = None;
    let mut xor_mapped_ip: Option<IpAddr> = None;

    while offset + 4 <= end_offset {
        let attr_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let attr_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        let val_start = offset + 4;
        let val_end = val_start + attr_len;

        if val_end > end_offset {
            break;
        }

        let val_bytes = &buf[val_start..val_end];
        if attr_type == ATTR_XOR_MAPPED_ADDRESS || attr_type == ATTR_XOR_MAPPED_ADDRESS_ALT {
            xor_mapped_ip = parse_xor_mapped_address(val_bytes, expected_tx_id).or(xor_mapped_ip);
        } else if attr_type == ATTR_MAPPED_ADDRESS {
            mapped_ip = parse_mapped_address(val_bytes).or(mapped_ip);
        }

        let padding = (4 - (attr_len % 4)) % 4;
        offset = val_end + padding;
    }

    xor_mapped_ip.or(mapped_ip).ok_or_else(|| {
        FetchError::Other("STUN 响应中未找到有效的 (XOR-)MAPPED-ADDRESS 属性".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request_structure() {
        let (req, tx_id) = build_binding_request();
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

        let parsed = parse_binding_response(&resp, &tx_id).unwrap();
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

        let parsed = parse_binding_response(&resp, &tx_id).unwrap();
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

        let parsed = parse_binding_response(&resp, &tx_id).unwrap();
        assert_eq!(parsed, IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
    }
}

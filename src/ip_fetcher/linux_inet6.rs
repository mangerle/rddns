use crate::util::net::is_global_unicast_ipv6;
use std::fs;
use std::net::Ipv6Addr;
use std::path::Path;

/// Linux 内核 IPv6 地址标志位常量 (定义于 include/uapi/linux/if_addr.h，使用 32 位掩码避免高位溢出)
pub const IFA_F_TEMPORARY: u32 = 0x01; // RFC 4941 临时隐私地址
pub const IFA_F_DADFAILED: u32 = 0x08; // DAD 冲突检测失败
pub const IFA_F_DEPRECATED: u32 = 0x20; // 已过期的废弃地址
pub const IFA_F_TENTATIVE: u32 = 0x40; // DAD 冲突检测中

/// Linux `/proc/net/if_inet6` 单条 IPv6 地址条目
///
/// # 设计原理
/// - **实现初衷**: Linux 系统下各网络接口的 IPv6 地址拥有内核级的生命周期状态标志（如临时隐私地址、废弃状态、DAD 探测状态等），
///   常规 Socket 或跨平台网络库通常无法细粒度获取这些标志，直接读取 `/proc/net/if_inet6` 是最轻量且无外部 C 依赖的获取途径。
/// - **核心优势**: 纯文本解析开销极低，能精确识别并过滤临时隐私地址与 DAD 冲突地址，保证 DDNS 绑定的始终是稳定、可达的公网 IPv6。
/// - **代价与局限**: 仅在 Linux procfs 文件系统有效；非 Linux 平台需依赖通用网卡枚举兜底。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxIfInet6Entry {
    pub ip: Ipv6Addr,
    pub if_index: u32,
    pub prefix_len: u8,
    pub scope: u8,
    pub flags: u32,
    pub if_name: String,
}

impl LinuxIfInet6Entry {
    /// 是否为全球单播作用域 (Scope 0x00)
    pub fn is_global_scope(&self) -> bool {
        self.scope == 0x00
    }

    /// 是否为临时隐私地址 (IFA_F_TEMPORARY = 0x01)
    pub fn is_temporary(&self) -> bool {
        (self.flags & IFA_F_TEMPORARY) != 0
    }

    /// 是否已废弃 (IFA_F_DEPRECATED = 0x20)
    pub fn is_deprecated(&self) -> bool {
        (self.flags & IFA_F_DEPRECATED) != 0
    }

    /// 是否处于 DAD 探测或失败状态 (IFA_F_TENTATIVE = 0x40 或 IFA_F_DADFAILED = 0x08)
    pub fn is_tentative_or_failed(&self) -> bool {
        (self.flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) != 0
    }

    /// 是否为适合入站 DDNS 的稳定全球单播地址 (非临时、未废弃、非冲突且为全球单播)
    pub fn is_stable_global(&self) -> bool {
        self.is_global_scope()
            && !self.is_temporary()
            && !self.is_deprecated()
            && !self.is_tentative_or_failed()
            && is_global_unicast_ipv6(&self.ip)
    }
}

/// 解析单行 `/proc/net/if_inet6` 内容
/// 格式示例：`2408820778cd12340200f8fffed144ff 02 40 00 80 eth0`
pub fn parse_if_inet6_line(line: &str) -> Option<LinuxIfInet6Entry> {
    let mut parts = line.split_whitespace();
    let hex_ip = parts.next()?;
    let hex_ifindex = parts.next()?;
    let hex_prefix = parts.next()?;
    let hex_scope = parts.next()?;
    let hex_flags = parts.next()?;
    let if_name = parts.next()?;

    // 严格校验 IPv6 十六进制字符串长度与字符集，杜绝非 ASCII 字符在切片时触发 panic (P3-16)
    if hex_ip.len() != 32 || !hex_ip.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let mut segments = [0u16; 8];
    for i in 0..8 {
        segments[i] = u16::from_str_radix(&hex_ip[i * 4..(i + 1) * 4], 16).ok()?;
    }
    let ip = Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    );

    let if_index = u32::from_str_radix(hex_ifindex, 16).ok()?;
    let prefix_len = u8::from_str_radix(hex_prefix, 16).ok()?;
    let scope = u8::from_str_radix(hex_scope, 16).ok()?;
    let flags = u32::from_str_radix(hex_flags, 16).ok()?;

    Some(LinuxIfInet6Entry {
        ip,
        if_index,
        prefix_len,
        scope,
        flags,
        if_name: if_name.to_string(),
    })
}

/// 从 `/proc/net/if_inet6` 文本中解析指定网卡的所有 IPv6 条目
pub fn parse_if_inet6_content(
    content: &str,
    target_ifname: Option<&str>,
) -> Vec<LinuxIfInet6Entry> {
    content
        .lines()
        .filter_map(parse_if_inet6_line)
        .filter(|entry| {
            if let Some(target) = target_ifname {
                entry.if_name.eq_ignore_ascii_case(target)
            } else {
                true
            }
        })
        .collect()
}

/// 读取并解析 Linux 系统 `/proc/net/if_inet6` 文件（仅在 Linux 或文件存在时有效）
pub fn read_linux_if_inet6(target_ifname: Option<&str>) -> Option<Vec<LinuxIfInet6Entry>> {
    let content = fs::read_to_string(Path::new("/proc/net/if_inet6")).ok()?;
    Some(parse_if_inet6_content(&content, target_ifname))
}

/// 根据网卡及 Linux procfs 条目对 IPv6 进行排序与去重
pub fn sort_linux_interface_ipv6s(
    if_name: &str,
    ipv6s: Vec<String>,
    all_entries: &[LinuxIfInet6Entry],
) -> Vec<String> {
    let if_entries: Vec<&LinuxIfInet6Entry> = all_entries
        .iter()
        .filter(|e| e.if_name.eq_ignore_ascii_case(if_name))
        .collect();

    if if_entries.is_empty() {
        return ipv6s;
    }

    let mut sorted_v6 = Vec::new();
    let mut push_unique = |ip_str: String| {
        if !sorted_v6.contains(&ip_str) {
            sorted_v6.push(ip_str);
        }
    };

    // 1. 优先加入稳定全球单播地址
    for e in if_entries.iter().filter(|e| e.is_stable_global()) {
        push_unique(e.ip.to_string());
    }
    // 2. 其次加入健康的临时全球单播地址 (排除废弃与 DAD 冲突)
    for e in if_entries.iter().filter(|e| {
        e.is_global_scope()
            && !e.is_stable_global()
            && !e.is_deprecated()
            && !e.is_tentative_or_failed()
    }) {
        push_unique(e.ip.to_string());
    }
    // 3. 补充其它非全局单播
    for v6_str in ipv6s {
        push_unique(v6_str);
    }
    sorted_v6
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_if_inet6_line() {
        // 永久稳定公网 IPv6
        let line_perm = "2408820778cd12340200f8fffed144ff 02 40 00 80 eth0";
        let entry_perm = parse_if_inet6_line(line_perm).expect("解析失败");
        assert_eq!(
            entry_perm.ip,
            Ipv6Addr::from_str("2408:8207:78cd:1234:200:f8ff:fed1:44ff").unwrap()
        );
        assert_eq!(entry_perm.if_index, 2);
        assert_eq!(entry_perm.prefix_len, 64);
        assert_eq!(entry_perm.scope, 0);
        assert_eq!(entry_perm.flags, 0x80);
        assert_eq!(entry_perm.if_name, "eth0");
        assert!(entry_perm.is_stable_global());
        assert!(!entry_perm.is_temporary());
        assert!(!entry_perm.is_deprecated());

        // 现代内核高位 Stable Privacy IPv6 (flags 0x880，超过 u8 范围)
        let line_high_flags = "2408820778cd12340200f8fffed144ff 02 40 00 880 eth0";
        let entry_high = parse_if_inet6_line(line_high_flags).expect("高位 Flags 解析失败");
        assert_eq!(entry_high.flags, 0x880);
        assert!(entry_high.is_stable_global());

        // 临时隐私 IPv6 (flags 0x01)
        let line_temp = "2408820778cd1234a5d34199c03b1234 02 40 00 01 eth0";
        let entry_temp = parse_if_inet6_line(line_temp).expect("解析失败");
        assert!(entry_temp.is_temporary());
        assert!(!entry_temp.is_stable_global());

        // 废弃 IPv6 (flags 0x20)
        let line_dep = "2408820778cd1234b4c23100a12b5678 02 40 00 20 eth0";
        let entry_dep = parse_if_inet6_line(line_dep).expect("解析失败");
        assert!(entry_dep.is_deprecated());
        assert!(!entry_dep.is_stable_global());

        // DAD 探测中 IPv6 (flags 0x40)
        let line_tent = "2408820778cd12341111222233334444 02 40 00 40 eth0";
        let entry_tent = parse_if_inet6_line(line_tent).expect("解析失败");
        assert!(entry_tent.is_tentative_or_failed());
        assert!(!entry_tent.is_stable_global());

        // 链路本地 fe80:: (scope 0x20)
        let line_ll = "fe800000000000000200f8fffed144ff 02 40 20 80 eth0";
        let entry_ll = parse_if_inet6_line(line_ll).expect("解析失败");
        assert!(!entry_ll.is_global_scope());
        assert!(!entry_ll.is_stable_global());
    }

    #[test]
    fn test_parse_if_inet6_content_filtering() {
        let content = r#"
00000000000000000000000000000001 01 80 10 80       lo
2408820778cd12340200f8fffed144ff 02 40 00 80     eth0
2408820778cd1234a5d34199c03b1234 02 40 00 01     eth0
2408820778cd1234b4c23100a12b5678 02 40 00 20     eth0
fe800000000000000200f8fffed144ff 02 40 20 80     eth0
24098900123456780000000000000001 03 40 00 880    wlan0
"#;

        let entries_eth0 = parse_if_inet6_content(content, Some("eth0"));
        assert_eq!(entries_eth0.len(), 4);

        let stable_eth0: Vec<Ipv6Addr> = entries_eth0
            .iter()
            .filter(|e| e.is_stable_global())
            .map(|e| e.ip)
            .collect();
        assert_eq!(stable_eth0.len(), 1);
        assert_eq!(
            stable_eth0[0],
            Ipv6Addr::from_str("2408:8207:78cd:1234:200:f8ff:fed1:44ff").unwrap()
        );

        let entries_wlan0 = parse_if_inet6_content(content, Some("wlan0"));
        assert_eq!(entries_wlan0.len(), 1);
        assert_eq!(entries_wlan0[0].flags, 0x880);
        assert!(entries_wlan0[0].is_stable_global());
    }

    #[test]
    fn test_parse_if_inet6_line_non_ascii_safety() {
        // 构造刚好 32 字节但包含非 ASCII 字符的畸形串 (26 字节 ASCII + 2 个 3 字节 UTF-8 字符)
        let malformed_32_bytes = "12345678901234567890123456测试 02 40 00 80 eth0";
        assert_eq!(
            malformed_32_bytes.split_whitespace().next().unwrap().len(),
            32
        );
        assert!(parse_if_inet6_line(malformed_32_bytes).is_none());

        // 包含非法字符（非十六进制）
        let invalid_hex = "2408820778cd12340200f8fffed144zz 02 40 00 80 eth0";
        assert!(parse_if_inet6_line(invalid_hex).is_none());
    }
}

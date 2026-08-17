use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv4 正则提取器（匹配常见 IPv4 地址文本）
static IPV4_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}").expect("编译 IPv4 正则表达式失败")
});

/// 判断 IPv6 地址是否为全球可路由的单播地址 (Global Unicast Address)
/// 严格过滤掉：
/// - 未指定地址 (::)
/// - 回环地址 (::1)
/// - 链路本地地址 (Link-Local fe80::/10)
/// - 唯一本地私网地址 (ULA fc00::/7, fd00::/7)
/// - 多播地址 (ff00::/8)
/// - 文档与保留地址 (2001:db8::/32 等)
pub fn is_global_unicast_ipv6(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();

    // 排除未指定与回环
    if addr.is_unspecified() || addr.is_loopback() {
        return false;
    }

    // 排除多播 (ff00::/8)
    if addr.is_multicast() {
        return false;
    }

    // 排除链路本地 (fe80::/10)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }

    // 排除唯一本地地址 ULA (fc00::/7，涵盖 fc00:: - fdff::)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }

    // 排除 IPv4 映射/兼容地址 (::ffff:0:0/96)
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        return false;
    }

    // 排除文档与丢弃前缀 (2001:db8::/32, 100::/64)
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return false;
    }
    if segments[0] == 0x0100 {
        return false;
    }

    true
}

/// 判断 IPv4 是否为公网地址 (非私有/回环/链路本地/保留)
pub fn is_public_ipv4(addr: &Ipv4Addr) -> bool {
    !(addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified())
}

/// 从字符串文本中提取第一个合法的 IPv4 地址
pub fn extract_ipv4(text: &str, custom_regex: Option<&str>) -> Option<Ipv4Addr> {
    if let Some(pattern) = custom_regex {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(text) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                    if let Ok(ip) = m.as_str().trim().parse::<Ipv4Addr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    for mat in IPV4_REGEX.find_iter(text) {
        if let Ok(ip) = mat.as_str().trim().parse::<Ipv4Addr>() {
            return Some(ip);
        }
    }

    None
}

/// 从字符串文本中提取合法的 IPv6 地址
/// 若指定了 custom_regex 则优先使用自定义正则表达式筛选目标 IPv6
pub fn extract_ipv6(text: &str, custom_regex: Option<&str>) -> Option<Ipv6Addr> {
    if let Some(pattern) = custom_regex {
        if let Ok(re) = Regex::new(pattern) {
            for cap in re.captures_iter(text) {
                if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                    let cleaned = m.as_str().trim().trim_matches(|c| c == '[' || c == ']');
                    if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }

    // 默认按照空格/换行/逗号/JSON括号分词提取
    for word in text.split(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'' || c == '{' || c == '}' || c == '<' || c == '>') {
        let cleaned = word.trim().trim_matches(|c| c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}');
        if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
            return Some(ip);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv6_classification() {
        let global = Ipv6Addr::from_str("2408:8207:7880:1234::1").unwrap();
        assert!(is_global_unicast_ipv6(&global));

        let link_local = Ipv6Addr::from_str("fe80::1ff:fe00:1").unwrap();
        assert!(!is_global_unicast_ipv6(&link_local));

        let ula = Ipv6Addr::from_str("fd00::1").unwrap();
        assert!(!is_global_unicast_ipv6(&ula));

        let loopback = Ipv6Addr::from_str("::1").unwrap();
        assert!(!is_global_unicast_ipv6(&loopback));
    }

    #[test]
    fn test_extract_ipv4() {
        let sample = "当前客户端公网 IP 为: 114.114.114.114，请注意保存";
        assert_eq!(
            extract_ipv4(sample, None),
            Some(Ipv4Addr::new(114, 114, 114, 114))
        );
    }

    #[test]
    fn test_extract_ipv6() {
        let sample = "您的 IPv6: 2409:8a00:1234:5678:abcd:efff:0001:0002 欢迎使用";
        assert_eq!(
            extract_ipv6(sample, None),
            Some(Ipv6Addr::from_str("2409:8a00:1234:5678:abcd:efff:1:2").unwrap())
        );
    }
}

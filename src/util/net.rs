use parking_lot::RwLock;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 自定义正则编译缓存池，避免高频任务重复编译 DFA 状态机
static CUSTOM_REGEX_CACHE: std::sync::LazyLock<RwLock<HashMap<String, Option<Regex>>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

fn get_or_compile_regex(pattern: &str) -> Option<Regex> {
    if let Some(cached) = CUSTOM_REGEX_CACHE.read().get(pattern) {
        return cached.clone();
    }
    let compiled = Regex::new(pattern).ok();
    CUSTOM_REGEX_CACHE
        .write()
        .insert(pattern.to_string(), compiled.clone());
    compiled
}

/// IPv4 正则提取器（严谨匹配四段点分十进制 IPv4 地址文本）
static IPV4_REGEX: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    )
    .expect("编译 IPv4 正则表达式失败")
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

/// 判断 IP 是否属于私有局域网或本地回环 (包括 RFC1918 私网, 127.0.0.1, ::1, fe80::, fd00::)
pub fn is_private_or_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || !is_global_unicast_ipv6(v6),
    }
}

/// 从字符串文本中提取第一个合法的 IPv4 地址
pub fn extract_ipv4(text: &str, custom_regex: Option<&str>) -> Option<Ipv4Addr> {
    if let Some(pattern) = custom_regex
        && let Some(re) = get_or_compile_regex(pattern)
    {
        for cap in re.captures_iter(text) {
            if let Some(m) = cap.get(1).or_else(|| cap.get(0))
                && let Ok(ip) = m.as_str().trim().parse::<Ipv4Addr>()
            {
                return Some(ip);
            }
        }
        return None;
    }

    for mat in IPV4_REGEX.find_iter(text) {
        if let Ok(ip) = mat.as_str().trim().parse::<Ipv4Addr>() {
            return Some(ip);
        }
    }

    None
}

/// 从字符串文本中提取合法的 IPv6 地址
/// 若指定了 custom_regex 则使用自定义正则表达式筛选目标 IPv6 (不匹配则返回 None)
pub fn extract_ipv6(text: &str, custom_regex: Option<&str>) -> Option<Ipv6Addr> {
    if let Some(pattern) = custom_regex
        && let Some(re) = get_or_compile_regex(pattern)
    {
        for cap in re.captures_iter(text) {
            if let Some(m) = cap.get(1).or_else(|| cap.get(0)) {
                let cleaned = m.as_str().trim().trim_matches(|c| c == '[' || c == ']');
                if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
                    return Some(ip);
                }
            }
        }
        return None;
    }

    // 默认按照空格/换行/逗号/JSON括号分词提取
    for word in text.split(|c: char| {
        c.is_whitespace()
            || c == ','
            || c == '"'
            || c == '\''
            || c == '{'
            || c == '}'
            || c == '<'
            || c == '>'
    }) {
        let cleaned = word
            .trim()
            .trim_matches(|c| c == '[' || c == ']' || c == '(' || c == ')' || c == '{' || c == '}');
        if let Ok(ip) = cleaned.parse::<Ipv6Addr>() {
            return Some(ip);
        }
    }

    None
}

/// 判断 IPv6 是否为基于网卡硬件 MAC 地址生成的 EUI-64 稳定单播地址
pub fn is_eui64_ipv6(addr: &Ipv6Addr) -> bool {
    if !is_global_unicast_ipv6(addr) {
        return false;
    }
    let segments = addr.segments();
    (segments[5] & 0x00ff) == 0x00ff && (segments[6] & 0xff00) == 0xfe00
}

/// 在候选 IPv6 地址列表中智能优选最稳定的公网地址（优先 EUI-64 硬件地址和静态分配地址，避开临时隐私地址）
pub fn select_best_ipv6(candidates: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    let global_addrs: Vec<&Ipv6Addr> = candidates
        .iter()
        .filter(|ip| is_global_unicast_ipv6(ip))
        .collect();

    if global_addrs.is_empty() {
        return None;
    }

    // 1. 优先查找具有 EUI-64 硬件特征的长期稳定 IPv6
    if let Some(&eui64_ip) = global_addrs.iter().find(|&&ip| is_eui64_ipv6(ip)) {
        return Some(*eui64_ip);
    }

    // 2. 其次查找具有静态分配特征的 IPv6 (后64位为小数值/短后缀如 ::1, ::10 等)
    if let Some(&static_ip) = global_addrs.iter().find(|&&ip| {
        let segs = ip.segments();
        segs[4] == 0 && segs[5] == 0 && segs[6] == 0
    }) {
        return Some(*static_ip);
    }

    // 3. 兜底返回第一个全球单播 IPv6
    Some(*global_addrs[0])
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
    fn test_select_best_ipv6_prefers_eui64() {
        // 临时随机公网 IPv6
        let temp_ip = Ipv6Addr::from_str("240e:390:800:100:a1b2:c3d4:e5f6:7890").unwrap();
        // 基于网卡 MAC 生成的稳定 EUI-64 IPv6
        let stable_eui64 = Ipv6Addr::from_str("240e:390:800:100:21a:2bff:fe3c:4d5e").unwrap();

        let addrs = vec![temp_ip, stable_eui64];
        // 尽管 temp_ip 排在第一个，智能选优策略仍能精准挑选出稳定 EUI-64 IPv6
        assert_eq!(select_best_ipv6(&addrs), Some(stable_eui64));
    }

    #[test]
    fn test_extract_ipv4() {
        let sample = "当前客户端公网 IP 为: 114.114.114.114，请注意保存";
        assert_eq!(
            extract_ipv4(sample, None),
            Some(Ipv4Addr::new(114, 114, 114, 114))
        );

        // 包含长数字串、版本号干扰时，依然精准匹配真实 IPv4
        let noisy = "error_id=12345678, code=999999, ip: 223.5.5.5, ver=1.2.3.4";
        assert_eq!(extract_ipv4(noisy, None), Some(Ipv4Addr::new(223, 5, 5, 5)));
    }

    #[test]
    fn test_extract_ipv6() {
        let sample = "您的 IPv6: 2409:8a00:1234:5678:abcd:efff:0001:0002 欢迎使用";
        assert_eq!(
            extract_ipv6(sample, None),
            Some(Ipv6Addr::from_str("2409:8a00:1234:5678:abcd:efff:1:2").unwrap())
        );
    }

    #[test]
    fn test_is_private_or_loopback() {
        assert!(is_private_or_loopback(
            &IpAddr::from_str("127.0.0.1").unwrap()
        ));
        assert!(is_private_or_loopback(
            &IpAddr::from_str("192.168.1.100").unwrap()
        ));
        assert!(is_private_or_loopback(
            &IpAddr::from_str("10.0.0.1").unwrap()
        ));
        assert!(is_private_or_loopback(
            &IpAddr::from_str("172.16.0.1").unwrap()
        ));
        assert!(is_private_or_loopback(&IpAddr::from_str("::1").unwrap()));
        assert!(is_private_or_loopback(
            &IpAddr::from_str("fe80::1").unwrap()
        ));

        // 公网 IP
        assert!(!is_private_or_loopback(
            &IpAddr::from_str("114.114.114.114").unwrap()
        ));
        assert!(!is_private_or_loopback(
            &IpAddr::from_str("240e:390:800:100::1").unwrap()
        ));
    }
}

//! 网络工具与 IP 提取算法单元测试

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

    // 6to4, Teredo, NAT64 排除验证
    let six_to_four = Ipv6Addr::from_str("2002:c000:201::1").unwrap();
    let teredo = Ipv6Addr::from_str("2001:0000:4136:e378:8000:63bf:3fff:fdd2").unwrap();
    let nat64 = Ipv6Addr::from_str("64:ff9b::192.0.2.33").unwrap();
    assert!(!is_global_unicast_ipv6(&six_to_four));
    assert!(!is_global_unicast_ipv6(&teredo));
    assert!(!is_global_unicast_ipv6(&nat64));
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

#[test]
fn test_is_public_and_cgnat_ipv4() {
    // CGNAT (100.64.0.0/10) 不应被判定为公网 IP
    let cgnat1 = Ipv4Addr::from_str("100.64.0.1").unwrap();
    let cgnat2 = Ipv4Addr::from_str("100.127.255.254").unwrap();
    assert!(is_cgnat_ipv4(&cgnat1));
    assert!(is_cgnat_ipv4(&cgnat2));
    assert!(!is_public_ipv4(&cgnat1));
    assert!(!is_public_ipv4(&cgnat2));

    // 邻近边界公网 IP
    let public1 = Ipv4Addr::from_str("100.63.255.255").unwrap();
    let public2 = Ipv4Addr::from_str("100.128.0.1").unwrap();
    assert!(!is_cgnat_ipv4(&public1));
    assert!(!is_cgnat_ipv4(&public2));
    assert!(is_public_ipv4(&public1));
    assert!(is_public_ipv4(&public2));

    // 保留段 RFC 6890 / RFC 7526 排除验证
    let ietf_reserved = Ipv4Addr::from_str("192.0.0.1").unwrap();
    let relay_6to4 = Ipv4Addr::from_str("192.88.99.1").unwrap();
    assert!(!is_public_ipv4(&ietf_reserved));
    assert!(!is_public_ipv4(&relay_6to4));
}

#[tokio::test]
async fn test_validate_safe_url_endpoint_ssrf_protection() {
    // 1. 允许合法公网地址
    assert!(
        validate_safe_url_endpoint("https://api.ipify.org")
            .await
            .is_ok()
    );
    assert!(
        validate_safe_url_endpoint("http://114.114.114.114/ip")
            .await
            .is_ok()
    );

    // 2. 拦截私有 IP / 回环 / 云元数据字面量
    assert!(
        validate_safe_url_endpoint("http://127.0.0.1:8080")
            .await
            .is_err()
    );
    assert!(validate_safe_url_endpoint("http://10.0.0.1").await.is_err());
    assert!(
        validate_safe_url_endpoint("http://192.168.1.1")
            .await
            .is_err()
    );
    assert!(
        validate_safe_url_endpoint("http://172.16.0.1")
            .await
            .is_err()
    );
    assert!(
        validate_safe_url_endpoint("http://169.254.169.254/latest/meta-data")
            .await
            .is_err()
    );
    assert!(validate_safe_url_endpoint("http://[::1]:80").await.is_err());

    // 3. 拦截 localhost 及内部保留域名
    assert!(
        validate_safe_url_endpoint("http://localhost:8080/test")
            .await
            .is_err()
    );
    assert!(
        validate_safe_url_endpoint("http://service.local/api")
            .await
            .is_err()
    );
    assert!(
        validate_safe_url_endpoint("http://k8s.internal/secret")
            .await
            .is_err()
    );

    // 4. 拦截协议非法
    assert!(
        validate_safe_url_endpoint("ftp://example.com")
            .await
            .is_err()
    );
    assert!(
        validate_safe_url_endpoint("file:///etc/passwd")
            .await
            .is_err()
    );
}

#[test]
fn test_custom_regex_pattern_len_limit() {
    // 正常长度正则应成功编译
    let normal = r"ip:\s*([0-9.]+)";
    assert!(get_or_compile_regex(normal).is_some());

    // 空正则返回 None
    assert!(get_or_compile_regex("").is_none());

    // 超过 1024 字符的异常超长正则直接拒绝返回 None
    let oversized = "a".repeat(1025);
    assert!(get_or_compile_regex(&oversized).is_none());
}

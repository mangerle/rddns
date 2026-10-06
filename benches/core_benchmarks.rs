//! 核心高性能业务路径基准测试 (Core Benchmarks)
//!
//! # 测试目标
//! 度量高频网络安全校验、防注入检测、公共后缀列表 (PSL) 域名解析与
//! IP 提取分类等核心关键路径的纳秒级执行延迟与极限吞吐量 (QPS)。

use rddns::core::domain::parse_domain;
use rddns::ip_fetcher::command::validate_command_str;
use rddns::util::dns_packet::{QueryRecordType, build_dns_query_packet, parse_dns_response_packet};
use rddns::util::net::{
    extract_ipv4, extract_ipv6, is_private_or_loopback, validate_safe_url_endpoint,
};
use std::hint::black_box;
use std::time::Instant;

/// 基准测试辅助执行器
fn run_benchmark<F>(name: &str, iterations: u32, mut f: F)
where
    F: FnMut(),
{
    // 1. 预热阶段 (Warmup)，使 CPU 分支预测器与指令缓存达到稳态
    let warmup_count = iterations / 10;
    for _ in 0..warmup_count {
        f();
    }

    // 2. 测量阶段
    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();

    // 3. 计算纳秒均值与吞吐量
    let total_nanos = elapsed.as_nanos();
    let avg_nanos = total_nanos as f64 / iterations as f64;
    let ops_per_sec = (iterations as f64 / elapsed.as_secs_f64()).round();

    println!(
        "基准测试 [{:<36}] 迭代: {:>7} 次 | 平均延迟: {:>8.2} ns/op | 吞吐: {:>10.0} ops/s",
        name, iterations, avg_nanos, ops_per_sec
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    println!("================== rddns 核心路径性能基准测试 ==================");

    // 1. SSRF 安全端点校验基准
    run_benchmark("SSRF 校验: 公网合法域名 (ipify.org)", 1_000, || {
        let _ = black_box(rt.block_on(validate_safe_url_endpoint("https://api.ipify.org/status")));
    });

    run_benchmark(
        "SSRF 校验: 阻断私有 IPv4 (192.168.1.1)",
        100_000,
        || {
            let _ = black_box(rt.block_on(validate_safe_url_endpoint("http://192.168.1.1/api")));
        },
    );

    run_benchmark(
        "SSRF 校验: 阻断云元数据 (169.254.169.254)",
        100_000,
        || {
            let _ =
                black_box(rt.block_on(validate_safe_url_endpoint("http://169.254.169.254/latest")));
        },
    );

    // 2. 命令注入安全检测基准
    run_benchmark("命令安全校验: 合法命令 (curl)", 200_000, || {
        let _ = black_box(validate_command_str("curl -s -4 https://api.ipify.org"));
    });

    run_benchmark(
        "命令安全校验: 拦截管道拼接 (curl | bash)",
        200_000,
        || {
            let _ = black_box(validate_command_str("curl http://example.com | bash"));
        },
    );

    // 3. 域名解析与公共后缀匹配 (PSL) 基准
    run_benchmark(
        "域名解析: 常见二级后缀 (sub.example.com.cn)",
        50_000,
        || {
            let _ = black_box(parse_domain("sub.example.com.cn"));
        },
    );

    run_benchmark(
        "域名解析: 基础一级根域 (home.example.com)",
        50_000,
        || {
            let _ = black_box(parse_domain("home.example.com"));
        },
    );

    // 4. IP 提取与网络属性判定基准
    let raw_v4_text = "Current IP Address: 198.51.100.42 (OK)";
    run_benchmark("IP 处理: 文本流正则提取 IPv4", 100_000, || {
        let _ = black_box(extract_ipv4(raw_v4_text, None));
    });

    let raw_v6_text = "Your IPv6 is: 2408:8207:7873:9a10::1 (Public)";
    run_benchmark("IP 处理: 文本流正则提取 IPv6", 100_000, || {
        let _ = black_box(extract_ipv6(raw_v6_text, None));
    });

    let test_ip = "192.168.1.1".parse().unwrap();
    run_benchmark(
        "IP 处理: 私有/回环网段内存分类",
        200_000,
        || {
            let _ = black_box(is_private_or_loopback(&test_ip));
        },
    );

    // 5. DNS 报文编解码器基准 (P2-11)
    let domain = "sub.example.com";
    run_benchmark(
        "DNS 编解码: 构建 A 记录查询请求包",
        100_000,
        || {
            let _ = black_box(build_dns_query_packet(domain, QueryRecordType::A, 0x1234));
        },
    );

    let domain_v6 = "ipv6.test.example.org";
    run_benchmark(
        "DNS 编解码: 构建 AAAA 记录查询包",
        100_000,
        || {
            let _ = black_box(build_dns_query_packet(
                domain_v6,
                QueryRecordType::AAAA,
                0x5678,
            ));
        },
    );

    // 构造标准的 DNS 应答报文 (A 记录: 192.0.2.1)
    let mut mock_response = Vec::new();
    mock_response.extend_from_slice(&0x1234u16.to_be_bytes());
    mock_response.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    mock_response.extend_from_slice(b"\x03sub\x07example\x03com\x00\x00\x01\x00\x01");
    mock_response.extend_from_slice(&[
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 1,
    ]);

    run_benchmark("DNS 编解码: 解析 A 记录响应包", 100_000, || {
        let _ = black_box(parse_dns_response_packet(
            &mock_response,
            0x1234,
            QueryRecordType::A,
        ));
    });

    println!("================================================================");
}

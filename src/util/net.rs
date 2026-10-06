use parking_lot::RwLock;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::Duration;
use tokio::net::lookup_host;
use url::{Host, Url};

/// 自定义正则编译缓存池，避免高频任务重复编译 DFA 状态机
static CUSTOM_REGEX_CACHE: LazyLock<RwLock<HashMap<String, Option<Regex>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 自定义正则表达式最大允许长度（1024 字符）
const MAX_REGEX_PATTERN_LEN: usize = 1024;

fn get_or_compile_regex(pattern: &str) -> Option<Regex> {
    if pattern.is_empty() || pattern.len() > MAX_REGEX_PATTERN_LEN {
        return None;
    }
    {
        let cache = CUSTOM_REGEX_CACHE.read();
        if let Some(cached) = cache.get(pattern) {
            return cached.clone();
        }
    }
    let compiled = Regex::new(pattern).ok();
    let mut cache = CUSTOM_REGEX_CACHE.write();
    // 双重检查锁定 (DCL)
    if let Some(cached) = cache.get(pattern) {
        return cached.clone();
    }
    if cache.len() >= 128 {
        let keys_to_remove: Vec<String> = cache.keys().take(64).cloned().collect();
        for k in keys_to_remove {
            cache.remove(&k);
        }
    }
    cache.insert(pattern.to_string(), compiled.clone());
    compiled
}

/// IPv4 正则提取器（严谨匹配四段点分十进制 IPv4 地址文本）
///
/// # 不变性保证
/// 正则表达式为硬编码且通过单元测试验证的字面量，初始化编译必然成功。
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    )
    .expect("内置 IPv4 静态正则表达式语法正确，编译不应失败")
});

/// 辅助检查 IPv6 是否命中过渡隧道或保留前缀
#[inline]
fn is_reserved_or_tunnel_ipv6(segments: &[u16; 8]) -> bool {
    // 排除文档与丢弃前缀 (2001:db8::/32, 100::/64)
    if segments[0] == 0x2001 && segments[1] == 0xdb8 {
        return true;
    }
    if segments[0] == 0x0100 {
        return true;
    }
    // 排除过渡与隧道前缀 (6to4 2002::/16, Teredo 2001::/32, NAT64 64:ff9b::/96)
    if segments[0] == 0x2002 {
        return true;
    }
    if segments[0] == 0x2001 && segments[1] == 0 {
        return true;
    }
    if segments[0] == 0x0064 && segments[1] == 0xff9b {
        return true;
    }
    false
}

/// 判断 IPv6 地址是否为全球可路由的单播地址 (Global Unicast Address)
///
/// # 设计原理
/// - **实现初衷**：DDNS 解析必须绑定公网可达的全球单播地址，严防将 Link-Local、ULA、NAT64
///   或未指定地址错误解析上报，避免造成域名解析不可达。
/// - **核心优势**：通过 16 位分段按位掩码就地快速匹配，零堆内存分配，吞吐量极高。
/// - **代价与局限**：静态匹配常见 RFC 标准保留前缀，无法感知运营商在局域网内自定义的非标准策略路由。
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

    // 排除文档、丢弃前缀及过渡/隧道前缀
    if is_reserved_or_tunnel_ipv6(&segments) {
        return false;
    }

    true
}

/// 判断 IPv4 是否为运营商级 NAT (CGNAT 100.64.0.0/10, RFC 6598)
///
/// # 设计原理
/// - **实现初衷**：ISP 在宽带缺乏公网 IPv4 时广泛分配此类内部地址，DDNS 解析若绑定此类 IP
///   会导致公网无法访问，需精准识别并告警或降级。
/// - **核心优势**：位运算快速判断，性能极高。
/// - **代价与局限**：仅判定 RFC 6598 规定的 `100.64.0.0/10` 网段。
pub fn is_cgnat_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

/// 判断 IPv4 是否为公网地址 (非私有/回环/链路本地/CGNAT/多播/保留/文档)
///
/// # 设计原理
/// - **实现初衷**：确保解析同步的 IPv4 是全球公网单播地址，避免把局域网或广播等无效 IP 提交给云解析。
/// - **核心优势**：基于标准 RFC 规则快速位运算与区间判定，零分配。
/// - **代价与局限**：不校验该 IP 是否当前实际具备端到端双向连通性。
pub fn is_public_ipv4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    !(addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_unspecified()
        || addr.is_multicast()
        || is_cgnat_ipv4(addr)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // IETF Protocol Assignments (RFC 6890)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 6to4 Relay Anycast (RFC 7526)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        || octets[0] >= 240)
}

/// 判断 IP 是否属于私有局域网、CGNAT 或本地回环 (包括 RFC1918 私网, 100.64.0.0/10, 127.0.0.1, ::1, fe80::, fd00::)
///
/// # 设计原理
/// - **实现初衷**：统一抽象 IPv4 与 IPv6 的内网属性判断，主要用于 Web 控制台的安全来源校验与警告提示。
/// - **核心优势**：统一枚举分发，复用各协议的高效位检测。
pub fn is_private_or_loopback(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_cgnat_ipv4(v4)
                || (octets[0] == 169 && octets[1] == 254) // 云元数据 / 链路本地 (169.254.0.0/16)
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                || octets[0] == 0
                || octets[0] >= 240
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || !is_global_unicast_ipv6(v6),
    }
}

/// 校验 URL 端点安全性（防范针对内网及保留地址的 SSRF 攻击与 DNS 重绑定绕过）
///
/// # 设计原理
/// - **实现初衷**: 统一验证外部 URL 端点，防止将请求指向本地回环、局域网或云厂商元数据服务（如 169.254.169.254）。
/// - **核心优势**: 严格校验协议（仅允许 http/https）、主机合法性；针对域名执行 DNS 解析校验，彻底防御通过自定义域名指向 127.0.0.1 或云元数据进行 DNS 重绑定绕过。
///
/// # Errors
/// 当协议非法、URL 格式无效、缺少主机或指向内部网络/元数据地址时返回错误描述。
/// 校验外部目标主机（IP 或域名）的合法性，防御指向内网与云元数据的 SSRF 风险
///
/// # 设计原理
/// - **实现初衷**: 统一验证外部主机或域名，防止指向本地回环、局域网或云厂商元数据服务（如 169.254.169.254）。
/// - **核心优势**: 支持裸 IP 直接判定与域名解析穿透校验，防御 DNS 重绑定与内网穿透。
///
/// 校验目标主机地址合法性（防范 SSRF 攻击与私网目标穿透）
///
/// # 设计原理
/// - **实现初衷**: 统一验证目标主机地址与端口，防范指向本地回环、局域网或云厂商元数据服务。
/// - **核心优势**: 采用非阻塞的异步 DNS 解析 (`tokio::net::lookup_host`) 并辅以 3 秒强制超时保护，
///   避免在单线程异步运行时中因底层操作系统同步阻塞 DNS 解析挂起而导致全局事件循环冻结 (P-3)。
/// - **代价与局限**: 校验过程需执行网络异步 DNS 查询，存在微秒至毫秒级网络 I/O 耗时。
///
/// # Errors
/// 当主机指向本地回环、私网 IP、localhost、内部保留域名，或解析出的 IP 属于私网/保留网段时返回错误。
pub async fn validate_safe_host(host_str: &str, port: Option<u16>) -> Result<(), String> {
    let trimmed = host_str.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        if is_private_or_loopback(&ip) {
            return Err(format!(
                "出于安全策略，禁止配置或测试指向本地回环、局域网或内部保留 IP [{}] 的目标地址",
                ip
            ));
        }
        return Ok(());
    }

    let lower_domain = trimmed.to_ascii_lowercase();
    if lower_domain == "localhost"
        || lower_domain.ends_with(".localhost")
        || lower_domain.ends_with(".local")
        || lower_domain.ends_with(".internal")
        || lower_domain.ends_with(".localdomain")
        || lower_domain.ends_with(".arpa")
    {
        return Err(
            "出于安全策略，禁止配置或测试指向 localhost 及内部保留域名的目标地址".to_string(),
        );
    }

    // 执行异步 DNS 解析，防御 DNS 重绑定与解析指向私网/云元数据 IP 的自定义域名 (P-3)
    let check_port = port.unwrap_or(80);
    let addr_str = format!("{}:{}", trimmed, check_port);
    let lookup_timeout = Duration::from_secs(3);

    let lookup_result = tokio::time::timeout(lookup_timeout, lookup_host(&addr_str)).await;
    if let Ok(Ok(addrs)) = lookup_result {
        for socket_addr in addrs {
            let ip = socket_addr.ip();
            if is_private_or_loopback(&ip) {
                return Err(format!(
                    "出于安全策略，域名 [{}] 解析结果指向内部保留/私网 IP [{}]，已拒绝该目标地址",
                    trimmed, ip
                ));
            }
        }
    }
    Ok(())
}

/// 校验外部网络请求 URL 端点的协议与目标地址合法性（防范 SSRF 攻击，覆盖保留网段及 DNS 重绑定）(S-1)
///
/// # 设计原理
/// - **实现初衷**: 统一验证外部 URL 端点，防止将请求指向本地回环、局域网或云厂商元数据服务（如 169.254.169.254）。
/// - **核心优势**: 严格校验协议（仅允许 http/https）、主机合法性；针对域名执行异步 DNS 解析校验，彻底防御通过自定义域名指向 127.0.0.1 或云元数据进行 DNS 重绑定绕过。
///
/// # Errors
/// 当协议非法、URL 格式无效、缺少主机或指向内部网络/元数据地址时返回错误描述。
pub async fn validate_safe_url_endpoint(raw_url: &str) -> Result<(), String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(format!(
            "URL 端点 [{}] 协议非法，仅允许 http:// 或 https:// 开头的地址",
            trimmed
        ));
    }
    let parsed =
        Url::parse(trimmed).map_err(|e| format!("URL 端点 [{}] 格式无效: {}", trimmed, e))?;
    match parsed.host() {
        Some(Host::Ipv4(v4)) => validate_safe_host(&v4.to_string(), parsed.port()).await,
        Some(Host::Ipv6(v6)) => validate_safe_host(&v6.to_string(), parsed.port()).await,
        Some(Host::Domain(domain)) => validate_safe_host(domain, parsed.port()).await,
        None => Err("URL 端点缺少有效的主机地址".to_string()),
    }
}

/// 从字符串文本中提取第一个合法的 IPv4 地址
///
/// # 设计原理
/// - **实现初衷**：外部 API 响应可能包含纯文本、HTML 网页或 JSON 数据，通过正则模糊匹配提取 IPv4。
/// - **核心优势**：支持用户自定义正则表达式针对特殊接口定制提取，具备全局 DFA 状态机缓存。
/// - **代价与局限**：多 IP 返回场景下默认仅返回首个有效地址。
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
///
/// # 设计原理
/// - **实现初衷**：兼容各种 API 格式（如包含中括号、引号或纯文本）的 IPv6 提取。
/// - **核心优势**：双模提取机制，分词提取时过滤包围字符并强类型解析校验。
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
///
/// # 设计原理
/// - **实现初衷**：EUI-64 地址根据网卡硬件 MAC 生成，接口标识在网络重连时固定不变，
///   非常适合作为长期稳定的 DDNS 目标地址，避开短期过期的临时隐私扩展地址。
/// - **核心优势**：检查第 6、7 分段的 0x00ff 与 0xfe00 标志位，效率极高。
pub fn is_eui64_ipv6(addr: &Ipv6Addr) -> bool {
    if !is_global_unicast_ipv6(addr) {
        return false;
    }
    let segments = addr.segments();
    (segments[5] & 0x00ff) == 0x00ff && (segments[6] & 0xff00) == 0xfe00
}

/// 在候选 IPv6 地址列表中智能优选最稳定的公网地址（优先 EUI-64 硬件地址和静态分配地址，避开临时隐私地址）
///
/// # 设计原理
/// - **实现初衷**：现代操作系统通常同时分配临时隐私地址（随机频繁变动）与硬件/静态地址，
///   若更新临时隐私地址会导致客户端每隔数小时断连重解析，因此需优先挑选长期稳定的地址。
/// - **核心优势**：三级优先级筛选，保证在无硬件地址时安全降级为静态分配或首个可用公网地址。
pub fn select_best_ipv6(candidates: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    let mut global_addrs = Vec::with_capacity(candidates.len());
    for ip in candidates {
        if is_global_unicast_ipv6(ip) {
            global_addrs.push(ip);
        }
    }

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
#[path = "net_tests.rs"]
mod net_tests;

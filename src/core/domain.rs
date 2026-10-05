use idna::domain_to_ascii;
use log::warn;
use psl::Psl;
use std::collections::HashMap;
use std::str::from_utf8;
use url::form_urlencoded;

/// 解析后的单个域名实体
///
/// # 设计原理
/// - **实现初衷**: 标准化用户在配置文件或 Web UI 中填写的各类异构域名格式（标准 FQDN、URL 复制粘贴、中文 Punycode、显式指定 `sub:root` 以及带查询参数的扩展语法），为 DNS 提供商驱动提供确定的主从域名结构。
/// - **核心优势**: 基于官方 Public Suffix List (PSL) 准确识别多级公共后缀（如 `.com.cn`, `.co.uk`），避免因简单切分导致根域名误判；同时兼容各种人性化输入容错。
/// - **代价与局限**: 依赖内置 PSL 静态规则库，新增或极其小众的特殊国别后缀需定期随 crate 升级维护。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomain {
    /// 原始用户输入字符串
    pub raw: String,
    /// 根域名 (例如 "example.com")
    pub root_domain: String,
    /// 子域名前缀 (例如 "www", "@", "sub.dev")
    pub sub_domain: String,
    /// 自定义 URL 查询参数 (如 "line=telecom&weight=10")
    pub custom_params: HashMap<String, String>,
}

impl ParsedDomain {
    /// 格式化为完整 FQDN 域名（如 "www.example.com" 或 "example.com"）
    pub fn full_domain(&self) -> String {
        if self.sub_domain.is_empty() || self.sub_domain == "@" {
            self.root_domain.clone()
        } else {
            format!("{}.{}", self.sub_domain, self.root_domain)
        }
    }

    /// 获取服务商子域名标识（如果为空或根域名则返回 "@"）
    pub fn sub_domain_or_at(&self) -> &str {
        if self.sub_domain.is_empty() || self.sub_domain == "@" {
            "@"
        } else {
            &self.sub_domain
        }
    }

    /// 校验给定的云端记录名是否与当前域名匹配（自动处理末尾点、大小写与 @ 根域）
    pub fn matches_record_name(&self, record_name: &str) -> bool {
        let clean_rec = record_name.trim_end_matches('.');
        let full = self.full_domain();
        clean_rec.eq_ignore_ascii_case(full.trim_end_matches('.'))
            || clean_rec.eq_ignore_ascii_case(self.sub_domain_or_at().trim_end_matches('.'))
    }
}

/// 将域名字符串转换为 ASCII Punycode 格式（针对中文等多语言 IDN 域名）
fn to_ascii_domain(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if !lower.is_ascii() {
        domain_to_ascii(&lower).unwrap_or(lower)
    } else {
        lower
    }
}

/// 清洗输入的 URL 文本并提取查询参数
fn clean_url_and_extract_params(raw_input: &str) -> Option<(&str, HashMap<String, String>)> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    let no_protocol = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };

    let (domain_and_path, query_part) = match no_protocol.split_once('?') {
        Some((d, q)) => (d.trim(), Some(q.trim())),
        None => (no_protocol.trim(), None),
    };

    let domain_raw = domain_and_path.split('/').next().unwrap_or("").trim();
    if domain_raw.is_empty() {
        return None;
    }

    let mut custom_params = HashMap::new();
    if let Some(query) = query_part {
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            custom_params.insert(k.to_string(), v.to_string());
        }
    }

    Some((domain_raw, custom_params))
}

/// 解析显式冒号语法 "sub:root.com"
fn parse_explicit_sub_root(domain_raw: &str) -> (Option<&str>, Option<(&str, &str)>) {
    if let Some((left, right)) = domain_raw.split_once(':') {
        if right.parse::<u16>().is_ok() {
            // 右侧为端口号，剥离端口后保留左侧作为真实域名
            (Some(left.trim()), None)
        } else {
            (None, Some((left, right)))
        }
    } else {
        (Some(domain_raw), None)
    }
}

/// 使用标准 Public Suffix List (PSL) 拆分根域名与子域名
fn split_sub_and_root_by_psl(domain_ascii: &str) -> (String, String) {
    if let Some(domain) = psl::List.domain(domain_ascii.as_bytes()) {
        let root_str = from_utf8(domain.as_bytes()).unwrap_or(domain_ascii);
        if root_str == domain_ascii {
            ("@".to_string(), root_str.to_string())
        } else if let Some(prefix) = domain_ascii.strip_suffix(root_str) {
            let sub = prefix.trim_end_matches('.');
            (
                if sub.is_empty() {
                    "@".to_string()
                } else {
                    sub.to_string()
                },
                root_str.to_string(),
            )
        } else {
            ("@".to_string(), root_str.to_string())
        }
    } else {
        let parts: Vec<&str> = domain_ascii.split('.').collect();
        if parts.len() < 2 {
            ("@".to_string(), domain_ascii.to_string())
        } else {
            let sub = parts[..parts.len() - 2].join(".");
            let root = parts[parts.len() - 2..].join(".");
            (if sub.is_empty() { "@".to_string() } else { sub }, root)
        }
    }
}

/// 校验子域名是否包含非法或破坏性字符（防路径穿越与 URL 注入）
///
/// # 设计原理
/// - **实现初衷**: 许多 DNS 服务商的 API 直接将子域名拼接入请求 URL 路径或 Query 参数中。
///   若子域名包含 `../`、`/`、`?`、`#`、`&` 等破坏性字符，将导致路径穿越或参数污染 (P1-13)。
/// - **核心优势**: 严格校验子域名字符集，只允许字母、数字、连字符 `-`、下划线 `_`、点号 `.`，以及特殊的 `@` 与 `*`。
fn is_valid_sub_domain(sub: &str) -> bool {
    if sub.is_empty() {
        return false;
    }
    if sub == "@" || sub == "*" {
        return true;
    }
    // 禁止以点号开头或结尾，禁止连续点号（防 .. 路径穿越）
    if sub.starts_with('.') || sub.ends_with('.') || sub.contains("..") {
        return false;
    }
    // 逐字符白名单校验：只能由 a-z, A-Z, 0-9, '-', '_', '.' 构成，严禁包含 / \ ? # & 等
    sub.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// 校验根域名格式合法性
fn is_valid_root_domain(root: &str) -> bool {
    if root.is_empty()
        || !root.contains('.')
        || root.starts_with('.')
        || root.ends_with('.')
        || root.contains("..")
    {
        return false;
    }
    root.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// 解析用户配置的单个域名字符串
///
/// # 设计原理
/// - **支持格式**:
///   - `example.com` -> sub: `@`, root: `example.com`
///   - `www.example.com` -> sub: `www`, root: `example.com`
///   - `*.example.com` -> sub: `*`, root: `example.com`
///   - `sub:example.com` -> sub: `sub`, root: `example.com`
///   - `https://www.example.com:8080/path` -> 自动剥离协议与端口
///   - `sub:example.com?line=telecom` -> 提取扩展参数
pub fn parse_domain(raw_input: &str) -> Option<ParsedDomain> {
    let (domain_raw, custom_params) = clean_url_and_extract_params(raw_input)?;
    if domain_raw.contains("..") {
        return None;
    }
    let (cleaned_domain_opt, explicit_sub_root) = parse_explicit_sub_root(domain_raw);

    if let Some((sub, root)) = explicit_sub_root {
        let root_ascii = to_ascii_domain(root);
        let sub_trimmed = sub.trim();
        let sub_ascii = if sub_trimmed.is_empty() || sub_trimmed == "@" {
            "@".to_string()
        } else if sub_trimmed == "*" {
            "*".to_string()
        } else {
            to_ascii_domain(sub_trimmed)
        };
        if !is_valid_sub_domain(&sub_ascii) || !is_valid_root_domain(&root_ascii) {
            return None;
        }
        return Some(ParsedDomain {
            raw: raw_input.to_string(),
            root_domain: root_ascii,
            sub_domain: sub_ascii,
            custom_params,
        });
    }

    let domain_ascii = to_ascii_domain(cleaned_domain_opt.unwrap_or(domain_raw));
    if domain_ascii.split('.').count() < 2 {
        return None;
    }

    let (sub_domain, root_domain) = split_sub_and_root_by_psl(&domain_ascii);
    if !is_valid_sub_domain(&sub_domain) || !is_valid_root_domain(&root_domain) {
        return None;
    }

    Some(ParsedDomain {
        raw: raw_input.to_string(),
        root_domain,
        sub_domain,
        custom_params,
    })
}

/// 批量解析域名列表，同时收集格式非法的域名条目作为同步失败记录
///
/// # 设计原理
/// - **实现初衷**: 当用户配置的域名存在语法错误或根域名解析失败时，显式生成失败记录汇入同步结果。
/// - **核心优势**: 杜绝配置错误域名被静默忽略导致引擎判定为全绿健康（P1-17 缺陷）。
pub fn parse_domain_list_with_invalid(
    raw_list: &[String],
    record_type: crate::dns::trait_def::DnsRecordType,
) -> (
    Vec<ParsedDomain>,
    Vec<crate::dns::trait_def::SyncRecordResult>,
) {
    let mut parsed = Vec::with_capacity(raw_list.len());
    let mut invalid = Vec::new();
    for raw in raw_list {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match parse_domain(trimmed) {
            Some(domain) => parsed.push(domain),
            None => {
                warn!(
                    "配置的域名 [{}] 格式非法或无法识别根域名，已被跳过，请检查任务域名配置",
                    raw
                );
                invalid.push(crate::dns::trait_def::SyncRecordResult::failed(
                    raw.to_string(),
                    record_type,
                    "未知/解析失败",
                    "域名格式非法或无法识别有效根域名",
                ));
            }
        }
    }
    (parsed, invalid)
}

/// 批量解析域名列表
///
/// 遇到格式非法或无法识别根域名的输入时，打印警告日志提醒用户核对配置，并安全跳过该项。
pub fn parse_domain_list(raw_list: &[String]) -> Vec<ParsedDomain> {
    let mut parsed = Vec::with_capacity(raw_list.len());
    for raw in raw_list {
        match parse_domain(raw) {
            Some(domain) => parsed.push(domain),
            None => {
                warn!(
                    "配置的域名 [{}] 格式非法或无法识别根域名，已被跳过，请检查任务域名配置",
                    raw
                );
            }
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_domain_with_url_prefix_and_slash() {
        // 自动剔除 https:// 和 尾部斜杠
        let d1 = parse_domain("https://nas.example.com/").unwrap();
        assert_eq!(d1.sub_domain, "nas");
        assert_eq!(d1.root_domain, "example.com");

        // 自动小写化与大写混合
        let d2 = parse_domain("HTTP://WWW.EXAMPLE.COM/PATH").unwrap();
        assert_eq!(d2.sub_domain, "www");
        assert_eq!(d2.root_domain, "example.com");

        // 泛域名支持
        let d3 = parse_domain("*.example.com").unwrap();
        assert_eq!(d3.sub_domain, "*");
        assert_eq!(d3.root_domain, "example.com");

        // 带端口的 URL 自动剥离端口 (不会与 sub:root 冒号语法混淆)
        let d4 = parse_domain("http://nas.example.com:8080/dashboard").unwrap();
        assert_eq!(d4.sub_domain, "nas");
        assert_eq!(d4.root_domain, "example.com");

        // 注释行自动过滤
        assert!(parse_domain("# 这是一行注释").is_none());
        assert!(parse_domain("// 另一行注释").is_none());
    }

    #[test]
    fn test_parse_domain_standard() {
        let d1 = parse_domain("example.com").unwrap();
        assert_eq!(d1.root_domain, "example.com");
        assert_eq!(d1.sub_domain, "@");
        assert_eq!(d1.full_domain(), "example.com");

        let d2 = parse_domain("www.example.com").unwrap();
        assert_eq!(d2.root_domain, "example.com");
        assert_eq!(d2.sub_domain, "www");
        assert_eq!(d2.full_domain(), "www.example.com");

        let d3 = parse_domain("api.v1.example.com").unwrap();
        assert_eq!(d3.root_domain, "example.com");
        assert_eq!(d3.sub_domain, "api.v1");
        assert_eq!(d3.full_domain(), "api.v1.example.com");
    }

    #[test]
    fn test_parse_domain_colon_syntax() {
        let d = parse_domain("sub.test:myroot.com").unwrap();
        assert_eq!(d.root_domain, "myroot.com");
        assert_eq!(d.sub_domain, "sub.test");

        let d_at = parse_domain("@:myroot.com").unwrap();
        assert_eq!(d_at.root_domain, "myroot.com");
        assert_eq!(d_at.sub_domain, "@");
    }

    #[test]
    fn test_parse_domain_compound_suffix() {
        let d = parse_domain("nas.myhome.com.cn").unwrap();
        assert_eq!(d.root_domain, "myhome.com.cn");
        assert_eq!(d.sub_domain, "nas");

        let d_eu = parse_domain("nas.myhome.eu.org").unwrap();
        assert_eq!(d_eu.root_domain, "myhome.eu.org");
        assert_eq!(d_eu.sub_domain, "nas");

        let d_au = parse_domain("router.company.com.au").unwrap();
        assert_eq!(d_au.root_domain, "company.com.au");
        assert_eq!(d_au.sub_domain, "router");

        let d_prov = parse_domain("web.node.bj.cn").unwrap();
        assert_eq!(d_prov.root_domain, "node.bj.cn");
        assert_eq!(d_prov.sub_domain, "web");

        let d_sg = parse_domain("api.service.com.sg").unwrap();
        assert_eq!(d_sg.root_domain, "service.com.sg");
        assert_eq!(d_sg.sub_domain, "api");

        let root_d = parse_domain("myhome.com.cn").unwrap();
        assert_eq!(root_d.root_domain, "myhome.com.cn");
        assert_eq!(root_d.sub_domain, "@");
    }

    #[test]
    fn test_punycode_chinese_domain() {
        // 中文根域名自动 Punycode 转码
        let d_chinese = parse_domain("测试.com").unwrap();
        assert_eq!(d_chinese.root_domain, "xn--0zwm56d.com");
        assert_eq!(d_chinese.sub_domain, "@");

        // 中文子域名自动 Punycode 转码 ("我的nas" -> "xn--nas-st5fr61g")
        let d_sub_chinese = parse_domain("我的nas.example.com").unwrap();
        assert_eq!(d_sub_chinese.root_domain, "example.com");
        assert_eq!(d_sub_chinese.sub_domain, "xn--nas-st5fr61g");

        // 冒号语法下的中文域名与子域名转码
        let d_colon_chinese = parse_domain("我的nas:测试.cn").unwrap();
        assert_eq!(d_colon_chinese.root_domain, "xn--0zwm56d.cn");
        assert_eq!(d_colon_chinese.sub_domain, "xn--nas-st5fr61g");
        assert_eq!(
            d_colon_chinese.full_domain(),
            "xn--nas-st5fr61g.xn--0zwm56d.cn"
        );
    }

    #[test]
    fn test_parse_domain_with_params() {
        let d = parse_domain("nas:example.com?line=telecom&ttl=600").unwrap();
        assert_eq!(d.root_domain, "example.com");
        assert_eq!(d.sub_domain, "nas");
        assert_eq!(d.custom_params.get("line").unwrap(), "telecom");
        assert_eq!(d.custom_params.get("ttl").unwrap(), "600");
    }

    #[test]
    fn test_matches_record_name() {
        let d = parse_domain("www.example.com").unwrap();
        assert!(d.matches_record_name("www.example.com"));
        assert!(d.matches_record_name("www.example.com."));
        assert!(d.matches_record_name("WWW.EXAMPLE.COM"));
        assert!(d.matches_record_name("www"));
        assert!(!d.matches_record_name("api.example.com"));

        let d_root = parse_domain("example.com").unwrap();
        assert!(d_root.matches_record_name("example.com"));
        assert!(d_root.matches_record_name("example.com."));
        assert!(d_root.matches_record_name("@"));
    }

    #[test]
    fn test_parse_domain_global_compound_suffixes() {
        // 测试此前缺失的全球各国家/地区复合后缀
        let d1 = parse_domain("www.example.com.tr").unwrap();
        assert_eq!(d1.sub_domain, "www");
        assert_eq!(d1.root_domain, "example.com.tr");

        let d2 = parse_domain("api.service.co.il").unwrap();
        assert_eq!(d2.sub_domain, "api");
        assert_eq!(d2.root_domain, "service.co.il");

        let d3 = parse_domain("example.com.mx").unwrap();
        assert_eq!(d3.sub_domain, "@");
        assert_eq!(d3.root_domain, "example.com.mx");

        let d4 = parse_domain("blog.my-app.co.in").unwrap();
        assert_eq!(d4.sub_domain, "blog");
        assert_eq!(d4.root_domain, "my-app.co.in");

        let d5 = parse_domain("portal.gov.sa").unwrap();
        assert_eq!(d5.sub_domain, "@");
        assert_eq!(d5.root_domain, "portal.gov.sa");

        let d5_sub = parse_domain("www.portal.gov.sa").unwrap();
        assert_eq!(d5_sub.sub_domain, "www");
        assert_eq!(d5_sub.root_domain, "portal.gov.sa");

        let d6 = parse_domain("cloud.server.co.ke").unwrap();
        assert_eq!(d6.sub_domain, "cloud");
        assert_eq!(d6.root_domain, "server.co.ke");

        let d7 = parse_domain("test.eu.org").unwrap();
        assert_eq!(d7.sub_domain, "@");
        assert_eq!(d7.root_domain, "test.eu.org");
    }

    #[test]
    fn test_parse_domain_single_label_no_panic() {
        // 单标签域名（如 localhost、myrouter）无点号，parse_domain 应安全返回 None，严禁 panic
        assert!(parse_domain("localhost").is_none());
        assert!(parse_domain("myhost?line=default").is_none());

        // 直接测试底层拆分函数，即便独立调用也绝不发生算术下溢 panic
        let (sub, root) = split_sub_and_root_by_psl("localhost");
        assert_eq!(sub, "@");
        assert_eq!(root, "localhost");
    }

    #[test]
    fn test_parse_domain_list_skips_invalid() {
        let list = vec![
            "example.com".to_string(),
            "localhost".to_string(),
            "sub.test.org".to_string(),
        ];
        let parsed = parse_domain_list(&list);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].full_domain(), "example.com");
        assert_eq!(parsed[1].full_domain(), "sub.test.org");
    }

    #[test]
    fn test_parse_domain_path_traversal_and_injection_blocked() {
        // 1. 冒号语法中的路径穿越攻击
        assert!(parse_domain("../../evil:example.com").is_none());
        assert!(parse_domain("sub/test:example.com").is_none());
        assert!(parse_domain("sub\\test:example.com").is_none());

        // 2. 连续点号 (..)
        assert!(parse_domain("sub..name:example.com").is_none());
        assert!(parse_domain("sub..example.com").is_none());

        // 3. 非法 URL 控制字符注入
        assert!(parse_domain("sub?query=evil:example.com").is_none());
        assert!(parse_domain("sub#anchor:example.com").is_none());
        assert!(parse_domain("sub&arg=1:example.com").is_none());

        // 4. 合法字符（下划线、短横线、多级子域名、泛域名、根域@）正常放行
        assert!(parse_domain("_acme-challenge:example.com").is_some());
        assert!(parse_domain("my-host.sub:example.com").is_some());
        assert!(parse_domain("*.example.com").is_some());
        assert!(parse_domain("@:example.com").is_some());
    }
}

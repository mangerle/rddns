use std::collections::HashMap;
use url::form_urlencoded;

/// 解析后的单个域名实体
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
}

/// 解析用户配置的单个域名字符串
/// 支持格式:
/// - "example.com" -> sub: "@", root: "example.com"
/// - "www.example.com" -> sub: "www", root: "example.com"
/// - "sub:example.com" -> sub: "sub", root: "example.com"
/// - "@:example.com" -> sub: "@", root: "example.com"
/// - "sub.dev:example.com" -> sub: "sub.dev", root: "example.com"
/// - "sub:example.com?line=telecom" -> 带自定义参数
/// 解析用户配置的单个域名字符串
/// 支持格式:
/// - "example.com" -> sub: "@", root: "example.com"
/// - "www.example.com" -> sub: "www", root: "example.com"
/// - "*.example.com" -> sub: "*", root: "example.com"
/// - "sub:example.com" -> sub: "sub", root: "example.com"
/// - "https://www.example.com/" -> 自动清洗为 sub: "www", root: "example.com"
/// - "sub:example.com?line=telecom" -> 带自定义参数
pub fn parse_domain(raw_input: &str) -> Option<ParsedDomain> {
    let trimmed = raw_input.trim();
    // 忽略空行以及以 # 或 // 开头的注释行
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    // 1. 去除协议头 (如 http://, https://, 大小写不敏感)
    let no_protocol = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };

    // 2. 提取 query 参数 (以 ? 分割)
    let (domain_and_path, query_part) = match no_protocol.split_once('?') {
        Some((d, q)) => (d.trim(), Some(q.trim())),
        None => (no_protocol.trim(), None),
    };

    // 3. 去除末尾斜杠及 URL 路径 (例如 example.com/path -> example.com)
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

    // 4. 检查冒号自定义子域名格式: "sub:domain.com"
    if let Some((sub, root)) = domain_raw.split_once(':') {
        let sub = sub.trim().to_ascii_lowercase();
        let root = root.trim().to_ascii_lowercase();
        if root.is_empty() {
            return None;
        }
        return Some(ParsedDomain {
            raw: raw_input.to_string(),
            root_domain: root,
            sub_domain: if sub.is_empty() { "@".to_string() } else { sub },
            custom_params,
        });
    }

    // 5. 若包含非 ASCII 字符（如中文域名），使用 IDNA Punycode 转码为 xn--... 形式
    let domain_ascii = if !domain_raw.is_ascii() {
        idna::domain_to_ascii(&domain_raw.to_ascii_lowercase())
            .unwrap_or_else(|_| domain_raw.to_ascii_lowercase())
    } else {
        domain_raw.to_ascii_lowercase()
    };

    let parts: Vec<&str> = domain_ascii.split('.').collect();
    if parts.len() < 2 {
        // 单个单词无法作为有效公网域名
        return None;
    }

    // 针对常见二级后缀 (如 .com.cn, .net.cn, .org.cn, .co.uk, .gov.cn, .eu.org)
    let is_special_second_level =
        parts.len() >= 3 && is_compound_suffix(parts[parts.len() - 2], parts[parts.len() - 1]);

    let (sub_domain, root_domain) = if is_special_second_level {
        if parts.len() == 3 {
            ("@".to_string(), domain_ascii)
        } else {
            let sub = parts[..parts.len() - 3].join(".");
            let root = parts[parts.len() - 3..].join(".");
            (sub, root)
        }
    } else {
        if parts.len() == 2 {
            ("@".to_string(), domain_ascii)
        } else {
            let sub = parts[..parts.len() - 2].join(".");
            let root = parts[parts.len() - 2..].join(".");
            (sub, root)
        }
    };

    Some(ParsedDomain {
        raw: raw_input.to_string(),
        root_domain,
        sub_domain,
        custom_params,
    })
}

fn is_compound_suffix(second_last: &str, last: &str) -> bool {
    let second_lower = second_last.to_ascii_lowercase();
    let last_lower = last.to_ascii_lowercase();
    matches!(
        (second_lower.as_str(), last_lower.as_str()),
        ("com", "cn")
            | ("net", "cn")
            | ("org", "cn")
            | ("gov", "cn")
            | ("edu", "cn")
            | ("co", "uk")
            | ("org", "uk")
            | ("co", "jp")
            | ("com", "hk")
            | ("eu", "org")
            | ("net", "ru")
            | ("org", "ru")
            | ("pp", "ru")
            | ("com", "tw")
            | ("org", "tw")
    )
}

/// 批量解析域名列表
pub fn parse_domain_list(raw_list: &[String]) -> Vec<ParsedDomain> {
    raw_list.iter().filter_map(|d| parse_domain(d)).collect()
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
    }

    #[test]
    fn test_parse_domain_with_params() {
        let d = parse_domain("nas:example.com?line=telecom&ttl=600").unwrap();
        assert_eq!(d.root_domain, "example.com");
        assert_eq!(d.sub_domain, "nas");
        assert_eq!(d.custom_params.get("line").unwrap(), "telecom");
        assert_eq!(d.custom_params.get("ttl").unwrap(), "600");
    }
}

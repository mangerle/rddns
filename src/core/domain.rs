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

/// 将域名字符串转换为 ASCII Punycode 格式（针对中文等多语言 IDN 域名）
fn to_ascii_domain(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    if !lower.is_ascii() {
        idna::domain_to_ascii(&lower).unwrap_or(lower)
    } else {
        lower
    }
}

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
    // 注意：若冒号右侧为纯数字端口（如 "example.com:8080"），应视为端口号剥离，而非 sub:root 冒号语法
    let (domain_cleaned, explicit_sub_root) =
        if let Some((left, right)) = domain_raw.split_once(':') {
            if right.parse::<u16>().is_ok() {
                // 右侧为端口号，剥离端口后保留左侧作为真实域名
                (left.trim(), None)
            } else {
                (domain_raw, Some((left, right)))
            }
        } else {
            (domain_raw, None)
        };

    if let Some((sub, root)) = explicit_sub_root {
        let root_ascii = to_ascii_domain(root);
        if root_ascii.is_empty() {
            return None;
        }
        let sub_trimmed = sub.trim();
        let sub_ascii = if sub_trimmed.is_empty() || sub_trimmed == "@" {
            "@".to_string()
        } else if sub_trimmed == "*" {
            "*".to_string()
        } else {
            to_ascii_domain(sub_trimmed)
        };
        return Some(ParsedDomain {
            raw: raw_input.to_string(),
            root_domain: root_ascii,
            sub_domain: sub_ascii,
            custom_params,
        });
    }

    // 5. 若包含非 ASCII 字符（如中文域名），使用 IDNA Punycode 转码为 xn--... 形式
    let domain_ascii = to_ascii_domain(domain_cleaned);

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
        // 中国大陆 (.cn) 类别及省份前缀
        ("com", "cn")
            | ("net", "cn")
            | ("org", "cn")
            | ("gov", "cn")
            | ("edu", "cn")
            | ("ac", "cn")
            | ("mil", "cn")
            | ("ah", "cn")
            | ("bj", "cn")
            | ("cq", "cn")
            | ("fj", "cn")
            | ("gd", "cn")
            | ("gs", "cn")
            | ("gx", "cn")
            | ("gz", "cn")
            | ("ha", "cn")
            | ("hb", "cn")
            | ("he", "cn")
            | ("hi", "cn")
            | ("hl", "cn")
            | ("hn", "cn")
            | ("jl", "cn")
            | ("js", "cn")
            | ("jx", "cn")
            | ("ln", "cn")
            | ("nm", "cn")
            | ("nx", "cn")
            | ("qh", "cn")
            | ("sc", "cn")
            | ("sd", "cn")
            | ("sh", "cn")
            | ("sn", "cn")
            | ("sx", "cn")
            | ("tj", "cn")
            | ("xj", "cn")
            | ("xz", "cn")
            | ("yn", "cn")
            | ("zj", "cn")
            // 中国香港 (.hk) / 澳门 (.mo) / 台湾 (.tw)
            | ("com", "hk")
            | ("net", "hk")
            | ("org", "hk")
            | ("edu", "hk")
            | ("gov", "hk")
            | ("idv", "hk")
            | ("com", "mo")
            | ("net", "mo")
            | ("org", "mo")
            | ("edu", "mo")
            | ("gov", "mo")
            | ("com", "tw")
            | ("net", "tw")
            | ("org", "tw")
            | ("edu", "tw")
            | ("gov", "tw")
            | ("idv", "tw")
            | ("club", "tw")
            | ("game", "tw")
            | ("ebiz", "tw")
            // 英国 (.uk)
            | ("co", "uk")
            | ("org", "uk")
            | ("me", "uk")
            | ("net", "uk")
            | ("ltd", "uk")
            | ("plc", "uk")
            | ("ac", "uk")
            | ("gov", "uk")
            // 日本 (.jp)
            | ("co", "jp")
            | ("ne", "jp")
            | ("or", "jp")
            | ("ac", "jp")
            | ("go", "jp")
            | ("ed", "jp")
            | ("gr", "jp")
            | ("lg", "jp")
            // 澳大利亚 (.au)
            | ("com", "au")
            | ("net", "au")
            | ("org", "au")
            | ("edu", "au")
            | ("gov", "au")
            | ("id", "au")
            | ("asn", "au")
            // 新西兰 (.nz)
            | ("co", "nz")
            | ("net", "nz")
            | ("org", "nz")
            | ("ac", "nz")
            | ("govt", "nz")
            | ("school", "nz")
            | ("geek", "nz")
            | ("gen", "nz")
            // 新加坡 (.sg) / 马来西亚 (.my)
            | ("com", "sg")
            | ("net", "sg")
            | ("org", "sg")
            | ("edu", "sg")
            | ("gov", "sg")
            | ("per", "sg")
            | ("com", "my")
            | ("net", "my")
            | ("org", "my")
            | ("edu", "my")
            | ("gov", "my")
            // 韩国 (.kr)
            | ("co", "kr")
            | ("ne", "kr")
            | ("or", "kr")
            | ("re", "kr")
            | ("pe", "kr")
            | ("go", "kr")
            // 巴西 (.br)
            | ("com", "br")
            | ("net", "br")
            | ("org", "br")
            | ("app", "br")
            | ("art", "br")
            | ("dev", "br")
            | ("eco", "br")
            | ("emp", "br")
            | ("log", "br")
            // 俄罗斯 (.ru) / 欧洲与其它
            | ("com", "ru")
            | ("net", "ru")
            | ("org", "ru")
            | ("pp", "ru")
            | ("co", "za")
            | ("net", "za")
            | ("org", "za")
            | ("web", "za")
            | ("eu", "org")
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
}

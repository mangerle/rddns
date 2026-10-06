use super::*;

/// 构造一个所有凭据字段均为空字符串的 provider 配置
fn blank_credentials() -> ProviderConfig {
    ProviderConfig::Cloudflare {
        api_token: Some(String::new()),
        api_key: Some(String::new()),
        email: Some(String::new()),
    }
}

#[test]
fn test_is_configured_rejects_blank_credentials() {
    // 全空凭据必须判定为未配置，避免向云端发送必然失败的请求
    assert!(!blank_credentials().is_configured());
}

#[test]
fn test_is_configured_rejects_whitespace_only_credentials() {
    // 仅含空白字符等同于未填写
    let conf = ProviderConfig::Cloudflare {
        api_token: Some("   ".to_string()),
        api_key: None,
        email: None,
    };
    assert!(!conf.is_configured());
}

#[test]
fn test_is_configured_accepts_cloudflare_token() {
    let conf = ProviderConfig::Cloudflare {
        api_token: Some("cf-token".to_string()),
        api_key: None,
        email: None,
    };
    assert!(conf.is_configured());
}

#[test]
fn test_is_configured_cloudflare_requires_key_and_email_together() {
    // Global API Key 必须与邮箱同时配置，缺一不可
    let only_key = ProviderConfig::Cloudflare {
        api_token: None,
        api_key: Some("cf-key".to_string()),
        email: None,
    };
    assert!(!only_key.is_configured());

    let key_and_email = ProviderConfig::Cloudflare {
        api_token: None,
        api_key: Some("cf-key".to_string()),
        email: Some("user@example.com".to_string()),
    };
    assert!(key_and_email.is_configured());
}

#[test]
fn test_is_configured_rejects_partial_credential_pairs() {
    // 各厂商的「密钥对」必须成对出现，缺一即视为未配置
    let cases: Vec<ProviderConfig> = vec![
        ProviderConfig::AliDns {
            access_key_id: "ak".to_string(),
            access_key_secret: String::new(),
            endpoint: None,
        },
        ProviderConfig::TencentCloud {
            secret_id: "sid".to_string(),
            secret_key: String::new(),
        },
        ProviderConfig::EdgeOne {
            secret_id: "sid".to_string(),
            secret_key: String::new(),
        },
        ProviderConfig::BaiduCloud {
            access_key_id: "ak".to_string(),
            secret_access_key: String::new(),
        },
        ProviderConfig::TrafficRoute {
            access_key_id: "ak".to_string(),
            secret_access_key: String::new(),
        },
        ProviderConfig::Porkbun {
            api_key: "ak".to_string(),
            secret_key: String::new(),
        },
        ProviderConfig::GoDaddy {
            api_key: "ak".to_string(),
            api_secret: String::new(),
        },
        ProviderConfig::NameCom {
            username: "user".to_string(),
            api_token: String::new(),
        },
    ];

    for conf in cases {
        assert!(
            !conf.is_configured(),
            "凭据对不完整时应判定为未配置: {:?}",
            conf
        );
    }
}

#[test]
fn test_is_configured_accepts_complete_credential_pairs() {
    let cases: Vec<ProviderConfig> = vec![
        ProviderConfig::AliDns {
            access_key_id: "ak".to_string(),
            access_key_secret: "sk".to_string(),
            endpoint: None,
        },
        ProviderConfig::TencentCloud {
            secret_id: "sid".to_string(),
            secret_key: "sk".to_string(),
        },
        ProviderConfig::EdgeOne {
            secret_id: "sid".to_string(),
            secret_key: "sk".to_string(),
        },
        ProviderConfig::BaiduCloud {
            access_key_id: "ak".to_string(),
            secret_access_key: "sk".to_string(),
        },
        ProviderConfig::TrafficRoute {
            access_key_id: "ak".to_string(),
            secret_access_key: "sk".to_string(),
        },
        ProviderConfig::Porkbun {
            api_key: "ak".to_string(),
            secret_key: "sk".to_string(),
        },
        ProviderConfig::GoDaddy {
            api_key: "ak".to_string(),
            api_secret: "sk".to_string(),
        },
        ProviderConfig::NameCom {
            username: "user".to_string(),
            api_token: "token".to_string(),
        },
        ProviderConfig::Namecheap {
            password: "pwd".to_string(),
        },
        ProviderConfig::Dynv6 {
            token: "token".to_string(),
        },
        ProviderConfig::Vercel {
            token: "token".to_string(),
            team_id: None,
        },
        ProviderConfig::Callback {
            url: "https://example.com/hook".to_string(),
            method: "POST".to_string(),
            headers: None,
            body: None,
        },
    ];

    for conf in cases {
        assert!(conf.is_configured(), "凭据完整时应判定为已配置: {:?}", conf);
    }
}

/// 契约测试：确保 web-ui/index.html 下拉框提交的所有服务商 type 键均能被正确反序列化识别
#[test]
fn test_all_frontend_provider_keys_accepted() {
    let frontend_keys = [
        "cloudflare",
        "ali_dns",
        "tencent_cloud",
        "huawei_cloud",
        "porkbun",
        "godaddy",
        "dynv6",
        "baidu_cloud",
        "traffic_route",
        "namecheap",
        "namesilo",
        "spaceship",
        "dynadot",
        "vercel",
        "rainyun",
        "cloudns",
        "gcore",
        "name_com",
        "dnsla",
        "aliesa",
        "edgeone",
        "nowcn",
        "eranet",
        "tnethk",
        "nsone",
        "hipm_dnsmgr",
        "callback",
    ];

    for key in frontend_keys {
        let json_probe = format!("{{\"type\":\"{}\",\"__probe__\":1}}", key);
        if let Err(e) = serde_json::from_str::<ProviderConfig>(&json_probe) {
            assert!(
                !e.to_string().contains("unknown variant"),
                "前端 type 键 [{}] 后端无法识别变体: {}",
                key,
                e
            );
        }
    }
}

#[test]
fn test_is_configured_hipm_dnsmgr_requires_both_endpoint_and_token() {
    // 仅配置 token 未配置 endpoint：未完成配置 (P3-18)
    let no_endpoint = ProviderConfig::HipmDnsMgr {
        endpoint: None,
        api_token: "secret_token".to_string(),
    };
    assert!(!no_endpoint.is_configured(), "缺少 endpoint 应判定为未配置");

    // endpoint 为纯空白字符
    let blank_endpoint = ProviderConfig::HipmDnsMgr {
        endpoint: Some("   ".to_string()),
        api_token: "secret_token".to_string(),
    };
    assert!(
        !blank_endpoint.is_configured(),
        "空白 endpoint 应判定为未配置"
    );

    // 仅配置 endpoint 未配置 token
    let no_token = ProviderConfig::HipmDnsMgr {
        endpoint: Some("https://dnsmgr.example.com".to_string()),
        api_token: String::new(),
    };
    assert!(!no_token.is_configured(), "缺少 token 应判定为未配置");

    // 两者均完整配置
    let complete = ProviderConfig::HipmDnsMgr {
        endpoint: Some("https://dnsmgr.example.com".to_string()),
        api_token: "secret_token".to_string(),
    };
    assert!(
        complete.is_configured(),
        "endpoint 与 token 齐全应判定为已配置"
    );
}

//! DNS 提供商抽象接口与错误类型单元测试

use super::*;

#[test]
fn test_sanitize_sensitive_url_params() {
    let raw_err = "error sending request for url (https://www.namesilo.com/api/dnsListRecords?version=1&type=xml&key=secret123456&domain=example.com): operation timed out";
    let sanitized = sanitize_sensitive_url_params(raw_err);
    assert!(!sanitized.contains("secret123456"));
    assert!(sanitized.contains("key=******"));

    let raw_nc = "https://dynamicdns.park-your-domain.com/update?host=@&domain=test.com&password=my_password_xyz&ip=1.1.1.1";
    let sanitized_nc = sanitize_sensitive_url_params(raw_nc);
    assert!(!sanitized_nc.contains("my_password_xyz"));
    assert!(sanitized_nc.contains("password=******"));
}

#[test]
fn test_sync_record_result_constructors() {
    let res_unchanged = SyncRecordResult::unchanged("example.com", DnsRecordType::A, "1.1.1.1");
    assert_eq!(res_unchanged.status, SyncStatus::Unchanged);
    assert_eq!(res_unchanged.domain, "example.com");

    let res_updated = SyncRecordResult::updated("example.com", DnsRecordType::A, "1.1.1.2");
    assert_eq!(res_updated.status, SyncStatus::Updated);

    let res_created = SyncRecordResult::created("example.com", DnsRecordType::AAAA, "::1");
    assert_eq!(res_created.status, SyncStatus::Created);

    let res_unchanged_log =
        SyncRecordResult::unchanged_log("TestProvider", "example.com", DnsRecordType::A, "1.1.1.1");
    assert_eq!(res_unchanged_log.status, SyncStatus::Unchanged);

    let res_updated_log =
        SyncRecordResult::updated_log("TestProvider", "example.com", DnsRecordType::A, "1.1.1.2");
    assert_eq!(res_updated_log.status, SyncStatus::Updated);

    let res_created_log =
        SyncRecordResult::created_log("TestProvider", "example.com", DnsRecordType::AAAA, "::1");
    assert_eq!(res_created_log.status, SyncStatus::Created);

    let res_failed =
        SyncRecordResult::failed("example.com", DnsRecordType::A, "1.1.1.1", "网络超时");
    assert_eq!(res_failed.status, SyncStatus::Failed);
    assert_eq!(res_failed.message, "网络超时");
}

#[test]
fn test_sanitize_covers_json_body_credentials() {
    // 服务商在响应体中回显凭据是常见形态，此前完全未被脱敏覆盖
    let json_body = r#"{"code":"InvalidToken","token":"json_secret_abc","expires":3600}"#;
    let sanitized = sanitize_sensitive_url_params(json_body);
    assert!(
        !sanitized.contains("json_secret_abc"),
        "JSON body 中的 token 必须被脱敏: {}",
        sanitized
    );
    assert!(sanitized.contains("\"token\":\"******\""));

    // 驼峰与下划线命名形式同样需覆盖
    let camel = r#"{"api_key":"k_12345","apiToken":"t_67890"}"#;
    let sanitized_camel = sanitize_sensitive_url_params(camel);
    assert!(!sanitized_camel.contains("k_12345"));
    assert!(!sanitized_camel.contains("t_67890"));
}

#[test]
fn test_sanitize_preserves_non_sensitive_fields() {
    // 脱敏不得误伤非敏感字段，否则会丢失排障所需信息
    let body = r#"{"code":"AuthenticationFailed","message":"Invalid credentials","region":"ap-southeast-1"}"#;
    let sanitized = sanitize_sensitive_url_params(body);
    assert!(sanitized.contains("AuthenticationFailed"));
    assert!(sanitized.contains("Invalid credentials"));
    assert!(sanitized.contains("ap-southeast-1"));
}

#[test]
fn test_error_display_masks_api_error_message() {
    // 这是核心保障：无论 provider 如何构造错误，经 Display 输出时必然已脱敏。
    // 该文本会继续流向 SyncRecordResult.message、日志、Web 面板与第三方通知渠道。
    let err = DnsProviderError::api(
        "401",
        r#"{"error":"invalid","api_key":"leaked_secret_value"}"#,
    );
    let text = err.to_string();
    assert!(
        !text.contains("leaked_secret_value"),
        "错误输出中绝不可包含原始凭据: {}",
        text
    );
    assert!(text.contains("401"));
}

#[test]
fn test_error_display_masks_all_variants() {
    // 各变体均应脱敏，防止遗漏某条路径
    let leaked = "secret=should_be_masked";

    let http = DnsProviderError::Http(leaked.to_string()).to_string();
    assert!(!http.contains("should_be_masked"), "Http 变体未脱敏");

    let other = DnsProviderError::Other(leaked.to_string()).to_string();
    assert!(!other.contains("should_be_masked"), "Other 变体未脱敏");

    let missing = DnsProviderError::MissingCredentials(leaked.to_string()).to_string();
    assert!(
        !missing.contains("should_be_masked"),
        "MissingCredentials 变体未脱敏"
    );

    // ZoneNotFound 承载的是根域名，不含凭据，无需脱敏
    let zone = DnsProviderError::ZoneNotFound("example.com".to_string()).to_string();
    assert!(zone.contains("example.com"));
}

#[test]
fn test_error_still_conforms_to_std_error_trait() {
    // 改为手写 Display 后，必须继续满足 std::error::Error 契约，
    // 否则 anyhow 上下文包装与 ? 传播会失效
    fn assert_error<E: std::error::Error + Send + Sync + 'static>(_: &E) {}
    let err = DnsProviderError::api("500", "内部错误");
    assert_error(&err);
    // 仍可作为 Box<dyn Error> 使用
    let boxed: Box<dyn std::error::Error> = Box::new(err);
    assert!(boxed.to_string().contains("500"));
}

#[test]
fn test_truncate_body() {
    let short = "短文本";
    assert_eq!(truncate_body(short), short);

    let long = "a".repeat(2000);
    let truncated = truncate_body(&long);
    assert_eq!(truncated.len(), MAX_ERR_BODY_CHARS);

    let err = DnsProviderError::api("500", "x".repeat(3000));
    let err_str = err.to_string();
    assert!(err_str.len() <= MAX_ERR_BODY_CHARS + 60);
}

#[test]
fn test_ip_value_matches() {
    use std::net::{IpAddr, Ipv4Addr};

    let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(ip_value_matches("1.2.3.4", &v4));
    assert!(ip_value_matches(" 1.2.3.4 ", &v4));
    assert!(!ip_value_matches("1.2.3.5", &v4));

    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    // 缩写与全写等价比对
    assert!(ip_value_matches("2001:db8::1", &v6));
    assert!(ip_value_matches(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        &v6
    ));
    assert!(!ip_value_matches("2001:db8::2", &v6));
}

#[test]
fn test_error_is_retryable() {
    assert!(DnsProviderError::Http("Connection reset".to_string()).is_retryable());
    assert!(DnsProviderError::api("503", "Service Unavailable").is_retryable());
    assert!(DnsProviderError::api("TooManyRequests", "Rate limit exceeded").is_retryable());
    assert!(!DnsProviderError::MissingCredentials("missing key".to_string()).is_retryable());
    assert!(!DnsProviderError::ZoneNotFound("example.com".to_string()).is_retryable());
    assert!(!DnsProviderError::api("InvalidDomain", "Domain does not exist").is_retryable());
}

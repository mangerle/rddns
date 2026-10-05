use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::net::IpAddr;

const DYNADOT_ENDPOINT: &str = "https://www.dynadot.com/set_ddns";

/// Dynadot 动态 DNS 提供商
pub struct DynadotProvider {
    password: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct DynadotResp {
    #[serde(rename = "error_code")]
    error_code: Option<i32>,
    content: Option<Vec<String>>,
}

impl DynadotProvider {
    pub fn new(password: String, http_interface: Option<&str>) -> Self {
        Self {
            password,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    /// 解析 Dynadot set_ddns 接口响应
    ///
    /// # 设计原理
    /// - **实现初衷**：统一精确校验 Dynadot JSON 响应的 `error_code` 以及 XML/纯文本格式，遵循 fail-closed 理念。
    /// - **核心优势**：杜绝因宽松子串匹配（如 `contains("ok")` 误匹配 token/cookie/broken）及 `!= Some(-1)` 逻辑漏洞导致的静默更新成功误判。
    /// - **代价与局限**：对非预期格式直接返回错误，要求远端响应必须具有明确的成功指示。
    pub(crate) fn parse_dynadot_response(
        status: StatusCode,
        body_text: &str,
    ) -> Result<(), DnsProviderError> {
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, body_text));
        }

        if let Ok(res_json) = serde_json::from_str::<DynadotResp>(body_text) {
            return match res_json.error_code {
                Some(0) => Ok(()),
                Some(code) => {
                    let err_msg = res_json.content.unwrap_or_default().join(", ");
                    Err(DnsProviderError::ApiError {
                        code: code.to_string(),
                        message: format!(
                            "Dynadot 更新失败: {}",
                            if err_msg.is_empty() {
                                body_text.to_string()
                            } else {
                                err_msg
                            }
                        ),
                    })
                }
                None => {
                    let is_ok = res_json
                        .content
                        .as_deref()
                        .is_some_and(|c| c.len() == 1 && c[0].trim().eq_ignore_ascii_case("ok"));
                    if is_ok {
                        Ok(())
                    } else {
                        Err(DnsProviderError::ApiError {
                            code: "MissingErrorCode".to_string(),
                            message: format!("Dynadot 响应缺少明确的成功错误码: {}", body_text),
                        })
                    }
                }
            };
        }

        let trimmed = body_text.trim();
        if trimmed.eq_ignore_ascii_case("ok")
            || trimmed.eq_ignore_ascii_case("success")
            || trimmed.contains("<error_code>0</error_code>")
            || trimmed.contains("<SuccessCode>0</SuccessCode>")
            || trimmed.contains("<Status>success</Status>")
            || trimmed.contains("<status>success</status>")
        {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Dynadot 返回失败或未知格式响应: {}", body_text),
            })
        }
    }
}

#[async_trait]
impl DnsProvider for DynadotProvider {
    fn provider_name(&self) -> &'static str {
        "Dynadot"
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();
        let ttl_val = ttl.unwrap_or(600).max(1).to_string();
        let record_type_str = record_type.to_string();

        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_name = if is_root { "@" } else { &domain.sub_domain };

        let query = [
            ("domain", domain.root_domain.as_str()),
            ("subDomain", sub_name),
            ("type", record_type_str.as_str()),
            ("ip", &target_ip_str),
            ("pwd", &self.password),
            ("ttl", &ttl_val),
            ("containRoot", if is_root { "true" } else { "false" }),
        ];

        let resp = self
            .client
            .get(DYNADOT_ENDPOINT)
            .query(&query)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        Self::parse_dynadot_response(status, &body_text)?;

        Ok(SyncRecordResult::updated_log(
            self.provider_name(),
            full_domain,
            record_type,
            target_ip_str,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynadot_parse_json_success() {
        let ok_json = r#"{"error_code": 0, "content": ["ok"]}"#;
        assert!(DynadotProvider::parse_dynadot_response(StatusCode::OK, ok_json).is_ok());
    }

    #[test]
    fn test_dynadot_parse_json_error_code() {
        let err_json = r#"{"error_code": 1, "content": ["domain not found"]}"#;
        let res = DynadotProvider::parse_dynadot_response(StatusCode::OK, err_json);
        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "1");
                assert!(message.contains("domain not found"));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_dynadot_parse_json_system_error() {
        let err_json = r#"{"error_code": -1, "content": ["system error"]}"#;
        let res = DynadotProvider::parse_dynadot_response(StatusCode::OK, err_json);
        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "-1");
                assert!(message.contains("system error"));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_dynadot_parse_json_missing_code_rejected() {
        let err_json = r#"{"content": ["something went wrong"]}"#;
        let res = DynadotProvider::parse_dynadot_response(StatusCode::OK, err_json);
        assert!(res.is_err());
    }

    #[test]
    fn test_dynadot_does_not_falsely_succeed_on_token_error_substring() {
        // 验证包含 token/look/cookie/broken 的错误消息不会因包含 "ok" 而被误判成功
        let err_text = "error: auth token expired, please re-authenticate";
        let res = DynadotProvider::parse_dynadot_response(StatusCode::OK, err_text);
        assert!(res.is_err());
    }

    #[test]
    fn test_dynadot_xml_success() {
        let xml_ok = "<SetDnsResponse><error_code>0</error_code></SetDnsResponse>";
        assert!(DynadotProvider::parse_dynadot_response(StatusCode::OK, xml_ok).is_ok());
    }

    #[test]
    fn test_dynadot_raw_ok() {
        assert!(DynadotProvider::parse_dynadot_response(StatusCode::OK, "ok\n").is_ok());
        assert!(DynadotProvider::parse_dynadot_response(StatusCode::OK, "SUCCESS").is_ok());
    }
}

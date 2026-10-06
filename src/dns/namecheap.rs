use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use std::net::IpAddr;

const NAMECHEAP_ENDPOINT: &str = "https://dynamicdns.park-your-domain.com/update";

/// Namecheap 动态 DNS 提供商
pub struct NamecheapProvider {
    password: String,
    client: Client,
}

impl NamecheapProvider {
    pub fn new(password: String, http_interface: Option<&str>) -> Self {
        Self {
            password,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    /// 解析 Namecheap 动态 DNS 响应体
    ///
    /// # 设计原理
    /// - **实现初衷**：严格依据 Namecheap XML 中的 `<ErrCount>0</ErrCount>` 判定成功，遵循 fail-closed 理念。
    /// - **核心优势**：杜绝因 `<Done>true</Done>`（错误完成亦返回 true）或宽泛子串 `"Success"`（错误文本可能包含）导致的误判成功。
    /// - **代价与局限**：若远端未返回标准 ErrCount 标签则安全拒绝。
    pub(crate) fn parse_namecheap_response(
        status: StatusCode,
        body_text: &str,
    ) -> Result<(), DnsProviderError> {
        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Namecheap HTTP 请求异常: {}", body_text),
            });
        }

        if body_text.contains("<ErrCount>0</ErrCount>") {
            return Ok(());
        }

        let err_detail =
            extract_namecheap_error(body_text).unwrap_or_else(|| body_text.to_string());
        Err(DnsProviderError::ApiError {
            code: "NamecheapError".to_string(),
            message: format!("Namecheap 更新失败: {}", err_detail),
        })
    }
}

/// 从 Namecheap XML 响应中提取错误消息描述
fn extract_namecheap_error(body: &str) -> Option<String> {
    if let Some(start) = body.find("<Err1>")
        && let Some(end) = body.find("</Err1>")
        && start < end
    {
        let msg = &body[start + 6..end];
        return Some(msg.trim().to_string());
    }
    None
}

#[async_trait]
impl DnsProvider for NamecheapProvider {
    fn provider_name(&self) -> &'static str {
        "Namecheap"
    }

    /// Namecheap 官方动态更新接口仅支持 IPv4 (A 记录)，不支持 IPv6 (P2-11)
    fn supports_record_type(&self, record_type: DnsRecordType) -> bool {
        record_type == DnsRecordType::A
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        _ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();

        // 拦截不支持的记录类型
        if !self.supports_record_type(record_type) {
            return Err(DnsProviderError::UnsupportedRecordType {
                provider: "Namecheap",
                record_type,
            });
        }

        let host = domain.sub_domain_or_at();

        let resp = self
            .client
            .get(NAMECHEAP_ENDPOINT)
            .query(&[
                ("host", host),
                ("domain", &domain.root_domain),
                ("password", &self.password),
                ("ip", &target_ip_str),
            ])
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        Self::parse_namecheap_response(status, &body_text)?;

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
    fn test_namecheap_parse_success() {
        let xml_ok = r#"<interface-response><ErrCount>0</ErrCount><responseStatus>Success</responseStatus><Done>true</Done></interface-response>"#;
        assert!(NamecheapProvider::parse_namecheap_response(StatusCode::OK, xml_ok).is_ok());
    }

    #[test]
    fn test_namecheap_parse_error_with_done_true() {
        // 关键防护场景：虽然 Done 为 true，但 ErrCount 为 1，必须判定为失败
        let xml_err = r#"<interface-response><ErrCount>1</ErrCount><errors><Err1>Domain not found</Err1></errors><responseStatus>ERROR</responseStatus><Done>true</Done></interface-response>"#;
        let res = NamecheapProvider::parse_namecheap_response(StatusCode::OK, xml_err);
        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "NamecheapError");
                assert!(message.contains("Domain not found"));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_namecheap_does_not_falsely_succeed_on_success_substring() {
        // 验证错误提示中包含 Successive failures 时不会因子串匹配误判成功
        let xml_err = r#"<interface-response><ErrCount>1</ErrCount><errors><Err1>Successive authentication failures</Err1></errors></interface-response>"#;
        let res = NamecheapProvider::parse_namecheap_response(StatusCode::OK, xml_err);
        assert!(res.is_err());
    }
}

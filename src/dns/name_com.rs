use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const NAME_COM_ENDPOINT: &str = "https://api.name.com/core/v1/domains";

/// Name.com DNS 提供商
pub struct NameComProvider {
    username: String,
    api_token: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct NameComRecordItem {
    id: i64,
    #[serde(rename = "type")]
    record_type: String,
    host: Option<String>,
    answer: String,
}

#[derive(Debug, Deserialize)]
struct NameComListResp {
    records: Option<Vec<NameComRecordItem>>,
}

impl NameComProvider {
    pub fn new(username: String, api_token: String, http_interface: Option<&str>) -> Self {
        Self {
            username,
            api_token,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_raw = format!("{}:{}", self.username, self.api_token);
        let auth_b64 = BASE64.encode(auth_raw.as_bytes());
        if let Ok(hv) = HeaderValue::from_str(&format!("Basic {}", auth_b64)) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl DnsProvider for NameComProvider {
    fn provider_name(&self) -> &'static str {
        "Name.com"
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
        let ttl_val = ttl.unwrap_or(300).max(1);

        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        // 1. 查询现有解析记录
        let list_url = format!("{}/{}/records", NAME_COM_ENDPOINT, domain.root_domain);

        let list_resp = self
            .client
            .get(&list_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = list_resp.status();
        let body_text = list_resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Name.com 查询解析记录失败: {}", body_text),
            });
        }

        let parsed: NameComListResp = serde_json::from_str(&body_text)?;
        let records = parsed.records.unwrap_or_default();

        let matched = records.into_iter().find(|r| {
            r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                && (r
                    .host
                    .as_deref()
                    .unwrap_or("")
                    .eq_ignore_ascii_case(sub_name)
                    || (sub_name.is_empty() && r.host.as_deref() == Some("@")))
        });

        if let Some(existing) = matched {
            if existing.answer == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 更新记录 (PUT)
            let update_url = format!(
                "{}/{}/records/{}",
                NAME_COM_ENDPOINT, domain.root_domain, existing.id
            );

            let payload = json!({
                "host": sub_name,
                "type": record_type.to_string(),
                "answer": target_ip_str,
                "ttl": ttl_val
            });

            let put_resp = self
                .client
                .put(&update_url)
                .headers(self.build_headers())
                .json(&payload)
                .send()
                .await?;

            let put_status = put_resp.status();
            if put_status.is_success() {
                Ok(SyncRecordResult::updated_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ))
            } else {
                let err_text = put_resp.text().await.unwrap_or_default();
                Err(DnsProviderError::ApiError {
                    code: put_status.to_string(),
                    message: format!("Name.com 更新记录失败: {}", err_text),
                })
            }
        } else {
            // 创建记录 (POST)
            let create_url = format!("{}/{}/records", NAME_COM_ENDPOINT, domain.root_domain);

            let payload = json!({
                "host": sub_name,
                "type": record_type.to_string(),
                "answer": target_ip_str,
                "ttl": ttl_val
            });

            let post_resp = self
                .client
                .post(&create_url)
                .headers(self.build_headers())
                .json(&payload)
                .send()
                .await?;

            let post_status = post_resp.status();
            if post_status.is_success() {
                Ok(SyncRecordResult::created_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ))
            } else {
                let err_text = post_resp.text().await.unwrap_or_default();
                Err(DnsProviderError::ApiError {
                    code: post_status.to_string(),
                    message: format!("Name.com 创建记录失败: {}", err_text),
                })
            }
        }
    }
}

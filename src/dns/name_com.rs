use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType};
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

#[derive(Debug, Deserialize)]
struct NameComErrorResp {
    message: Option<String>,
    details: Option<String>,
}

fn check_namecom_error(
    body_text: &str,
    status: reqwest::StatusCode,
    action: &str,
) -> Result<(), DnsProviderError> {
    if let Ok(err) = serde_json::from_str::<NameComErrorResp>(body_text)
        && (err.message.is_some() || err.details.is_some())
    {
        let msg = err
            .message
            .or(err.details)
            .unwrap_or_else(|| body_text.to_string());
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Name.com {}业务失败: {}", action, msg),
        });
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Name.com {}: {}", action, body_text),
        });
    }

    Ok(())
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
        if let Ok(mut hv) = HeaderValue::from_str(&format!("Basic {}", auth_b64)) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl RecordOps for NameComProvider {
    fn provider_name(&self) -> &'static str {
        "Name.com"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        let list_url = format!("{}/{}/records", NAME_COM_ENDPOINT, domain.root_domain);

        let list_resp = self
            .client
            .get(&list_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = list_resp.status();
        let body_text = list_resp.text().await?;

        check_namecom_error(&body_text, status, "查询解析记录失败")?;

        let parsed: NameComListResp = serde_json::from_str(&body_text)?;
        let records = parsed.records.unwrap_or_default();

        let matched = records
            .into_iter()
            .filter(|r| {
                r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                    && (r
                        .host
                        .as_deref()
                        .unwrap_or("")
                        .eq_ignore_ascii_case(sub_name)
                        || (sub_name.is_empty() && r.host.as_deref() == Some("@")))
            })
            .map(|r| RemoteRecord::new(r.id.to_string(), r.answer))
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(300).max(1);
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };
        let target_ip_str = ip.to_string();

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
        let post_text = post_resp.text().await?;
        check_namecom_error(&post_text, post_status, "创建记录失败")?;

        Ok(())
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(300).max(1);
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };
        let target_ip_str = ip.to_string();

        let update_url = format!(
            "{}/{}/records/{}",
            NAME_COM_ENDPOINT, domain.root_domain, record_id
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
        let put_text = put_resp.text().await?;
        check_namecom_error(&put_text, put_status, "更新记录失败")?;

        Ok(())
    }
}

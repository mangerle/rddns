use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const GODADDY_API_BASE: &str = "https://api.godaddy.com/v1";

/// GoDaddy DNS 提供商
pub struct GoDaddyProvider {
    api_key: String,
    api_secret: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct GoDaddyRecord {
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GoDaddyErrorResp {
    code: Option<String>,
    message: Option<String>,
}

impl GoDaddyProvider {
    pub fn new(api_key: String, api_secret: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            api_secret,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_val = format!("sso-key {}:{}", self.api_key, self.api_secret);
        if let Ok(mut hv) = HeaderValue::from_str(&auth_val) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    /// 幂等写入/更新域名记录 (PUT /domains/{domain}/records/{type}/{name})
    async fn put_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let path = format!(
            "{}/domains/{}/records/{}/{}",
            GODADDY_API_BASE, zone, record_type, sub
        );

        let body = json!([
            {
                "data": ip.to_string(),
                "ttl": ttl_val
            }
        ]);

        let put_resp = self
            .client
            .put(&path)
            .headers(self.build_headers())
            .json(&body)
            .send()
            .await?;

        let status = put_resp.status();
        let body_text = put_resp.text().await.unwrap_or_default();
        if let Ok(err) = serde_json::from_str::<GoDaddyErrorResp>(&body_text)
            && (err.code.is_some() || err.message.is_some())
        {
            return Err(DnsProviderError::ApiError {
                code: err.code.unwrap_or_else(|| status.to_string()),
                message: format!("GoDaddy 响应错误: {}", err.message.unwrap_or(body_text)),
            });
        }

        if status.is_success() {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("GoDaddy 响应错误: {}", body_text),
            })
        }
    }
}

#[async_trait]
impl RecordOps for GoDaddyProvider {
    fn provider_name(&self) -> &'static str {
        "GoDaddy"
    }

    /// 查询现有解析记录列表
    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let path = format!(
            "{}/domains/{}/records/{}/{}",
            GODADDY_API_BASE, zone, record_type, sub
        );

        let query_resp = self
            .client
            .get(&path)
            .headers(self.build_headers())
            .send()
            .await?;

        if query_resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }

        let status = query_resp.status();
        let body = query_resp.text().await.unwrap_or_default();

        if let Ok(err) = serde_json::from_str::<GoDaddyErrorResp>(&body)
            && (err.code.is_some() || err.message.is_some())
        {
            return Err(DnsProviderError::ApiError {
                code: err.code.unwrap_or_else(|| status.to_string()),
                message: format!("GoDaddy 查询记录失败: {}", err.message.unwrap_or(body)),
            });
        }

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("GoDaddy 查询记录失败: {}", body),
            });
        }

        let records = serde_json::from_str::<Vec<GoDaddyRecord>>(&body)?;
        let matched = records
            .into_iter()
            .filter_map(|r| r.data.map(|d| RemoteRecord::new(sub, d)))
            .collect();

        Ok(matched)
    }

    /// 新增解析记录
    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        self.put_record(zone, domain, record_type, ip, ttl).await
    }

    /// 更新既有解析记录
    async fn update_record(
        &self,
        zone: &str,
        _record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        self.put_record(zone, domain, record_type, ip, ttl).await
    }
}

#[async_trait]
impl DnsProvider for GoDaddyProvider {
    fn provider_name(&self) -> &'static str {
        "GoDaddy"
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        sync_record_via(self, domain, record_type, ip, ttl).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_godaddy_record_deserialization() {
        let sample = r#"[
            {
                "data": "1.2.3.4",
                "name": "sub",
                "ttl": 600,
                "type": "A"
            }
        ]"#;

        let parsed: Vec<GoDaddyRecord> =
            serde_json::from_str(sample).expect("反序列化 GoDaddy 记录失败");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].data.as_deref(), Some("1.2.3.4"));
    }
}

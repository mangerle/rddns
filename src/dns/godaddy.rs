use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
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
        if let Ok(hv) = HeaderValue::from_str(&auth_val) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
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
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();

        let path = format!(
            "{}/domains/{}/records/{}/{}",
            GODADDY_API_BASE, domain.root_domain, record_type, sub
        );

        // 1. 查询当前记录
        let query_resp = self
            .client
            .get(&path)
            .headers(self.build_headers())
            .send()
            .await?;

        if query_resp.status().is_success()
            && let Ok(records) = query_resp.json::<Vec<GoDaddyRecord>>().await
            && let Some(existing) = records.first()
            && existing.data.as_deref() == Some(&target_ip_str)
        {
            info!(
                "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            return Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Unchanged,
                message: "记录未发生变化，无需更新".to_string(),
            });
        }

        // 2. 幂等更新/创建记录 (PUT /domains/{domain}/records/{type}/{name})
        let body = json!([
            {
                "data": target_ip_str,
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
        if status.is_success() {
            info!(
                "[{}] 成功更新/创建域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Updated,
                message: "记录更新成功".to_string(),
            })
        } else {
            let body_text = put_resp.text().await.unwrap_or_default();
            Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("GoDaddy 响应错误: {}", body_text),
            })
        }
    }
}

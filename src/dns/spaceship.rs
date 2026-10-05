use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::http::url_encode;
use async_trait::async_trait;
use log::warn;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const SPACESHIP_API_BASE: &str = "https://spaceship.dev/api/v1/dns/records";

/// Spaceship DNS 提供商 (Namecheap 旗下新平台)
pub struct SpaceshipProvider {
    api_key: String,
    api_secret: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct SpaceshipItem {
    #[serde(rename = "type")]
    record_type: String,
    address: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct SpaceshipListResponse {
    items: Option<Vec<SpaceshipItem>>,
}

#[derive(Debug, Deserialize)]
struct SpaceshipErrorResponse {
    detail: Option<String>,
}

impl SpaceshipProvider {
    pub fn new(api_key: String, api_secret: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            api_secret,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(mut hv) = HeaderValue::from_str(&self.api_key) {
            hv.set_sensitive(true);
            headers.insert(HeaderName::from_static("x-api-key"), hv);
        }
        if let Ok(mut hv) = HeaderValue::from_str(&self.api_secret) {
            hv.set_sensitive(true);
            headers.insert(HeaderName::from_static("x-api-secret"), hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl RecordOps for SpaceshipProvider {
    fn provider_name(&self) -> &'static str {
        "Spaceship"
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

        let domain_url = format!("{}/{}", SPACESHIP_API_BASE, url_encode(&domain.root_domain));

        let list_resp = self
            .client
            .get(&domain_url)
            .headers(self.build_headers())
            .query(&[("take", "500"), ("skip", "0")])
            .send()
            .await?;

        let status = list_resp.status();
        let body_text = list_resp.text().await?;

        if !status.is_success() {
            let err_detail = serde_json::from_str::<SpaceshipErrorResponse>(&body_text)
                .ok()
                .and_then(|e| e.detail)
                .unwrap_or(body_text);
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Spaceship 记录查询失败: {}", err_detail),
            });
        }

        let list_data: SpaceshipListResponse = serde_json::from_str(&body_text)?;
        let items = list_data.items.unwrap_or_default();

        let mut remotes = Vec::new();
        for item in items {
            if item
                .record_type
                .eq_ignore_ascii_case(&record_type.to_string())
                && (item.name.eq_ignore_ascii_case(sub_name)
                    || (sub_name.is_empty() && item.name == "@"))
            {
                remotes.push(RemoteRecord::new(item.address.clone(), item.address));
            }
        }
        Ok(remotes)
    }

    async fn create_record(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(600).max(60);
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };
        let domain_url = format!("{}/{}", SPACESHIP_API_BASE, url_encode(&domain.root_domain));

        let put_payload = json!({
            "force": true,
            "items": [
                {
                    "type": record_type.to_string(),
                    "address": ip.to_string(),
                    "name": sub_name,
                    "ttl": ttl_val
                }
            ]
        });

        let put_resp = self
            .client
            .put(&domain_url)
            .headers(self.build_headers())
            .json(&put_payload)
            .send()
            .await?;

        let put_status = put_resp.status();
        let put_body = put_resp.text().await.unwrap_or_default();
        if let Ok(err_resp) = serde_json::from_str::<SpaceshipErrorResponse>(&put_body)
            && err_resp.detail.is_some()
        {
            return Err(DnsProviderError::ApiError {
                code: put_status.to_string(),
                message: format!(
                    "Spaceship 记录写入失败: {}",
                    err_resp.detail.unwrap_or(put_body)
                ),
            });
        }

        if put_status.is_success() {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: put_status.to_string(),
                message: format!("Spaceship 记录写入失败: {}", put_body),
            })
        }
    }

    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };
        let domain_url = format!("{}/{}", SPACESHIP_API_BASE, url_encode(&domain.root_domain));

        // 先清理旧记录
        if !record_id.is_empty() && record_id != ip.to_string() {
            let del_payload = json!([{
                "type": record_type.to_string(),
                "address": record_id,
                "name": sub_name
            }]);

            match self
                .client
                .delete(&domain_url)
                .headers(self.build_headers())
                .json(&del_payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        warn!(
                            "Spaceship 删除旧解析记录响应非成功状态，HTTP 状态码: {}，详情: {}",
                            status, text
                        );
                    }
                }
                Err(e) => {
                    warn!("Spaceship 删除旧解析记录网络请求失败: {}", e);
                }
            }
        }

        self.create_record(zone, domain, record_type, ip, ttl).await
    }
}

#[async_trait]
impl DnsProvider for SpaceshipProvider {
    fn provider_name(&self) -> &'static str {
        <Self as RecordOps>::provider_name(self)
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

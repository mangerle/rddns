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
use std::time::Duration;

const GCORE_API_BASE: &str = "https://api.gcore.com/dns/v2";

/// Gcore DNS 提供商
pub struct GcoreProvider {
    api_key: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct GcoreZone {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GcoreZoneResponse {
    zones: Option<Vec<GcoreZone>>,
}

#[derive(Debug, Deserialize)]
struct GcoreResourceRecord {
    content: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct GcoreRRSet {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    resource_records: Option<Vec<GcoreResourceRecord>>,
}

#[derive(Debug, Deserialize)]
struct GcoreRRSetListResponse {
    rrsets: Option<Vec<GcoreRRSet>>,
}

impl GcoreProvider {
    pub fn new(api_key: String, http_interface: Option<&str>) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { api_key, client }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_val = if self.api_key.starts_with("APIKey ") || self.api_key.starts_with("Bearer ")
        {
            self.api_key.clone()
        } else {
            format!("APIKey {}", self.api_key)
        };
        if let Ok(hv) = HeaderValue::from_str(&auth_val) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl DnsProvider for GcoreProvider {
    fn provider_name(&self) -> &'static str {
        "Gcore DNS"
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
        let ttl_val = ttl.unwrap_or(120).max(1);

        // 1. 查询 Zone
        let zone_url = format!("{}/zones?name={}", GCORE_API_BASE, domain.root_domain);
        let zone_resp = self
            .client
            .get(&zone_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let zone_status = zone_resp.status();
        let zone_text = zone_resp.text().await?;

        if !zone_status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: zone_status.to_string(),
                message: format!("查询 Gcore Zone 失败: {}", zone_text),
            });
        }

        let zone_data: GcoreZoneResponse = serde_json::from_str(&zone_text)?;
        let zones = zone_data.zones.unwrap_or_default();
        let zone = zones
            .into_iter()
            .find(|z| z.name.eq_ignore_ascii_case(&domain.root_domain))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在 Gcore 中未找到域名 [{}] 对应的 Zone",
                    domain.root_domain
                ))
            })?;

        // 2. 查询现有 RRSet (带 limit=100 参数)
        let rrset_url = format!("{}/zones/{}/rrsets?limit=100", GCORE_API_BASE, zone.name);
        let rrset_resp = self
            .client
            .get(&rrset_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = rrset_resp.status();
        let rrset_text = rrset_resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Gcore 查询 RRSet 失败: {}", rrset_text),
            });
        }
        let rrset_data: GcoreRRSetListResponse = serde_json::from_str(&rrset_text)?;
        let rrsets = rrset_data.rrsets.unwrap_or_default();

        let matched = rrsets.into_iter().find(|r| {
            r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                && r.name
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(full_domain.trim_end_matches('.'))
        });

        let full_record_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            zone.name.clone()
        } else {
            format!("{}.{}", domain.sub_domain, zone.name)
        };

        let target_url = format!(
            "{}/zones/{}/{}/{}",
            GCORE_API_BASE, zone.name, full_record_name, record_type
        );

        let payload = json!({
            "ttl": ttl_val,
            "resource_records": [
                {
                    "content": [target_ip_str],
                    "enabled": true
                }
            ]
        });

        if let Some(existing) = matched {
            // 检查现有 IP 是否匹配
            let is_matched = existing
                .resource_records
                .and_then(|mut r| r.pop())
                .and_then(|rr| rr.content)
                .map(|contents| contents.iter().any(|c| c.as_str() == Some(&target_ip_str)))
                .unwrap_or(false);

            if is_matched {
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

            // 更新记录 (PUT)
            let put_resp = self
                .client
                .put(&target_url)
                .headers(self.build_headers())
                .json(&payload)
                .send()
                .await?;

            let put_status = put_resp.status();
            if put_status.is_success() {
                info!(
                    "[{}] 成功更新域名 {} -> {}",
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
                let err_text = put_resp.text().await.unwrap_or_default();
                Err(DnsProviderError::ApiError {
                    code: put_status.to_string(),
                    message: format!("Gcore 更新记录失败: {}", err_text),
                })
            }
        } else {
            // 创建记录 (POST)
            let post_resp = self
                .client
                .post(&target_url)
                .headers(self.build_headers())
                .json(&payload)
                .send()
                .await?;

            let post_status = post_resp.status();
            if post_status.is_success() {
                info!(
                    "[{}] 成功创建域名解析 {} -> {}",
                    self.provider_name(),
                    full_domain,
                    target_ip_str
                );
                Ok(SyncRecordResult {
                    domain: full_domain,
                    record_type,
                    target_ip: target_ip_str,
                    status: SyncStatus::Created,
                    message: "解析记录创建成功".to_string(),
                })
            } else {
                let err_text = post_resp.text().await.unwrap_or_default();
                Err(DnsProviderError::ApiError {
                    code: post_status.to_string(),
                    message: format!("Gcore 创建记录失败: {}", err_text),
                })
            }
        }
    }
}

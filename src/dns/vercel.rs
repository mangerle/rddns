use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

/// Vercel DNS 提供商
pub struct VercelProvider {
    token: String,
    team_id: Option<String>,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct VercelRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct VercelRecordsResp {
    records: Option<Vec<VercelRecord>>,
}

impl VercelProvider {
    pub fn new(token: String, team_id: Option<String>, http_interface: Option<&str>) -> Self {
        Self {
            token,
            team_id: team_id.filter(|t| !t.trim().is_empty()),
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    fn append_team_id(&self, base_url: &str) -> String {
        if let Some(ref tid) = self.team_id {
            if base_url.contains('?') {
                format!("{}&teamId={}", base_url, tid)
            } else {
                format!("{}?teamId={}", base_url, tid)
            }
        } else {
            base_url.to_string()
        }
    }
}

#[async_trait]
impl DnsProvider for VercelProvider {
    fn provider_name(&self) -> &'static str {
        "Vercel DNS"
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string().to_lowercase();
        let ttl_val = ttl.unwrap_or(60).max(60); // Vercel 规定 TTL 必须 >= 60

        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        // 1. 查询现有解析记录 (带 limit=100 参数)
        let list_url = self.append_team_id(&format!(
            "https://api.vercel.com/v4/domains/{}/records?limit=100",
            domain.root_domain
        ));

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
                message: format!("Vercel 查询记录失败: {}", body_text),
            });
        }

        let parsed: VercelRecordsResp = serde_json::from_str(&body_text)?;
        let records = parsed.records.unwrap_or_default();

        let matched = records.into_iter().find(|r| {
            r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                && domain.matches_record_name(&r.name)
        });

        if let Some(existing) = matched {
            if existing.value.to_lowercase() == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 更新记录
            let update_url = self.append_team_id(&format!(
                "https://api.vercel.com/v1/domains/records/{}",
                existing.id
            ));

            let update_payload = json!({
                "type": record_type.to_string(),
                "value": target_ip_str,
                "ttl": ttl_val
            });

            let patch_resp = self
                .client
                .patch(&update_url)
                .headers(self.build_headers())
                .json(&update_payload)
                .send()
                .await?;

            let patch_status = patch_resp.status();
            if patch_status.is_success() {
                Ok(SyncRecordResult::updated_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ))
            } else {
                let err_text = patch_resp.text().await.unwrap_or_default();
                Err(DnsProviderError::ApiError {
                    code: patch_status.to_string(),
                    message: format!("Vercel 更新记录失败: {}", err_text),
                })
            }
        } else {
            // 创建记录
            let create_url = self.append_team_id(&format!(
                "https://api.vercel.com/v2/domains/{}/records",
                domain.root_domain
            ));

            let create_payload = json!({
                "name": sub_name,
                "type": record_type.to_string(),
                "value": target_ip_str,
                "ttl": ttl_val,
                "comment": "Created by rddns"
            });

            let post_resp = self
                .client
                .post(&create_url)
                .headers(self.build_headers())
                .json(&create_payload)
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
                    message: format!("Vercel 创建记录失败: {}", err_text),
                })
            }
        }
    }
}

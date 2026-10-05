use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::http::url_encode;
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
struct VercelPagination {
    next: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct VercelRecordsResp {
    records: Option<Vec<VercelRecord>>,
    pagination: Option<VercelPagination>,
}

#[derive(Debug, Deserialize)]
struct VercelApiErrorDetail {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VercelErrorEnvelope {
    error: Option<VercelApiErrorDetail>,
}

/// 统一校验 Vercel API 响应，杜绝 HTTP 200 + {"error": ...} 静默误判成功
fn check_vercel_error(
    body_text: &str,
    status: reqwest::StatusCode,
) -> Result<(), DnsProviderError> {
    if let Ok(env) = serde_json::from_str::<VercelErrorEnvelope>(body_text)
        && let Some(err) = env.error
    {
        return Err(DnsProviderError::ApiError {
            code: err.code.unwrap_or_else(|| status.to_string()),
            message: format!(
                "Vercel API 业务失败: {}",
                err.message.unwrap_or_else(|| body_text.to_string())
            ),
        });
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Vercel API 请求失败: {}", body_text),
        });
    }

    Ok(())
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
        if let Ok(mut hv) = HeaderValue::from_str(&format!("Bearer {}", self.token)) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    fn append_team_id(&self, base_url: &str) -> String {
        if let Some(ref tid) = self.team_id {
            let encoded_tid = url_encode(tid);
            if base_url.contains('?') {
                format!("{}&teamId={}", base_url, encoded_tid)
            } else {
                format!("{}?teamId={}", base_url, encoded_tid)
            }
        } else {
            base_url.to_string()
        }
    }
}

#[async_trait]
impl RecordOps for VercelProvider {
    fn provider_name(&self) -> &'static str {
        "Vercel DNS"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let mut all_records = Vec::new();
        let mut next_cursor: Option<u64> = None;
        const MAX_PAGES: usize = 10;

        for _ in 0..MAX_PAGES {
            let base_url = format!(
                "https://api.vercel.com/v4/domains/{}/records?limit=100{}",
                url_encode(&domain.root_domain),
                next_cursor
                    .map(|c| format!("&until={}", c))
                    .unwrap_or_default()
            );
            let list_url = self.append_team_id(&base_url);

            let list_resp = self
                .client
                .get(&list_url)
                .headers(self.build_headers())
                .send()
                .await?;

            let status = list_resp.status();
            let body_text = list_resp.text().await?;
            check_vercel_error(&body_text, status)?;

            let parsed: VercelRecordsResp = serde_json::from_str(&body_text)?;
            let records = parsed.records.unwrap_or_default();
            let page_len = records.len();
            all_records.extend(records);

            if let Some(pagination) = parsed.pagination
                && let Some(next) = pagination.next
                && page_len >= 100
            {
                next_cursor = Some(next);
            } else {
                break;
            }
        }

        let matched = all_records
            .into_iter()
            .filter(|r| {
                r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                    && domain.matches_record_name(&r.name)
            })
            .map(|r| RemoteRecord::new(r.id, r.value))
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
        let ttl_val = ttl.unwrap_or(60).max(60);
        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        let create_url = self.append_team_id(&format!(
            "https://api.vercel.com/v2/domains/{}/records",
            url_encode(&domain.root_domain)
        ));

        let create_payload = json!({
            "name": sub_name,
            "type": record_type.to_string(),
            "value": ip.to_string(),
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
        let body_text = post_resp.text().await.unwrap_or_default();
        check_vercel_error(&body_text, post_status)?;
        Ok(())
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        _domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(60).max(60);
        let update_url = self.append_team_id(&format!(
            "https://api.vercel.com/v1/domains/records/{}",
            url_encode(record_id)
        ));

        let update_payload = json!({
            "type": record_type.to_string(),
            "value": ip.to_string(),
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
        let body_text = patch_resp.text().await.unwrap_or_default();
        check_vercel_error(&body_text, patch_status)?;
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for VercelProvider {
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

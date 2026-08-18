use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const DNSLA_RECORD_LIST_URL: &str = "https://api.dns.la/api/recordList";
const DNSLA_RECORD_URL: &str = "https://api.dns.la/api/record";

/// DNS.LA 提供商
pub struct DnsLaProvider {
    api_id: String,
    api_secret: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct DnsLaRecord {
    id: String,
    host: String,
    #[serde(rename = "type")]
    record_type: i32,
    data: String,
}

#[derive(Debug, Deserialize)]
struct DnsLaListData {
    results: Option<Vec<DnsLaRecord>>,
}

#[derive(Debug, Deserialize)]
struct DnsLaListResp {
    code: i32,
    msg: Option<String>,
    data: Option<DnsLaListData>,
}

#[derive(Debug, Deserialize)]
struct DnsLaActionResp {
    code: i32,
    msg: Option<String>,
}

impl DnsLaProvider {
    pub fn new(api_id: String, api_secret: String) -> Self {
        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            api_id,
            api_secret,
            client,
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let raw = format!("{}:{}", self.api_id, self.api_secret);
        let encoded = BASE64.encode(raw.as_bytes());
        if let Ok(hv) = HeaderValue::from_str(&format!("Basic {}", encoded)) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json;charset=utf-8"),
        );
        headers
    }

    fn record_type_to_int(record_type: DnsRecordType) -> i32 {
        match record_type {
            DnsRecordType::A => 1,
            DnsRecordType::AAAA => 28,
        }
    }
}

#[async_trait]
impl DnsProvider for DnsLaProvider {
    fn provider_name(&self) -> &'static str {
        "DNS.LA"
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
        let type_int = Self::record_type_to_int(record_type);

        // 1. 查询现有解析记录
        let list_url = format!(
            "{}?domain={}&host={}&type={}&pageIndex=1&pageSize=100",
            DNSLA_RECORD_LIST_URL, domain.root_domain, sub, type_int
        );

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
                message: format!("DNS.LA 查询解析记录失败: {}", body_text),
            });
        }

        let parsed: DnsLaListResp = serde_json::from_str(&body_text)?;
        if parsed.code != 200 {
            return Err(DnsProviderError::ApiError {
                code: parsed.code.to_string(),
                message: parsed.msg.unwrap_or_else(|| "DNS.LA 查询失败".to_string()),
            });
        }

        let records = parsed.data.and_then(|d| d.results).unwrap_or_default();

        let matched = records
            .into_iter()
            .find(|r| r.record_type == type_int && r.host.eq_ignore_ascii_case(sub));

        if let Some(existing) = matched {
            if existing.data == target_ip_str {
                tracing::info!(
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
            let modify_payload = json!({
                "Id": existing.id,
                "Host": sub,
                "Type": type_int,
                "Data": target_ip_str,
                "TTL": ttl_val
            });

            let put_resp = self
                .client
                .put(DNSLA_RECORD_URL)
                .headers(self.build_headers())
                .json(&modify_payload)
                .send()
                .await?;

            let put_text = put_resp.text().await?;
            let act_res: DnsLaActionResp =
                serde_json::from_str(&put_text).unwrap_or(DnsLaActionResp {
                    code: -1,
                    msg: Some(put_text.clone()),
                });

            if act_res.code == 200 {
                tracing::info!(
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
                let err_msg = act_res.msg.unwrap_or(put_text);
                Err(DnsProviderError::ApiError {
                    code: act_res.code.to_string(),
                    message: format!("DNS.LA 更新记录失败: {}", err_msg),
                })
            }
        } else {
            // 创建记录 (POST)
            let create_payload = json!({
                "Domain": domain.root_domain,
                "Host": sub,
                "Type": type_int,
                "Data": target_ip_str,
                "TTL": ttl_val
            });

            let post_resp = self
                .client
                .post(DNSLA_RECORD_URL)
                .headers(self.build_headers())
                .json(&create_payload)
                .send()
                .await?;

            let post_text = post_resp.text().await?;
            let act_res: DnsLaActionResp =
                serde_json::from_str(&post_text).unwrap_or(DnsLaActionResp {
                    code: -1,
                    msg: Some(post_text.clone()),
                });

            if act_res.code == 200 {
                tracing::info!(
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
                let err_msg = act_res.msg.unwrap_or(post_text);
                Err(DnsProviderError::ApiError {
                    code: act_res.code.to_string(),
                    message: format!("DNS.LA 创建记录失败: {}", err_msg),
                })
            }
        }
    }
}

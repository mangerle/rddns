use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const RAINYUN_ENDPOINT: &str = "https://api.v2.rainyun.com";

use parking_lot::RwLock;
use std::collections::HashMap;

/// 雨云 (RainYun) DNS 提供商
pub struct RainYunProvider {
    api_key: String,
    domain_id: Option<String>,
    client: Client,
    domain_cache: RwLock<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct RainyunRecord {
    record_id: i64,
    host: String,
    #[serde(rename = "type")]
    record_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct RainyunRecordList {
    #[serde(rename = "Records")]
    records: Option<Vec<RainyunRecord>>,
}

#[derive(Debug, Deserialize)]
struct RainyunDomainItem {
    id: i64,
    domain: String,
}

#[derive(Debug, Deserialize)]
struct RainyunDomainList {
    #[serde(rename = "DomainList")]
    domain_list: Option<Vec<RainyunDomainItem>>,
}

#[derive(Debug, Deserialize)]
struct RainyunResp {
    code: i32,
    message: Option<String>,
    data: Option<serde_json::Value>,
}

impl RainYunProvider {
    pub fn new(api_key: String, domain_id: Option<String>, http_interface: Option<&str>) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            api_key,
            domain_id: domain_id.filter(|d| !d.trim().is_empty()),
            client,
            domain_cache: RwLock::new(HashMap::new()),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(&self.api_key) {
            headers.insert(HeaderName::from_static("x-api-key"), hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    /// 获取或自动根据根域名查询 Domain ID (优先从内存缓存读取)
    async fn get_domain_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        if let Some(ref did) = self.domain_id {
            return Ok(did.clone());
        }

        if let Some(cached_id) = self.domain_cache.read().get(root_domain).cloned() {
            return Ok(cached_id);
        }

        // 自动查询域名列表
        let url = format!("{}/product/domain/?limit=100&page_no=1", RAINYUN_ENDPOINT);
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        let body_text = resp.text().await?;
        let res: RainyunResp = serde_json::from_str(&body_text)?;

        if res.code != 200 {
            return Err(DnsProviderError::ApiError {
                code: res.code.to_string(),
                message: res
                    .message
                    .unwrap_or_else(|| "查询雨云域名列表失败".to_string()),
            });
        }

        if let Some(data_val) = res.data {
            let list = serde_json::from_value::<RainyunDomainList>(data_val).ok();
            let matched = list
                .and_then(|l| l.domain_list)
                .unwrap_or_default()
                .into_iter()
                .find(|d| d.domain.eq_ignore_ascii_case(root_domain));

            if let Some(m) = matched {
                let did_str = m.id.to_string();
                self.domain_cache
                    .write()
                    .insert(root_domain.to_string(), did_str.clone());
                return Ok(did_str);
            }
        }

        Err(DnsProviderError::ZoneNotFound(format!(
            "在雨云账户中未找到域名 [{}] 对应的 Domain ID，请在配置中手动指定 Domain ID",
            root_domain
        )))
    }
}

#[async_trait]
impl DnsProvider for RainYunProvider {
    fn provider_name(&self) -> &'static str {
        "雨云 (RainYun)"
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

        let domain_id = self.get_domain_id(&domain.root_domain).await?;

        // 1. 查询现有解析记录
        let list_url = format!(
            "{}/product/domain/{}/dns/?limit=100&page_no=1",
            RAINYUN_ENDPOINT, domain_id
        );

        let list_resp = self
            .client
            .get(&list_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let body_text = list_resp.text().await?;
        let res: RainyunResp = serde_json::from_str(&body_text)?;

        if res.code != 200 {
            return Err(DnsProviderError::ApiError {
                code: res.code.to_string(),
                message: res
                    .message
                    .unwrap_or_else(|| "查询雨云 DNS 记录失败".to_string()),
            });
        }

        let mut matched: Option<RainyunRecord> = None;
        if let Some(data_val) = res.data {
            let rec_list = serde_json::from_value::<RainyunRecordList>(data_val).ok();
            matched = rec_list
                .and_then(|r| r.records)
                .unwrap_or_default()
                .into_iter()
                .find(|r| {
                    r.host.eq_ignore_ascii_case(sub)
                        && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                });
        }

        if let Some(existing) = matched {
            if existing.value == target_ip_str {
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

            // 更新记录
            let update_url = format!("{}/product/domain/{}/dns", RAINYUN_ENDPOINT, domain_id);
            let update_payload = json!({
                "host": sub,
                "type": record_type.to_string(),
                "value": target_ip_str,
                "line": "DEFAULT",
                "ttl": ttl_val,
                "level": 10,
                "record_id": existing.record_id
            });

            let patch_resp = self
                .client
                .patch(&update_url)
                .headers(self.build_headers())
                .json(&update_payload)
                .send()
                .await?;

            let patch_text = patch_resp.text().await?;
            let patch_res: RainyunResp = serde_json::from_str(&patch_text)?;

            if patch_res.code == 200 {
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
                Err(DnsProviderError::ApiError {
                    code: patch_res.code.to_string(),
                    message: patch_res
                        .message
                        .unwrap_or_else(|| "更新雨云记录失败".to_string()),
                })
            }
        } else {
            // 创建记录
            let create_url = format!("{}/product/domain/{}/dns", RAINYUN_ENDPOINT, domain_id);
            let create_payload = json!({
                "host": sub,
                "type": record_type.to_string(),
                "value": target_ip_str,
                "line": "DEFAULT",
                "ttl": ttl_val,
                "level": 10,
                "record_id": 0
            });

            let post_resp = self
                .client
                .post(&create_url)
                .headers(self.build_headers())
                .json(&create_payload)
                .send()
                .await?;

            let post_text = post_resp.text().await?;
            let post_res: RainyunResp = serde_json::from_str(&post_text)?;

            if post_res.code == 200 {
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
                Err(DnsProviderError::ApiError {
                    code: post_res.code.to_string(),
                    message: post_res
                        .message
                        .unwrap_or_else(|| "创建雨云记录失败".to_string()),
                })
            }
        }
    }
}

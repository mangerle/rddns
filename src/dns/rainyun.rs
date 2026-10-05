use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const RAINYUN_ENDPOINT: &str = "https://api.v2.rainyun.com";

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::LazyLock;

/// 全局雨云 Domain ID 缓存池 ((api_key, root_domain) -> domain_id)，实现多账号隔离与跨周期缓存复用
static GLOBAL_RAINYUN_DOMAIN_CACHE: LazyLock<RwLock<HashMap<(String, String), String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// 雨云 (RainYun) DNS 提供商
pub struct RainYunProvider {
    api_key: String,
    domain_id: Option<String>,
    client: Client,
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
        Self {
            api_key,
            domain_id: domain_id.filter(|d| !d.trim().is_empty()),
            client: crate::util::http::create_default_dns_client(http_interface),
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

    /// 获取或自动根据根域名查询 Domain ID (优先从全局内存缓存读取)
    async fn get_domain_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        if let Some(ref did) = self.domain_id {
            return Ok(did.clone());
        }

        let cache_key = (self.api_key.clone(), root_domain.to_string());
        if let Some(cached_id) = GLOBAL_RAINYUN_DOMAIN_CACHE.read().get(&cache_key).cloned() {
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
                GLOBAL_RAINYUN_DOMAIN_CACHE
                    .write()
                    .insert(cache_key, did_str.clone());
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
impl RecordOps for RainYunProvider {
    fn provider_name(&self) -> &'static str {
        "雨云 (RainYun)"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        self.get_domain_id(root_domain).await
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let list_url = format!(
            "{}/product/domain/{}/dns/?limit=100&page_no=1",
            RAINYUN_ENDPOINT, zone
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

        let mut remotes = Vec::new();
        if let Some(data_val) = res.data {
            let rec_list = serde_json::from_value::<RainyunRecordList>(data_val).ok();
            let matched = rec_list
                .and_then(|r| r.records)
                .unwrap_or_default()
                .into_iter()
                .filter(|r| {
                    r.host.eq_ignore_ascii_case(sub)
                        && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                })
                .map(|r| RemoteRecord::new(r.record_id.to_string(), r.value));
            remotes.extend(matched);
        }

        Ok(remotes)
    }

    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();
        let create_url = format!("{}/product/domain/{}/dns", RAINYUN_ENDPOINT, zone);
        let create_payload = json!({
            "host": sub,
            "type": record_type.to_string(),
            "value": ip.to_string(),
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
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: post_res.code.to_string(),
                message: post_res
                    .message
                    .unwrap_or_else(|| "创建雨云记录失败".to_string()),
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
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();
        let rid = record_id.parse::<i64>().unwrap_or(0);
        let update_url = format!("{}/product/domain/{}/dns", RAINYUN_ENDPOINT, zone);
        let update_payload = json!({
            "host": sub,
            "type": record_type.to_string(),
            "value": ip.to_string(),
            "line": "DEFAULT",
            "ttl": ttl_val,
            "level": 10,
            "record_id": rid
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
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: patch_res.code.to_string(),
                message: patch_res
                    .message
                    .unwrap_or_else(|| "更新雨云记录失败".to_string()),
            })
        }
    }
}

#[async_trait]
impl DnsProvider for RainYunProvider {
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

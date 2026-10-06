use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType};
use crate::dns::zone_cache::TtlCache;
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const RAINYUN_ENDPOINT: &str = "https://api.v2.rainyun.com";

use std::sync::LazyLock;
use std::time::Duration;

/// 雨云 Domain ID 缓存生存期（2 小时）
const RAINYUN_DOMAIN_CACHE_TTL: Duration = Duration::from_secs(7200);

/// 雨云 Domain ID 缓存容量硬上限
const RAINYUN_DOMAIN_CACHE_CAPACITY: usize = 128;

/// 雨云 Domain ID 缓存键（API Key 摘要 + 根域名）
///
/// # 安全设计
/// 使用 API Key 的 SHA-256 摘要而非原文作为缓存键，避免凭据以明文形式
/// 常驻内存并出现在内存转储中。
type RainyunDomainKey = (String, String);

/// 全局雨云 Domain ID 缓存池
///
/// # 重构说明 (P1-9)
/// 与 Cloudflare 的 Zone 缓存实现逐行同构，现统一复用 [`TtlCache`]。
static GLOBAL_RAINYUN_DOMAIN_CACHE: LazyLock<TtlCache<RainyunDomainKey, String>> =
    LazyLock::new(|| TtlCache::new(RAINYUN_DOMAIN_CACHE_TTL, RAINYUN_DOMAIN_CACHE_CAPACITY));

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
        if let Ok(mut hv) = HeaderValue::from_str(&self.api_key) {
            hv.set_sensitive(true);
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

        let cache_key = (
            crate::util::crypto::sha256_hex(self.api_key.as_bytes()),
            root_domain.to_string(),
        );
        if let Some(cached_id) = GLOBAL_RAINYUN_DOMAIN_CACHE.get(&cache_key) {
            return Ok(cached_id);
        }

        // 自动查询域名列表 (支持最多 10 页分页检索)
        let mut page_no = 1u32;
        const MAX_PAGES: u32 = 10;
        for _ in 0..MAX_PAGES {
            let url = format!(
                "{}/product/domain/?limit=100&page_no={}",
                RAINYUN_ENDPOINT, page_no
            );
            let resp = self
                .client
                .get(&url)
                .headers(self.build_headers())
                .send()
                .await?;

            let status = resp.status();
            let body_text = resp.text().await?;

            // 必须先判 HTTP 状态码：网关 502/503 返回的是 HTML 错误页，
            // 直接反序列化会变成 Json 错误，而 Json 在 is_retryable() 中
            // 恒为 false，导致瞬时故障永久失去重试机会 (P1-8)
            if !status.is_success() {
                return Err(DnsProviderError::http_status(status, &body_text));
            }

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
                let domain_items = list.and_then(|l| l.domain_list).unwrap_or_default();
                let page_len = domain_items.len();
                let matched = domain_items
                    .into_iter()
                    .find(|d| d.domain.eq_ignore_ascii_case(root_domain));

                if let Some(m) = matched {
                    let did_str = m.id.to_string();
                    GLOBAL_RAINYUN_DOMAIN_CACHE.insert(cache_key, did_str.clone());
                    return Ok(did_str);
                }

                if page_len < 100 {
                    break;
                }
                page_no = page_no.saturating_add(1);
            } else {
                break;
            }
        }

        Err(DnsProviderError::ZoneNotFound(root_domain.to_string()))
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
        let mut remotes = Vec::new();
        let mut page_no = 1u32;
        const MAX_PAGES: u32 = 10;

        for _ in 0..MAX_PAGES {
            let list_url = format!(
                "{}/product/domain/{}/dns/?limit=100&page_no={}",
                RAINYUN_ENDPOINT, zone, page_no
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

            let mut page_len = 0;
            if let Some(data_val) = res.data {
                let rec_list = serde_json::from_value::<RainyunRecordList>(data_val).ok();
                let records = rec_list.and_then(|r| r.records).unwrap_or_default();
                page_len = records.len();
                let matched = records
                    .into_iter()
                    .filter(|r| {
                        r.host.eq_ignore_ascii_case(sub)
                            && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                    })
                    .map(|r| RemoteRecord::new(r.record_id.to_string(), r.value));
                remotes.extend(matched);
            }

            if page_len < 100 {
                break;
            }
            page_no = page_no.saturating_add(1);
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

        let post_status = post_resp.status();
        let post_text = post_resp.text().await?;

        // 同上：先判状态码，避免 HTML 错误页被误判为不可重试的 Json 错误 (P1-8)
        if !post_status.is_success() {
            return Err(DnsProviderError::http_status(post_status, &post_text));
        }

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
        let rid = record_id.parse::<i64>().map_err(|e| {
            DnsProviderError::api(
                "InvalidRecordId",
                format!("雨云解析记录更新失败：无效的记录 ID 数字格式: {record_id}, 错误: {e}"),
            )
        })?;
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

        let patch_status = patch_resp.status();
        let patch_text = patch_resp.text().await?;

        // 同上：先判状态码，避免 HTML 错误页被误判为不可重试的 Json 错误 (P1-8)
        if !patch_status.is_success() {
            return Err(DnsProviderError::http_status(patch_status, &patch_text));
        }

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

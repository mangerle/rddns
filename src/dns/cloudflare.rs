use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Duration;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ZoneCacheKey {
    auth_identity: String,
    root_domain: String,
}

/// 全局 Cloudflare Zone ID 缓存池 ((auth_identity, root_domain) -> zone_id)，实现多账号隔离与跨周期缓存复用
static GLOBAL_CF_ZONE_CACHE: LazyLock<RwLock<HashMap<ZoneCacheKey, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

pub struct CloudflareProvider {
    client: Client,
    api_token: Option<String>,
    api_key: Option<String>,
    email: Option<String>,
    auth_identity: String,
}

impl CloudflareProvider {
    pub fn new(
        api_token: Option<String>,
        api_key: Option<String>,
        email: Option<String>,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        let has_token = api_token
            .as_ref()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false);
        let has_key = api_key
            .as_ref()
            .map(|k| !k.trim().is_empty())
            .unwrap_or(false);

        if !has_token && !has_key {
            return Err(DnsProviderError::MissingCredentials(
                "Cloudflare 需要配置 API Token 或 API Key + 邮箱".to_string(),
            ));
        }

        let auth_identity = if let Some(ref t) = api_token {
            format!("token:{}", t.trim())
        } else {
            format!(
                "key:{}:{}",
                api_key.as_deref().unwrap_or(""),
                email.as_deref().unwrap_or("")
            )
        };

        let client =
            crate::util::http::create_task_http_client(http_interface, Duration::from_secs(15))?;

        Ok(Self {
            client,
            api_token,
            api_key,
            email,
            auth_identity,
        })
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(ref token) = self.api_token
            && !token.trim().is_empty()
            && let Ok(val) = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
        {
            headers.insert(AUTHORIZATION, val);
            return headers;
        }

        if let (Some(key), Some(email)) = (&self.api_key, &self.email) {
            if let Ok(k_val) = HeaderValue::from_str(key.trim()) {
                headers.insert("X-Auth-Key", k_val);
            }
            if let Ok(e_val) = HeaderValue::from_str(email.trim()) {
                headers.insert("X-Auth-Email", e_val);
            }
        }

        headers
    }

    /// 查询根域名对应的 Zone ID (优先从带账号隔离的内存缓存读取)
    async fn get_zone_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let cache_key = ZoneCacheKey {
            auth_identity: self.auth_identity.clone(),
            root_domain: root_domain.to_string(),
        };

        if let Some(cached_id) = GLOBAL_CF_ZONE_CACHE.read().get(&cache_key).cloned() {
            return Ok(cached_id);
        }

        let url = format!("{}/zones?name={}&status=active", CF_API_BASE, root_domain);
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        let zones: Vec<CfZone> = parse_cf_response(resp, "CloudflareZoneError").await?;
        let zone = zones
            .into_iter()
            .next()
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;

        GLOBAL_CF_ZONE_CACHE
            .write()
            .insert(cache_key, zone.id.clone());

        Ok(zone.id)
    }

    /// 获取特定域名的 DNS 记录
    async fn get_records(
        &self,
        zone_id: &str,
        full_domain: &str,
        record_type: DnsRecordType,
    ) -> Result<Vec<CfRecord>, DnsProviderError> {
        let url = format!(
            "{}/zones/{}/dns_records?name={}&type={}",
            CF_API_BASE, zone_id, full_domain, record_type
        );
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        parse_cf_response(resp, "CloudflareRecordError").await
    }
}

/// 通用 Cloudflare API 响应解析器
async fn parse_cf_response<T: for<'de> Deserialize<'de>>(
    resp: reqwest::Response,
    default_err_code: &'static str,
) -> Result<T, DnsProviderError> {
    let status = resp.status();
    let body_text = resp.text().await?;

    if let Ok(data) = serde_json::from_str::<CfApiResponse<T>>(&body_text) {
        if data.success
            && let Some(res) = data.result
        {
            return Ok(res);
        }
        let msg = data
            .errors
            .into_iter()
            .map(|e| e.message)
            .collect::<Vec<_>>()
            .join("; ");
        if !msg.is_empty() {
            return Err(DnsProviderError::ApiError {
                code: format!("{} ({})", default_err_code, status),
                message: msg,
            });
        }
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: body_text,
        });
    }

    let data: CfApiResponse<T> = serde_json::from_str(&body_text)?;
    data.result
        .ok_or_else(|| DnsProviderError::Other("Cloudflare 响应缺少 result 数据实体".to_string()))
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    fn provider_name(&self) -> &'static str {
        "Cloudflare"
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
        let ttl_val = ttl.unwrap_or(1); // 1 代表 Cloudflare 的 Auto TTL

        // 1. 获取 Zone ID
        let zone_id = self.get_zone_id(&domain.root_domain).await?;

        // 2. 查询现有记录
        let records = self
            .get_records(&zone_id, &full_domain, record_type)
            .await?;

        // 3. 若存在多条同名同类型历史记录，清理除第一条以外的冗余冲突项
        if records.len() > 1 {
            for redundant in &records[1..] {
                let del_url = format!(
                    "{}/zones/{}/dns_records/{}",
                    CF_API_BASE, zone_id, redundant.id
                );
                let _ = self
                    .client
                    .delete(&del_url)
                    .headers(self.build_headers())
                    .send()
                    .await;
            }
        }

        if let Some(existing) = records.first() {
            if existing.content == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 更新记录 (使用 PATCH 保持用户既有的 proxied 代理加速状态)
            let update_url = format!(
                "{}/zones/{}/dns_records/{}",
                CF_API_BASE, zone_id, existing.id
            );
            let body = json!({
                "content": target_ip_str,
                "ttl": ttl_val,
            });

            let resp = self
                .client
                .patch(&update_url)
                .headers(self.build_headers())
                .json(&body)
                .send()
                .await?;

            let _: CfRecord = parse_cf_response(resp, "CloudflareUpdateFailed").await?;
            Ok(SyncRecordResult::updated_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        } else {
            // 新增记录
            let create_url = format!("{}/zones/{}/dns_records", CF_API_BASE, zone_id);
            let body = json!({
                "type": record_type.to_string(),
                "name": full_domain,
                "content": target_ip_str,
                "ttl": ttl_val,
                "proxied": false
            });

            let resp = self
                .client
                .post(&create_url)
                .headers(self.build_headers())
                .json(&body)
                .send()
                .await?;

            let _: CfRecord = parse_cf_response(resp, "CloudflareCreateFailed").await?;
            Ok(SyncRecordResult::created_log(
                self.provider_name(),
                full_domain,
                record_type,
                target_ip_str,
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
struct CfApiResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CfApiError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct CfZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CfRecord {
    id: String,
    content: String,
}

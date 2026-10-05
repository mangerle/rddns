use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType};
use async_trait::async_trait;
use log::warn;
use parking_lot::RwLock;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare 以TTL=1 表示「自动 TTL」，与用户未指定时的语义一致
const CF_AUTO_TTL: u32 = 1;

/// Cloudflare Zone ID 缓存生存期（2 小时）
const CF_ZONE_CACHE_TTL: Duration = Duration::from_secs(7200);

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct ZoneCacheKey {
    auth_identity: String,
    root_domain: String,
}

/// 全局 Cloudflare Zone ID 缓存池 ((auth_identity, root_domain) -> (created_at, zone_id))
static GLOBAL_CF_ZONE_CACHE: LazyLock<RwLock<HashMap<ZoneCacheKey, (Instant, String)>>> =
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
            format!(
                "token:{}",
                crate::util::crypto::sha256_hex(t.trim().as_bytes())
            )
        } else {
            format!(
                "key:{}:{}",
                crate::util::crypto::sha256_hex(api_key.as_deref().unwrap_or("").as_bytes()),
                email.as_deref().unwrap_or("")
            )
        };

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = crate::util::http::create_default_dns_client(http_interface);

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
            && let Ok(mut val) = HeaderValue::from_str(&format!("Bearer {}", token.trim()))
        {
            val.set_sensitive(true);
            headers.insert(AUTHORIZATION, val);
            return headers;
        }

        if let (Some(key), Some(email)) = (&self.api_key, &self.email) {
            if let Ok(mut k_val) = HeaderValue::from_str(key.trim()) {
                k_val.set_sensitive(true);
                headers.insert("X-Auth-Key", k_val);
            }
            if let Ok(mut e_val) = HeaderValue::from_str(email.trim()) {
                e_val.set_sensitive(true);
                headers.insert("X-Auth-Email", e_val);
            }
        }

        headers
    }

    /// 归一化 TTL 取值
    ///
    /// # 设计原理
    /// Cloudflare API 以 `1` 表示「自动 TTL」。用户在配置中未显式指定时
    /// 同样应落到该语义，故此处把 `None` 映射为 `1`。
    fn normalize_ttl(ttl: Option<u32>) -> u32 {
        ttl.unwrap_or(CF_AUTO_TTL)
    }

    /// 解析该域名是否应开启 CDN 代理加速
    ///
    /// # 设计原理
    /// 依据域名自定义参数 `?proxied=true`（或 `proxy`）判定。
    /// 保持与迁移前完全一致的宽松布尔解析：接受 true/1/yes 且忽略大小写。
    fn resolve_proxied_flag(domain: &ParsedDomain) -> bool {
        domain
            .custom_params
            .get("proxied")
            .or_else(|| domain.custom_params.get("proxy"))
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false)
    }

    /// 查询根域名对应的 Zone ID (优先从带账号隔离的内存缓存读取)
    async fn get_zone_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let cache_key = ZoneCacheKey {
            auth_identity: self.auth_identity.clone(),
            root_domain: root_domain.to_string(),
        };

        if let Some((created_at, cached_id)) = GLOBAL_CF_ZONE_CACHE.read().get(&cache_key).cloned()
            && created_at.elapsed() < CF_ZONE_CACHE_TTL
        {
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

        let mut guard = GLOBAL_CF_ZONE_CACHE.write();
        if guard.len() >= 128 {
            guard.clear();
        }
        guard.insert(cache_key, (Instant::now(), zone.id.clone()));

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

/// Cloudflare 的记录操作适配层
///
/// # 设计原理
/// 将「Zone 解析 / 列出 / 创建 / 更新」四类厂商差异封装于此，
/// 上层「查 - 比 - 改」骨架复用 [`sync_record_via`] 模板，
/// 避免逐家重复实现同一套编排逻辑。
#[async_trait]
impl RecordOps for CloudflareProvider {
    fn provider_name(&self) -> &'static str {
        "Cloudflare"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        self.get_zone_id(root_domain).await
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let records = self
            .get_records(zone, &domain.full_domain(), record_type)
            .await?;
        Ok(records
            .into_iter()
            .map(|r| RemoteRecord::new(r.id, r.content))
            .collect())
    }

    /// 清理同名同类型的历史冗余记录
    ///
    /// # 设计原理
    /// Cloudflare 允许存在多条同名同类型记录，若只更新首条会遗留冲突项，
    /// 导致 DNS 轮询返回非预期结果。
    async fn before_sync(&self, zone: &str, records: &[RemoteRecord]) {
        for redundant in records.iter().skip(1) {
            let del_url = format!(
                "{}/zones/{}/dns_records/{}",
                CF_API_BASE, zone, redundant.id
            );
            match self
                .client
                .delete(&del_url)
                .headers(self.build_headers())
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        warn!(
                            "清理 Cloudflare 冗余记录 {} 失败，HTTP 状态码: {}，详情: {}",
                            redundant.id, status, text
                        );
                    }
                }
                Err(e) => {
                    warn!("清理 Cloudflare 冗余记录 {} 失败: {}", redundant.id, e);
                }
            }
        }
    }

    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let create_url = format!("{}/zones/{}/dns_records", CF_API_BASE, zone);
        let body = json!({
            "type": record_type.to_string(),
            "name": domain.full_domain(),
            "content": ip.to_string(),
            "ttl": Self::normalize_ttl(ttl),
            // 读取自定义参数 ?proxied=true 决定是否开启 CDN 代理加速
            "proxied": Self::resolve_proxied_flag(domain),
        });

        let resp = self
            .client
            .post(&create_url)
            .headers(self.build_headers())
            .json(&body)
            .send()
            .await?;

        let _: CfRecord = parse_cf_response(resp, "CloudflareCreateFailed").await?;
        Ok(())
    }

    /// 更新既有记录 (使用 PATCH 以保持用户既有的 proxied 代理加速状态)
    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        _domain: &ParsedDomain,
        _record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let update_url = format!("{}/zones/{}/dns_records/{}", CF_API_BASE, zone, record_id);
        let body = json!({
            "content": ip.to_string(),
            "ttl": Self::normalize_ttl(ttl),
        });

        let resp = self
            .client
            .patch(&update_url)
            .headers(self.build_headers())
            .json(&body)
            .send()
            .await?;

        let _: CfRecord = parse_cf_response(resp, "CloudflareUpdateFailed").await?;
        Ok(())
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

use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

use parking_lot::RwLock;
use std::collections::HashMap;

/// 全局 Cloudflare Zone ID 缓存池 (root_domain -> zone_id)，实现跨任务与跨周期缓存复用
static GLOBAL_CF_ZONE_CACHE: std::sync::LazyLock<RwLock<HashMap<String, String>>> =
    std::sync::LazyLock::new(|| RwLock::new(HashMap::new()));

pub struct CloudflareProvider {
    client: Client,
    api_token: Option<String>,
    api_key: Option<String>,
    email: Option<String>,
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

        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()?;

        Ok(Self {
            client,
            api_token,
            api_key,
            email,
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

    /// 查询根域名对应的 Zone ID (优先从内存缓存读取)
    async fn get_zone_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        if let Some(cached_id) = GLOBAL_CF_ZONE_CACHE.read().get(root_domain).cloned() {
            return Ok(cached_id);
        }

        let url = format!("{}/zones?name={}&status=active", CF_API_BASE, root_domain);
        let resp = self
            .client
            .get(&url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_data) = serde_json::from_str::<CfApiResponse<Vec<CfZone>>>(&body_text) {
                let msg = err_data
                    .errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ");
                if !msg.is_empty() {
                    return Err(DnsProviderError::ApiError {
                        code: format!("CloudflareZoneError ({})", status),
                        message: msg,
                    });
                }
            }
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let data: CfApiResponse<Vec<CfZone>> = serde_json::from_str(&body_text)?;
        if !data.success {
            let msg = data
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DnsProviderError::ApiError {
                code: "CloudflareZoneError".to_string(),
                message: msg,
            });
        }

        let zone = data
            .result
            .and_then(|zones| zones.into_iter().next())
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;

        GLOBAL_CF_ZONE_CACHE
            .write()
            .insert(root_domain.to_string(), zone.id.clone());

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

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_data) = serde_json::from_str::<CfApiResponse<Vec<CfRecord>>>(&body_text) {
                let msg = err_data
                    .errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ");
                if !msg.is_empty() {
                    return Err(DnsProviderError::ApiError {
                        code: format!("CloudflareRecordError ({})", status),
                        message: msg,
                    });
                }
            }
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let data: CfApiResponse<Vec<CfRecord>> = serde_json::from_str(&body_text)?;
        if !data.success {
            let msg = data
                .errors
                .into_iter()
                .map(|e| e.message)
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DnsProviderError::ApiError {
                code: "CloudflareRecordError".to_string(),
                message: msg,
            });
        }

        Ok(data.result.unwrap_or_default())
    }
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

        if let Some(existing) = records.first() {
            if existing.content == target_ip_str {
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

            // 更新记录 (使用 PATCH 保持用户的 proxied 状态)
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

            let status = resp.status();
            let body_text = resp.text().await?;

            if !status.is_success() {
                if let Ok(err_data) = serde_json::from_str::<CfApiResponse<CfRecord>>(&body_text) {
                    let msg = err_data
                        .errors
                        .into_iter()
                        .map(|e| e.message)
                        .collect::<Vec<_>>()
                        .join("; ");
                    if !msg.is_empty() {
                        return Err(DnsProviderError::ApiError {
                            code: format!("CloudflareUpdateFailed ({})", status),
                            message: msg,
                        });
                    }
                }
                return Err(DnsProviderError::ApiError {
                    code: status.to_string(),
                    message: body_text,
                });
            }

            let result: CfApiResponse<CfRecord> = serde_json::from_str(&body_text)?;
            if result.success {
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
                let msg = result
                    .errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(DnsProviderError::ApiError {
                    code: "CloudflareUpdateFailed".to_string(),
                    message: msg,
                })
            }
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

            let status = resp.status();
            let body_text = resp.text().await?;

            if !status.is_success() {
                if let Ok(err_data) = serde_json::from_str::<CfApiResponse<CfRecord>>(&body_text) {
                    let msg = err_data
                        .errors
                        .into_iter()
                        .map(|e| e.message)
                        .collect::<Vec<_>>()
                        .join("; ");
                    if !msg.is_empty() {
                        return Err(DnsProviderError::ApiError {
                            code: format!("CloudflareCreateFailed ({})", status),
                            message: msg,
                        });
                    }
                }
                return Err(DnsProviderError::ApiError {
                    code: status.to_string(),
                    message: body_text,
                });
            }

            let result: CfApiResponse<CfRecord> = serde_json::from_str(&body_text)?;
            if result.success {
                tracing::info!(
                    "[{}] 成功创建域名 {} -> {}",
                    self.provider_name(),
                    full_domain,
                    target_ip_str
                );
                Ok(SyncRecordResult {
                    domain: full_domain,
                    record_type,
                    target_ip: target_ip_str,
                    status: SyncStatus::Created,
                    message: "记录添加成功".to_string(),
                })
            } else {
                let msg = result
                    .errors
                    .into_iter()
                    .map(|e| e.message)
                    .collect::<Vec<_>>()
                    .join("; ");
                Err(DnsProviderError::ApiError {
                    code: "CloudflareCreateFailed".to_string(),
                    message: msg,
                })
            }
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

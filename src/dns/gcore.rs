use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, MIN_DNS_TTL, clamp_ttl};
use crate::dns::zone_cache::{
    DEFAULT_ZONE_CACHE_CAPACITY, DEFAULT_ZONE_CACHE_TTL, TtlCache, ZoneCacheKey,
};
use crate::util::crypto::sha256_hex;
use crate::util::http::url_encode;
use async_trait::async_trait;
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::sync::LazyLock;

const GCORE_API_BASE: &str = "https://api.gcore.com/dns/v2";
const GCORE_DEFAULT_TTL: u32 = 120;

static GLOBAL_GCORE_ZONE_CACHE: LazyLock<TtlCache<ZoneCacheKey, String>> =
    LazyLock::new(|| TtlCache::new(DEFAULT_ZONE_CACHE_TTL, DEFAULT_ZONE_CACHE_CAPACITY));

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

#[derive(Debug, Deserialize)]
struct GcoreErrorResp {
    error: Option<String>,
    message: Option<String>,
}

fn check_gcore_error(
    body_text: &str,
    status: reqwest::StatusCode,
    action: &str,
) -> Result<(), DnsProviderError> {
    if let Ok(err) = serde_json::from_str::<GcoreErrorResp>(body_text)
        && (err.error.is_some() || err.message.is_some())
    {
        let msg = err
            .message
            .or(err.error)
            .unwrap_or_else(|| body_text.to_string());
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Gcore {}业务失败: {}", action, msg),
        });
    }

    if !status.is_success() {
        return Err(DnsProviderError::ApiError {
            code: status.to_string(),
            message: format!("Gcore {}: {}", action, body_text),
        });
    }

    Ok(())
}

impl GcoreProvider {
    pub fn new(api_key: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_val = if self.api_key.starts_with("APIKey ") || self.api_key.starts_with("Bearer ")
        {
            self.api_key.clone()
        } else {
            format!("APIKey {}", self.api_key)
        };
        if let Ok(mut hv) = HeaderValue::from_str(&auth_val) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl RecordOps for GcoreProvider {
    fn provider_name(&self) -> &'static str {
        "Gcore DNS"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let auth_id = sha256_hex(self.api_key.trim().as_bytes());
        let cache_key = ZoneCacheKey::new(auth_id, root_domain);
        if let Some(zone_name) = GLOBAL_GCORE_ZONE_CACHE.get(&cache_key) {
            return Ok(zone_name);
        }

        let zone_url = format!("{}/zones?name={}", GCORE_API_BASE, root_domain);
        let zone_resp = self
            .client
            .get(&zone_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let zone_status = zone_resp.status();
        let zone_text = zone_resp.text().await?;
        check_gcore_error(&zone_text, zone_status, "查询 Zone 失败")?;

        let zone_data: GcoreZoneResponse = serde_json::from_str(&zone_text)?;
        let zones = zone_data.zones.unwrap_or_default();
        let zone = zones
            .into_iter()
            .find(|z| z.name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;

        GLOBAL_GCORE_ZONE_CACHE.insert(cache_key, zone.name.clone());
        Ok(zone.name)
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let rrset_url = format!("{}/zones/{}/rrsets?limit=100", GCORE_API_BASE, zone);
        let rrset_resp = self
            .client
            .get(&rrset_url)
            .headers(self.build_headers())
            .send()
            .await?;

        let status = rrset_resp.status();
        let rrset_text = rrset_resp.text().await?;
        check_gcore_error(&rrset_text, status, "查询 RRSet 失败")?;
        let rrset_data: GcoreRRSetListResponse = serde_json::from_str(&rrset_text)?;
        let rrsets = rrset_data.rrsets.unwrap_or_default();

        let mut remotes = Vec::new();
        for r in rrsets {
            if r.record_type.eq_ignore_ascii_case(&record_type.to_string())
                && domain.matches_record_name(&r.name)
                && let Some(rrs) = r.resource_records
            {
                for rr in rrs {
                    if let Some(contents) = rr.content {
                        for c in contents {
                            if let Some(ip_str) = c.as_str() {
                                remotes.push(RemoteRecord::new(&r.name, ip_str));
                            }
                        }
                    }
                }
            }
        }

        Ok(remotes)
    }

    async fn create_record(
        &self,
        zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = clamp_ttl(params.ttl, GCORE_DEFAULT_TTL, MIN_DNS_TTL);
        let target_ip_str = params.ip.to_string();

        let full_record_name =
            if params.domain.sub_domain.is_empty() || params.domain.sub_domain == "@" {
                zone.to_string()
            } else {
                format!("{}.{}", params.domain.sub_domain, zone)
            };

        let target_url = format!(
            "{}/zones/{}/{}/{}",
            GCORE_API_BASE,
            url_encode(zone),
            url_encode(&full_record_name),
            params.record_type
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

        let post_resp = self
            .client
            .post(&target_url)
            .headers(self.build_headers())
            .json(&payload)
            .send()
            .await?;

        let post_status = post_resp.status();
        let post_text = post_resp.text().await?;
        check_gcore_error(&post_text, post_status, "创建记录失败")?;

        Ok(())
    }

    async fn update_record(
        &self,
        zone: &str,
        _record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = clamp_ttl(params.ttl, GCORE_DEFAULT_TTL, MIN_DNS_TTL);
        let target_ip_str = params.ip.to_string();

        let full_record_name =
            if params.domain.sub_domain.is_empty() || params.domain.sub_domain == "@" {
                zone.to_string()
            } else {
                format!("{}.{}", params.domain.sub_domain, zone)
            };

        let target_url = format!(
            "{}/zones/{}/{}/{}",
            GCORE_API_BASE,
            url_encode(zone),
            url_encode(&full_record_name),
            params.record_type
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

        let put_resp = self
            .client
            .put(&target_url)
            .headers(self.build_headers())
            .json(&payload)
            .send()
            .await?;

        let put_status = put_resp.status();
        let put_text = put_resp.text().await?;
        check_gcore_error(&put_text, put_status, "更新记录失败")?;

        Ok(())
    }

    async fn delete_record(
        &self,
        zone: &str,
        record: &RemoteRecord,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let _ = (zone, record, params);
        Ok(())
    }
}

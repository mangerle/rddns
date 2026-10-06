use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType};
use async_trait::async_trait;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const DYNV6_ENDPOINT: &str = "https://dynv6.com/api/v2";

/// Dynv6 免费 IPv6/IPv4 动态 DNS 提供商
pub struct Dynv6Provider {
    token: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct Dynv6Zone {
    id: u64,
    name: String,
    #[serde(rename = "ipv4address")]
    ipv4_address: Option<String>,
    #[serde(rename = "ipv6prefix")]
    ipv6_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Dynv6Record {
    id: u64,
    name: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Dynv6ErrorResp {
    error: Option<String>,
    message: Option<String>,
}

impl Dynv6Provider {
    pub fn new(token: String, http_interface: Option<&str>) -> Self {
        Self {
            token,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_val = format!("Bearer {}", self.token);
        if let Ok(mut hv) = HeaderValue::from_str(&auth_val) {
            hv.set_sensitive(true);
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, DnsProviderError> {
        let url = format!("{}{}", DYNV6_ENDPOINT, path);
        let mut req = self
            .client
            .request(method, &url)
            .headers(self.build_headers());
        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if let Ok(err) = serde_json::from_str::<Dynv6ErrorResp>(&body_text)
            && (err.error.is_some() || err.message.is_some())
        {
            let code = err.error.unwrap_or_else(|| status.to_string());
            let msg = err.message.unwrap_or_else(|| body_text.clone());
            return Err(DnsProviderError::ApiError {
                code,
                message: format!("Dynv6 响应错误: {}", msg),
            });
        }

        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &body_text));
        }

        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl RecordOps for Dynv6Provider {
    fn provider_name(&self) -> &'static str {
        "Dynv6"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let zones: Vec<Dynv6Zone> = self.request(Method::GET, "/zones", None).await?;
        let matched = zones
            .into_iter()
            .find(|z| {
                root_domain.eq_ignore_ascii_case(&z.name)
                    || root_domain.ends_with(&format!(".{}", z.name))
            })
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;
        Ok(matched.id.to_string())
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let zone_id: u64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 zone_id: {}", e)))?;
        let full_domain = domain.full_domain();

        let zone_detail: Dynv6Zone = self
            .request(Method::GET, &format!("/zones/{}", zone_id), None)
            .await?;
        let is_main_domain = full_domain.eq_ignore_ascii_case(&zone_detail.name);

        if is_main_domain {
            let cur_ip = match record_type {
                DnsRecordType::A => zone_detail.ipv4_address,
                DnsRecordType::AAAA => zone_detail.ipv6_prefix,
            };
            return Ok(cur_ip
                .map(|ip| vec![RemoteRecord::new("zone", ip)])
                .unwrap_or_default());
        }

        let sub_name = full_domain
            .strip_suffix(&format!(".{}", zone_detail.name))
            .unwrap_or(&domain.sub_domain);

        let records: Vec<Dynv6Record> = self
            .request(Method::GET, &format!("/zones/{}/records", zone_id), None)
            .await?;

        let record_type_str = record_type.to_string();
        let matched: Vec<RemoteRecord> = records
            .into_iter()
            .filter(|r| {
                r.name.as_deref() == Some(sub_name)
                    && r.record_type.as_deref() == Some(&record_type_str)
            })
            .filter_map(|r| r.data.map(|d| RemoteRecord::new(r.id.to_string(), d)))
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        _ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let zone_id: u64 = zone
            .parse()
            .map_err(|e| DnsProviderError::Other(format!("无效的 zone_id: {}", e)))?;
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();

        let zone_detail: Dynv6Zone = self
            .request(Method::GET, &format!("/zones/{}", zone_id), None)
            .await?;
        let is_main_domain = full_domain.eq_ignore_ascii_case(&zone_detail.name);

        if is_main_domain {
            let patch_body = match record_type {
                DnsRecordType::A => json!({ "ipv4address": target_ip_str }),
                DnsRecordType::AAAA => json!({ "ipv6prefix": target_ip_str }),
            };
            let _: serde_json::Value = self
                .request(
                    Method::PATCH,
                    &format!("/zones/{}", zone_id),
                    Some(patch_body),
                )
                .await?;
        } else {
            let sub_name = full_domain
                .strip_suffix(&format!(".{}", zone_detail.name))
                .unwrap_or(&domain.sub_domain);
            let post_body = json!({
                "name": sub_name,
                "type": record_type.to_string(),
                "data": target_ip_str
            });
            let _: serde_json::Value = self
                .request(
                    Method::POST,
                    &format!("/zones/{}/records", zone_id),
                    Some(post_body),
                )
                .await?;
        }

        Ok(())
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
        if record_id == "zone" {
            self.create_record(zone, domain, record_type, ip, ttl).await
        } else {
            let zone_id: u64 = zone
                .parse()
                .map_err(|e| DnsProviderError::Other(format!("无效的 zone_id: {}", e)))?;
            let target_ip_str = ip.to_string();
            let patch_body = json!({
                "type": record_type.to_string(),
                "data": target_ip_str
            });
            let _: serde_json::Value = self
                .request(
                    Method::PATCH,
                    &format!("/zones/{}/records/{}", zone_id, record_id),
                    Some(patch_body),
                )
                .await?;
            Ok(())
        }
    }

    async fn delete_record(&self, zone: &str, record_id: &str) -> Result<(), DnsProviderError> {
        if record_id != "zone" {
            let zone_id: u64 = zone
                .parse()
                .map_err(|e| DnsProviderError::Other(format!("无效的 zone_id: {}", e)))?;
            let _: serde_json::Value = self
                .request(
                    Method::DELETE,
                    &format!("/zones/{}/records/{}", zone_id, record_id),
                    None,
                )
                .await?;
        }
        Ok(())
    }
}

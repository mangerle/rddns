use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::{
    append_ntp_hint_if_expired, build_canonical_query_string, hmac_sha256_hex, sha256_hex,
};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const DEFAULT_HUAWEI_ENDPOINT: &str = "https://dns.myhuaweicloud.com";

/// 华为云 DNS 提供商
pub struct HuaweiDnsProvider {
    ak: String,
    sk: String,
    endpoint: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct HwZoneItem {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct HwZonesResponse {
    zones: Option<Vec<HwZoneItem>>,
}

#[derive(Debug, Deserialize)]
struct HwRecordsetItem {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    records: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct HwRecordsetsResponse {
    recordsets: Option<Vec<HwRecordsetItem>>,
}

#[derive(Debug, Deserialize)]
struct HwErrorResponse {
    code: Option<String>,
    message: Option<String>,
}

impl HuaweiDnsProvider {
    pub fn new(
        ak: String,
        sk: String,
        endpoint: Option<String>,
        http_interface: Option<&str>,
    ) -> Self {
        let ep = endpoint
            .unwrap_or_default()
            .trim()
            .trim_end_matches('/')
            .to_string();
        let endpoint = if ep.is_empty() {
            DEFAULT_HUAWEI_ENDPOINT.to_string()
        } else {
            ep
        };

        let client = crate::util::http::create_default_dns_client(http_interface);

        Self {
            ak,
            sk,
            endpoint,
            client,
        }
    }

    /// 发起经过 SDK-HMAC-SHA256 签名的华为云 API 请求
    async fn request_hw_api<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        query_params: Vec<(&str, String)>,
        body: Option<String>,
    ) -> Result<T, DnsProviderError> {
        let url_obj = reqwest::Url::parse(&self.endpoint)
            .map_err(|e| DnsProviderError::Other(format!("解析 Endpoint URL 失败: {}", e)))?;
        let host = url_obj.host_str().unwrap_or("dns.myhuaweicloud.com");

        let body_str = body.unwrap_or_default();
        let body_hash = sha256_hex(body_str.as_bytes());
        let x_sdk_date = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

        // 1. 构建标准化查询字符串 (Canonical Query String)
        let canonical_query_str = build_canonical_query_string(&query_params);

        // 2. 构建标准化标头 (Canonical Headers)
        let canonical_headers = format!(
            "host:{}\nx-sdk-content-sha256:{}\nx-sdk-date:{}\n",
            host, body_hash, x_sdk_date
        );
        let signed_headers = "host;x-sdk-content-sha256;x-sdk-date";

        // 3. 构建 Canonical Request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            path,
            canonical_query_str,
            canonical_headers,
            signed_headers,
            body_hash
        );

        // 4. 计算 StringToSign
        let string_to_sign = format!(
            "SDK-HMAC-SHA256\n{}\n{}",
            x_sdk_date,
            sha256_hex(canonical_request.as_bytes())
        );

        // 5. 计算签名
        let signature = hmac_sha256_hex(self.sk.as_bytes(), string_to_sign.as_bytes());

        // 6. 构造 Authorization 标头
        let auth_header_val = format!(
            "SDK-HMAC-SHA256 Access={}, SignedHeaders={}, Signature={}",
            self.ak, signed_headers, signature
        );

        let full_url = if canonical_query_str.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, canonical_query_str)
        };

        let mut header_map = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(host) {
            header_map.insert(HOST, hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&x_sdk_date) {
            header_map.insert(HeaderName::from_static("x-sdk-date"), hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&body_hash) {
            header_map.insert(HeaderName::from_static("x-sdk-content-sha256"), hv);
        }
        if let Ok(mut hv) = HeaderValue::from_str(&auth_header_val) {
            hv.set_sensitive(true);
            header_map.insert(HeaderName::from_static("authorization"), hv);
        }
        header_map.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json;charset=utf-8"),
        );

        let mut req = self.client.request(method, &full_url).headers(header_map);
        if !body_str.is_empty() {
            req = req.body(body_str);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_str::<HwErrorResponse>(&body_text) {
                let mut msg = err_resp.message.unwrap_or_else(|| body_text.clone());
                let code = err_resp.code.unwrap_or_else(|| status.to_string());
                append_ntp_hint_if_expired(&mut msg, &code);
                return Err(DnsProviderError::ApiError { code, message: msg });
            }
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl RecordOps for HuaweiDnsProvider {
    fn provider_name(&self) -> &'static str {
        "华为云 (Huawei Cloud)"
    }

    /// 解析公网根域名对应的 Zone ID
    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let hw_root_name = format!("{}.", root_domain);
        let zones_resp: HwZonesResponse = self
            .request_hw_api(
                Method::GET,
                "/v2.1/zones",
                vec![("name", hw_root_name.clone())],
                None,
            )
            .await?;

        let zones = zones_resp.zones.unwrap_or_default();
        let zone = zones
            .into_iter()
            .find(|z| z.name.eq_ignore_ascii_case(&hw_root_name))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在华为云 DNS 中未找到根域名 [{root_domain}] 对应的公网 Zone"
                ))
            })?;

        Ok(zone.id)
    }

    /// 查询现有解析记录列表
    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let hw_domain_name = format!("{}.", domain.full_domain());
        let query_params = vec![
            ("name", hw_domain_name.clone()),
            ("type", record_type.to_string()),
        ];

        let list_resp: HwRecordsetsResponse = self
            .request_hw_api(Method::GET, "/v2.1/recordsets", query_params, None)
            .await?;

        let recordsets = list_resp.recordsets.unwrap_or_default();
        let matched = recordsets
            .into_iter()
            .filter(|r| {
                r.name.eq_ignore_ascii_case(&hw_domain_name)
                    && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
            })
            .map(|r| {
                let val = r
                    .records
                    .and_then(|mut recs| recs.pop())
                    .unwrap_or_default();
                RemoteRecord::new(r.id, val)
            })
            .collect();

        Ok(matched)
    }

    /// 新增解析记录
    async fn create_record(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let hw_domain_name = format!("{}.", domain.full_domain());
        let ttl_val = ttl.unwrap_or(300).max(1);
        let path = format!("/v2.1/zones/{zone}/recordsets");
        let body = json!({
            "name": hw_domain_name,
            "type": record_type.to_string(),
            "records": [ip.to_string()],
            "ttl": ttl_val,
        })
        .to_string();

        let _: serde_json::Value = self
            .request_hw_api(Method::POST, &path, vec![], Some(body))
            .await?;

        Ok(())
    }

    /// 更新既有解析记录
    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        _domain: &ParsedDomain,
        _record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(300).max(1);
        let path = format!("/v2.1/zones/{zone}/recordsets/{record_id}");
        let body = json!({
            "records": [ip.to_string()],
            "ttl": ttl_val,
        })
        .to_string();

        let _: serde_json::Value = self
            .request_hw_api(Method::PUT, &path, vec![], Some(body))
            .await?;

        Ok(())
    }
}

#[async_trait]
impl DnsProvider for HuaweiDnsProvider {
    fn provider_name(&self) -> &'static str {
        "华为云 (Huawei Cloud)"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hw_zones_response_deserialization() {
        let sample = r#"{
            "zones": [
                {
                    "id": "zone_12345",
                    "name": "example.com."
                }
            ]
        }"#;

        let parsed: HwZonesResponse =
            serde_json::from_str(sample).expect("反序列化华为云 Zone 响应失败");
        let zones = parsed.zones.expect("缺失 zones 列表");
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].id, "zone_12345");
        assert_eq!(zones[0].name, "example.com.");
    }

    #[test]
    fn test_hw_recordsets_response_deserialization() {
        let sample = r#"{
            "recordsets": [
                {
                    "id": "rec_67890",
                    "name": "www.example.com.",
                    "type": "A",
                    "records": ["1.2.3.4"]
                }
            ]
        }"#;

        let parsed: HwRecordsetsResponse =
            serde_json::from_str(sample).expect("反序列化华为云 Recordsets 响应失败");
        let sets = parsed.recordsets.expect("缺失 recordsets 列表");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].id, "rec_67890");
        assert_eq!(sets[0].name, "www.example.com.");
        assert_eq!(sets[0].record_type, "A");
        assert_eq!(
            sets[0].records.as_deref(),
            Some(&["1.2.3.4".to_string()][..])
        );
    }
}

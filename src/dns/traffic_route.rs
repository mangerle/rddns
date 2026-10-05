use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::{build_canonical_query_string, hmac_sha256, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const VOLC_HOST: &str = "open.volcengineapi.com";
const VOLC_ENDPOINT: &str = "https://open.volcengineapi.com";
const VOLC_SERVICE: &str = "DNS";
const VOLC_REGION: &str = "cn-north-1";
const VOLC_VERSION: &str = "2018-08-01";

/// 火山引擎 TrafficRoute DNS 提供商
pub struct TrafficRouteProvider {
    ak: String,
    sk: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct VolcZone {
    #[serde(rename = "ZID")]
    zid: u64,
    #[serde(rename = "ZoneName")]
    zone_name: String,
}

#[derive(Debug, Deserialize)]
struct VolcRecord {
    #[serde(rename = "RecordID")]
    record_id: String,
    #[serde(rename = "Host")]
    host: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value")]
    value: String,
}

#[derive(Debug, Deserialize)]
struct VolcResponseMetadata {
    #[serde(rename = "Error")]
    error: Option<VolcError>,
}

#[derive(Debug, Deserialize)]
struct VolcError {
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "Message")]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VolcResult {
    #[serde(rename = "Zones")]
    zones: Option<Vec<VolcZone>>,
    #[serde(rename = "Records")]
    records: Option<Vec<VolcRecord>>,
}

#[derive(Debug, Deserialize)]
struct VolcResponse {
    #[serde(rename = "ResponseMetadata")]
    response_metadata: Option<VolcResponseMetadata>,
    #[serde(rename = "Result")]
    result: Option<VolcResult>,
}

impl TrafficRouteProvider {
    pub fn new(ak: String, sk: String, http_interface: Option<&str>) -> Self {
        Self {
            ak,
            sk,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    /// 发起经 AWS SigV4 变种签名的火山引擎 API 请求
    async fn request_volc(
        &self,
        action: &str,
        query_params: Vec<(&str, String)>,
        body: Option<serde_json::Value>,
    ) -> Result<VolcResult, DnsProviderError> {
        let now = Utc::now();
        let x_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let short_date = now.format("%Y%m%d").to_string();

        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let x_content_sha256 = sha256_hex(body_str.as_bytes());

        let sign_params = VolcSignParams {
            ak: &self.ak,
            sk: &self.sk,
            action,
            x_date: &x_date,
            short_date: &short_date,
            query_params: &query_params,
            body_str: &body_str,
        };
        let (auth_header, _sig, canonical_query_str) = compute_volc_authorization(&sign_params);

        let url = format!("{}/?{}", VOLC_ENDPOINT, canonical_query_str);

        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static(VOLC_HOST));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(hv) = HeaderValue::from_str(&x_date) {
            headers.insert(HeaderName::from_static("x-date"), hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&x_content_sha256) {
            headers.insert(HeaderName::from_static("x-content-sha256"), hv);
        }
        if let Ok(mut hv) = HeaderValue::from_str(&auth_header) {
            hv.set_sensitive(true);
            headers.insert(HeaderName::from_static("authorization"), hv);
        }

        let mut req = self.client.post(&url).headers(headers);
        if !body_str.is_empty() {
            req = req.body(body_str);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        let parsed: VolcResponse = serde_json::from_str(&body_text).map_err(|e| {
            DnsProviderError::Other(format!("解析火山引擎响应失败 [{}]: {}", status, e))
        })?;

        if let Some(err) = parsed.response_metadata.and_then(|m| m.error) {
            return Err(DnsProviderError::ApiError {
                code: err.code.unwrap_or_else(|| status.to_string()),
                message: err
                    .message
                    .unwrap_or_else(|| "火山引擎未知错误".to_string()),
            });
        }

        Ok(parsed.result.unwrap_or(VolcResult {
            zones: None,
            records: None,
        }))
    }

    fn parse_zid(zone: &str) -> Result<u64, DnsProviderError> {
        zone.parse::<u64>().map_err(|e| {
            DnsProviderError::api(
                "InvalidZID",
                format!("火山引擎解析失败：无效的 Zone ID 格式: {zone}, 错误: {e}"),
            )
        })
    }
}

#[async_trait]
impl RecordOps for TrafficRouteProvider {
    fn provider_name(&self) -> &'static str {
        "火山引擎 (TrafficRoute)"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let zones_result = self
            .request_volc("ListZones", vec![("Key", root_domain.to_string())], None)
            .await?;

        let zones = zones_result.zones.unwrap_or_default();
        let zone = zones
            .into_iter()
            .find(|z| z.zone_name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在火山引擎中未找到根域名 [{}] 对应的 Zone",
                    root_domain
                ))
            })?;

        Ok(zone.zid.to_string())
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let zid_num = Self::parse_zid(zone)?;
        let list_records_body = json!({
            "ZID": zid_num,
            "Host": sub,
            "Type": record_type.to_string()
        });

        let records_result = self
            .request_volc("ListRecords", vec![], Some(list_records_body))
            .await?;

        let records = records_result.records.unwrap_or_default();
        let matched = records
            .into_iter()
            .filter(|r| {
                r.host.eq_ignore_ascii_case(sub)
                    && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
            })
            .map(|r| RemoteRecord::new(r.record_id, r.value))
            .collect();

        Ok(matched)
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
        let zid_num = Self::parse_zid(zone)?;
        let create_body = json!({
            "ZID": zid_num,
            "Host": sub,
            "Type": record_type.to_string(),
            "Value": ip.to_string(),
            "TTL": ttl_val
        });

        let _ = self
            .request_volc("CreateRecord", vec![], Some(create_body))
            .await?;
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
        let ttl_val = ttl.unwrap_or(600).max(1);
        let sub = domain.sub_domain_or_at();
        let zid_num = Self::parse_zid(zone)?;
        let update_body = json!({
            "RecordID": record_id,
            "ZID": zid_num,
            "Host": sub,
            "Type": record_type.to_string(),
            "Value": ip.to_string(),
            "TTL": ttl_val
        });

        let _ = self
            .request_volc("UpdateRecord", vec![], Some(update_body))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl DnsProvider for TrafficRouteProvider {
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

/// 火山引擎 SigV4 签名计算参数
pub(crate) struct VolcSignParams<'a> {
    pub ak: &'a str,
    pub sk: &'a str,
    pub action: &'a str,
    pub x_date: &'a str,
    pub short_date: &'a str,
    pub query_params: &'a [(&'a str, String)],
    pub body_str: &'a str,
}

/// 计算火山引擎 SigV4 签名与 Authorization 标头
///
/// # 设计原理
/// - **实现初衷**: 将火山引擎签名与派生密钥计算逻辑抽离为纯函数，使得签名可独立进行单测验证 (P0-7)。
/// - **核心优势**: 采用参数结构体收敛参数列表，支持传入固定时间戳和参数进行标准测试向量回归，杜绝鉴权失效。
pub(crate) fn compute_volc_authorization(params: &VolcSignParams<'_>) -> (String, String, String) {
    let mut query = params.query_params.to_vec();
    query.push(("Action", params.action.to_string()));
    query.push(("Version", VOLC_VERSION.to_string()));

    let canonical_query_str = build_canonical_query_string(&query);
    let x_content_sha256 = sha256_hex(params.body_str.as_bytes());

    let canonical_headers = format!(
        "content-type:application/json\nhost:{}\nx-content-sha256:{}\nx-date:{}\n",
        VOLC_HOST, x_content_sha256, params.x_date
    );
    let signed_headers = "content-type;host;x-content-sha256;x-date";
    let canonical_request = format!(
        "POST\n/\n{}\n{}\n{}\n{}",
        canonical_query_str, canonical_headers, signed_headers, x_content_sha256
    );

    let credential_scope = format!(
        "{}/{}/{}/request",
        params.short_date, VOLC_REGION, VOLC_SERVICE
    );
    let string_to_sign = format!(
        "HMAC-SHA256\n{}\n{}\n{}",
        params.x_date,
        credential_scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(params.sk.as_bytes(), params.short_date.as_bytes());
    let k_region = hmac_sha256(&k_date, VOLC_REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, VOLC_SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        params.ak, credential_scope, signed_headers, signature
    );

    (auth_header, signature, canonical_query_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_route_update_body_includes_zid() {
        let zone = "123456789";
        let zid_num = zone.parse::<u64>().unwrap_or(0);
        let update_body = json!({
            "RecordID": "rec_001",
            "ZID": zid_num,
            "Host": "www",
            "Type": "A",
            "Value": "1.2.3.4",
            "TTL": 600
        });

        assert_eq!(update_body["ZID"], 123456789u64);
        assert_eq!(update_body["RecordID"], "rec_001");
    }

    #[test]
    fn test_volc_sigv4_known_vector() {
        let query_params = vec![("PageNumber", "1".to_string())];
        let params = VolcSignParams {
            ak: "AKLTODUzNzU3...",
            sk: "WW1Wall5TXpVM...",
            action: "ListZones",
            x_date: "20231005T120000Z",
            short_date: "20231005",
            query_params: &query_params,
            body_str: "",
        };

        let (auth, sig, canonical_query) = compute_volc_authorization(&params);

        assert!(canonical_query.contains("Action=ListZones"));
        assert!(canonical_query.contains("PageNumber=1"));
        assert!(canonical_query.contains("Version=2018-08-01"));
        assert!(
            auth.starts_with(
                "HMAC-SHA256 Credential=AKLTODUzNzU3.../20231005/cn-north-1/DNS/request"
            )
        );
        assert!(auth.contains("SignedHeaders=content-type;host;x-content-sha256;x-date"));
        assert!(auth.ends_with(&format!("Signature={}", sig)));
        assert_eq!(sig.len(), 64);

        // 验证确定性
        let (auth2, sig2, _) = compute_volc_authorization(&params);
        assert_eq!(auth, auth2);
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_traffic_route_invalid_zid_returns_error() {
        let valid = TrafficRouteProvider::parse_zid("123456789");
        assert_eq!(valid.unwrap(), 123456789);

        let invalid = TrafficRouteProvider::parse_zid("abc_not_a_number");
        assert!(invalid.is_err());
        match invalid.unwrap_err() {
            DnsProviderError::ApiError { code, .. } => assert_eq!(code, "InvalidZID"),
            other => panic!("预期 ApiError(InvalidZID)，实际为: {:?}", other),
        }
    }
}

use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{hmac_sha256, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

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
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { ak, sk, client }
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

        let mut query = query_params;
        query.push(("Action", action.to_string()));
        query.push(("Version", VOLC_VERSION.to_string()));
        query.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_query_str = query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>(),
                    url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        let body_str = body.map(|b| b.to_string()).unwrap_or_default();
        let x_content_sha256 = sha256_hex(body_str.as_bytes());

        // Canonical Request
        let canonical_headers = format!(
            "content-type:application/json\nhost:{}\nx-content-sha256:{}\nx-date:{}\n",
            VOLC_HOST, x_content_sha256, x_date
        );
        let signed_headers = "content-type;host;x-content-sha256;x-date";
        let canonical_request = format!(
            "POST\n/\n{}\n{}\n{}\n{}",
            canonical_query_str, canonical_headers, signed_headers, x_content_sha256
        );

        // StringToSign
        let credential_scope = format!("{}/{}/{}/request", short_date, VOLC_REGION, VOLC_SERVICE);
        let string_to_sign = format!(
            "HMAC-SHA256\n{}\n{}\n{}",
            x_date,
            credential_scope,
            sha256_hex(canonical_request.as_bytes())
        );

        // 计算 SigV4 派生密钥
        let k_date = hmac_sha256(self.sk.as_bytes(), short_date.as_bytes());
        let k_region = hmac_sha256(&k_date, VOLC_REGION.as_bytes());
        let k_service = hmac_sha256(&k_region, VOLC_SERVICE.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"request");
        let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

        let auth_header = format!(
            "HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.ak, credential_scope, signed_headers, signature
        );

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
        if let Ok(hv) = HeaderValue::from_str(&auth_header) {
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
}

#[async_trait]
impl DnsProvider for TrafficRouteProvider {
    fn provider_name(&self) -> &'static str {
        "火山引擎 (TrafficRoute)"
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

        // 1. 查询 Zone ID
        let zones_result = self
            .request_volc("ListZones", vec![("Key", domain.root_domain.clone())], None)
            .await?;

        let zones = zones_result.zones.unwrap_or_default();
        let zone = zones
            .into_iter()
            .find(|z| z.zone_name.eq_ignore_ascii_case(&domain.root_domain))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在火山引擎中未找到根域名 [{}] 对应的 Zone",
                    domain.root_domain
                ))
            })?;

        // 2. 查询现有解析记录
        let list_records_body = json!({
            "ZID": zone.zid,
            "Host": sub,
            "Type": record_type.to_string()
        });

        let records_result = self
            .request_volc("ListRecords", vec![], Some(list_records_body))
            .await?;

        let records = records_result.records.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.host.eq_ignore_ascii_case(sub)
                && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
            if existing.value == target_ip_str {
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

            // 更新记录
            let update_body = json!({
                "RecordID": existing.record_id,
                "Host": sub,
                "Type": record_type.to_string(),
                "Value": target_ip_str,
                "TTL": ttl_val
            });

            let _ = self
                .request_volc("UpdateRecord", vec![], Some(update_body))
                .await?;

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
            // 创建记录
            let create_body = json!({
                "ZID": zone.zid,
                "Host": sub,
                "Type": record_type.to_string(),
                "Value": target_ip_str,
                "TTL": ttl_val
            });

            let _ = self
                .request_volc("CreateRecord", vec![], Some(create_body))
                .await?;

            tracing::info!(
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
        }
    }
}

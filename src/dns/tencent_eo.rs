use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{hmac_sha256, sha256_hex};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const TEO_ENDPOINT: &str = "https://teo.tencentcloudapi.com";
const TEO_HOST: &str = "teo.tencentcloudapi.com";
const TEO_SERVICE: &str = "teo";
const TEO_VERSION: &str = "2022-09-01";

/// 腾讯云 EdgeOne (TEO) 提供商
pub struct TencentEoProvider {
    client: Client,
    secret_id: String,
    secret_key: String,
}

#[derive(Debug, Deserialize)]
struct TeoError {
    #[serde(rename = "Code")]
    code: String,
    #[serde(rename = "Message")]
    message: String,
}

#[derive(Debug, Deserialize)]
struct TeoZoneItem {
    #[serde(rename = "ZoneId")]
    zone_id: String,
    #[serde(rename = "ZoneName")]
    zone_name: String,
}

#[derive(Debug, Deserialize)]
struct TeoZoneRespData {
    #[serde(rename = "Zones")]
    zones: Option<Vec<TeoZoneItem>>,
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoZoneResp {
    #[serde(rename = "Response")]
    response: TeoZoneRespData,
}

#[derive(Debug, Deserialize)]
struct TeoRecordItem {
    #[serde(rename = "RecordId")]
    record_id: Option<String>,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Content")]
    content: String,
}

#[derive(Debug, Deserialize)]
struct TeoRecordRespData {
    #[serde(rename = "DnsRecords")]
    dns_records: Option<Vec<TeoRecordItem>>,
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoRecordResp {
    #[serde(rename = "Response")]
    response: TeoRecordRespData,
}

#[derive(Debug, Deserialize)]
struct TeoActionRespData {
    #[serde(rename = "Error")]
    error: Option<TeoError>,
}

#[derive(Debug, Deserialize)]
struct TeoActionResp {
    #[serde(rename = "Response")]
    response: TeoActionRespData,
}

impl TencentEoProvider {
    pub fn new(secret_id: String, secret_key: String) -> Result<Self, DnsProviderError> {
        if secret_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "腾讯云 EdgeOne 需要配置 SecretId 与 SecretKey".to_string(),
            ));
        }

        let client = Client::builder().timeout(Duration::from_secs(15)).build()?;

        Ok(Self {
            client,
            secret_id,
            secret_key,
        })
    }

    /// 发起腾讯云 TC3-HMAC-SHA256 签名请求
    async fn request_tc3_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        payload_json: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        let payload_str = payload_json.to_string();
        let timestamp = Utc::now().timestamp();
        let date = Utc::now().format("%Y-%m-%d").to_string();

        // 1. 构造规范请求串 CanonicalRequest
        let canonical_headers = format!(
            "content-type:application/json; charset=utf-8\nhost:{}\nx-tc-action:{}\nx-tc-timestamp:{}\n",
            TEO_HOST,
            action.to_ascii_lowercase(),
            timestamp
        );
        let signed_headers = "content-type;host;x-tc-action;x-tc-timestamp";
        let hashed_payload = sha256_hex(payload_str.as_bytes());

        let canonical_request = format!(
            "POST\n/\n\n{}\n{}\n{}",
            canonical_headers, signed_headers, hashed_payload
        );

        // 2. 构造待签名字符串 StringToSign
        let credential_scope = format!("{}/{}/tc3_request", date, TEO_SERVICE);
        let hashed_canonical_request = sha256_hex(canonical_request.as_bytes());
        let string_to_sign = format!(
            "TC3-HMAC-SHA256\n{}\n{}\n{}",
            timestamp, credential_scope, hashed_canonical_request
        );

        // 3. 计算签名 Signature
        let secret_date = hmac_sha256(
            format!("TC3{}", self.secret_key).as_bytes(),
            date.as_bytes(),
        );
        let secret_service = hmac_sha256(&secret_date, TEO_SERVICE.as_bytes());
        let secret_signing = hmac_sha256(&secret_service, b"tc3_request");
        let signature = hex::encode(hmac_sha256(&secret_signing, string_to_sign.as_bytes()));

        // 4. 构造 Authorization
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.secret_id, credential_scope, signed_headers, signature
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers.insert(HOST, HeaderValue::from_static(TEO_HOST));
        headers.insert("X-TC-Action", HeaderValue::from_str(action).unwrap());
        headers.insert("X-TC-Version", HeaderValue::from_static(TEO_VERSION));
        headers.insert(
            "X-TC-Timestamp",
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&authorization).unwrap(),
        );

        let resp = self
            .client
            .post(TEO_ENDPOINT)
            .headers(headers)
            .body(payload_str)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let parsed = serde_json::from_str::<T>(&body_text)?;
        Ok(parsed)
    }

    /// 获取 Zone ID
    async fn get_zone_id(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let payload = json!({
            "Filters": [
                {
                    "Name": "zone-name",
                    "Values": [root_domain]
                }
            ]
        });

        let resp: TeoZoneResp = self.request_tc3_api("DescribeZones", payload).await?;

        if let Some(err) = resp.response.error {
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: err.message,
            });
        }

        let zones = resp.response.zones.unwrap_or_default();
        let matched = zones
            .into_iter()
            .find(|z| z.zone_name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在腾讯云 EdgeOne 中未找到根域名 [{}] 对应的 Zone",
                    root_domain
                ))
            })?;

        Ok(matched.zone_id)
    }
}

#[async_trait]
impl DnsProvider for TencentEoProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 EdgeOne (EO)"
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

        // 1. 获取 Zone ID
        let zone_id = self.get_zone_id(&domain.root_domain).await?;

        // 2. 查询解析记录
        let describe_payload = json!({
            "ZoneId": zone_id,
            "Filters": [
                {
                    "Name": "name",
                    "Values": [full_domain]
                },
                {
                    "Name": "type",
                    "Values": [record_type.to_string()]
                }
            ]
        });

        let rec_resp: TeoRecordResp = self
            .request_tc3_api("DescribeDnsRecords", describe_payload)
            .await?;

        if let Some(err) = rec_resp.response.error {
            return Err(DnsProviderError::ApiError {
                code: err.code,
                message: err.message,
            });
        }

        let records = rec_resp.response.dns_records.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(full_domain.trim_end_matches('.'))
                && r.record_type.eq_ignore_ascii_case(&record_type.to_string())
        });

        if let Some(existing) = matched {
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

            let record_id = existing.record_id.unwrap_or_default();

            // 更新记录 (ModifyDnsRecords)
            let modify_payload = json!({
                "ZoneId": zone_id,
                "DnsRecords": [
                    {
                        "RecordId": record_id,
                        "ZoneId": zone_id,
                        "Name": full_domain,
                        "Type": record_type.to_string(),
                        "Content": target_ip_str,
                        "Location": "Default",
                        "TTL": ttl_val
                    }
                ]
            });

            let act_resp: TeoActionResp = self
                .request_tc3_api("ModifyDnsRecords", modify_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 更新记录失败: {}", err.message),
                });
            }

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
            // 创建记录 (CreateDnsRecord)
            let create_payload = json!({
                "ZoneId": zone_id,
                "Name": full_domain,
                "Type": record_type.to_string(),
                "Content": target_ip_str,
                "Location": "Default",
                "TTL": ttl_val
            });

            let act_resp: TeoActionResp = self
                .request_tc3_api("CreateDnsRecord", create_payload)
                .await?;

            if let Some(err) = act_resp.response.error {
                return Err(DnsProviderError::ApiError {
                    code: err.code,
                    message: format!("EdgeOne 创建记录失败: {}", err.message),
                });
            }

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

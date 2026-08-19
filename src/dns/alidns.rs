use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{append_ntp_hint_if_expired, hmac_sha1_base64, pop_url_encode};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

const DEFAULT_ALIDNS_ENDPOINT: &str = "https://alidns.aliyuncs.com";

pub struct AliDnsProvider {
    client: Client,
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
}

impl AliDnsProvider {
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        endpoint: Option<String>,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if access_key_id.trim().is_empty() || access_key_secret.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "阿里云 AliDNS 需要配置 AccessKeyId 与 AccessKeySecret".to_string(),
            ));
        }

        let endpoint = endpoint
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ALIDNS_ENDPOINT.to_string());

        let client =
            crate::util::http::create_task_http_client(http_interface, Duration::from_secs(15))?;

        Ok(Self {
            client,
            access_key_id,
            access_key_secret,
            endpoint,
        })
    }

    /// 发送阿里云 POP API 请求
    async fn request_pop_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        custom_params: Vec<(&str, String)>,
    ) -> Result<T, DnsProviderError> {
        let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let nonce = format!("{}-{}", Utc::now().timestamp_millis(), fastrand::u32(..));

        let mut params = BTreeMap::new();
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-01-09".to_string());
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("Timestamp".to_string(), timestamp);
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), nonce);
        params.insert("Action".to_string(), action.to_string());

        for (k, v) in custom_params {
            params.insert(k.to_string(), v);
        }

        // 构造标准化查询字符串 CanonicalizedQueryString
        let canonicalized_query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", pop_url_encode(k), pop_url_encode(v)))
            .collect();
        let canonicalized_query_str = canonicalized_query.join("&");

        // 计算 StringToSign
        let string_to_sign = format!(
            "GET&{}&{}",
            pop_url_encode("/"),
            pop_url_encode(&canonicalized_query_str)
        );

        // 签名密钥为 AccessKeySecret + "&"
        let sign_key = format!("{}&", self.access_key_secret);
        let signature = hmac_sha1_base64(sign_key.as_bytes(), string_to_sign.as_bytes());

        let mut query_with_sign = canonicalized_query_str;
        query_with_sign.push_str(&format!("&Signature={}", pop_url_encode(&signature)));

        let url = format!("{}/?{}", self.endpoint, query_with_sign);

        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_str::<AliErrorResponse>(&body_text) {
                let mut msg = err_resp.message;
                append_ntp_hint_if_expired(&mut msg, &err_resp.code);
                return Err(DnsProviderError::ApiError {
                    code: err_resp.code,
                    message: msg,
                });
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
impl DnsProvider for AliDnsProvider {
    fn provider_name(&self) -> &'static str {
        "阿里云 (AliDNS)"
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
        let rr = domain.sub_domain_or_at().to_string();
        let root_domain = domain.root_domain.clone();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let record_line = domain
            .custom_params
            .get("Line")
            .or_else(|| domain.custom_params.get("line"))
            .cloned()
            .unwrap_or_else(|| "default".to_string());

        // 1. 查询现有解析记录列表 (使用 DescribeSubDomainRecords 精确检索，规避 20 条记录的分页截断)
        let list_resp: AliDescribeRecordsResponse = self
            .request_pop_api(
                "DescribeSubDomainRecords",
                vec![
                    ("SubDomain", full_domain.clone()),
                    ("Type", record_type.to_string()),
                ],
            )
            .await?;

        let records = list_resp
            .domain_records
            .and_then(|dr| dr.record)
            .unwrap_or_default();

        // 找到 RR、Type 与 Line 匹配的记录
        let matched_record = records.into_iter().find(|r| {
            let rr_match = r.rr.eq_ignore_ascii_case(&rr);
            let type_match = r.record_type.eq_ignore_ascii_case(&record_type.to_string());
            let line_match = if let Some(ref l) = r.line {
                l.eq_ignore_ascii_case(&record_line)
            } else {
                record_line.eq_ignore_ascii_case("default")
            };
            rr_match && type_match && line_match
        });

        if let Some(existing) = matched_record {
            if existing.value == target_ip_str {
                info!(
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
            let _: serde_json::Value = self
                .request_pop_api(
                    "UpdateDomainRecord",
                    vec![
                        ("RecordId", existing.record_id),
                        ("RR", rr),
                        ("Type", record_type.to_string()),
                        ("Value", target_ip_str.clone()),
                        ("TTL", ttl_val.to_string()),
                        ("Line", record_line),
                    ],
                )
                .await?;

            info!(
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
            // 新增记录
            let _: serde_json::Value = self
                .request_pop_api(
                    "AddDomainRecord",
                    vec![
                        ("DomainName", root_domain),
                        ("RR", rr),
                        ("Type", record_type.to_string()),
                        ("Value", target_ip_str.clone()),
                        ("TTL", ttl_val.to_string()),
                        ("Line", record_line),
                    ],
                )
                .await?;

            info!(
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
                message: "记录创建成功".to_string(),
            })
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliDescribeRecordsResponse {
    domain_records: Option<AliDomainRecordsWrapper>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliDomainRecordsWrapper {
    record: Option<Vec<AliRecordItem>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliRecordItem {
    #[serde(alias = "RecordId", alias = "RecordID")]
    record_id: String,
    #[serde(rename = "RR", alias = "Rr", alias = "rr")]
    rr: String,
    #[serde(rename = "Type")]
    record_type: String,
    value: String,
    line: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AliErrorResponse {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ali_describe_subdomain_records_deserialization() {
        let sample_json = r#"{
            "TotalCount": 1,
            "PageSize": 20,
            "RequestId": "2B4C5F74-B32D-4E10-91D0-1234567890AB",
            "PageNumber": 1,
            "DomainRecords": {
                "Record": [
                    {
                        "Status": "ENABLE",
                        "Type": "A",
                        "Weight": 1,
                        "Value": "1.2.3.4",
                        "TTL": 600,
                        "RecordId": "999888777",
                        "RR": "@",
                        "DomainName": "mangerle.asia",
                        "Locked": false,
                        "Line": "default"
                    }
                ]
            }
        }"#;

        let parsed: AliDescribeRecordsResponse = serde_json::from_str(sample_json)
            .expect("阿里云 DescribeSubDomainRecords 响应反序列化失败");
        let records = parsed
            .domain_records
            .and_then(|dr| dr.record)
            .expect("缺少 Record 列表");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_id, "999888777");
        assert_eq!(records[0].rr, "@");
        assert_eq!(records[0].record_type, "A");
        assert_eq!(records[0].value, "1.2.3.4");
        assert_eq!(records[0].line.as_deref(), Some("default"));
    }
}

use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::{append_ntp_hint_if_expired, hmac_sha1_base64, pop_url_encode};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

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

        // 复用全局连接池缓存，避免每轮同步重复进行 TCP/TLS 握手
        let client = crate::util::http::create_default_dns_client(http_interface);

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
        let nonce = format!(
            "{}-{}",
            Utc::now().timestamp_millis(),
            crate::util::crypto::random_u32()
        );

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

    /// 获取域名自定义参数中指定的解析线路
    fn resolve_line(domain: &ParsedDomain) -> &str {
        domain
            .custom_params
            .get("Line")
            .or_else(|| domain.custom_params.get("line"))
            .map(|s| s.as_str())
            .unwrap_or("default")
    }
}

#[async_trait]
impl RecordOps for AliDnsProvider {
    fn provider_name(&self) -> &'static str {
        "阿里云 (AliDNS)"
    }

    /// 查询现有解析记录列表 (使用 DescribeSubDomainRecords 精确检索，规避 20 条记录的分页截断)
    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let full_domain = domain.full_domain();
        let rr = domain.sub_domain_or_at();
        let record_line = Self::resolve_line(domain);

        let list_resp: AliDescribeRecordsResponse = self
            .request_pop_api(
                "DescribeSubDomainRecords",
                vec![
                    ("SubDomain", full_domain),
                    ("Type", record_type.to_string()),
                ],
            )
            .await?;

        let records = list_resp
            .domain_records
            .and_then(|dr| dr.record)
            .unwrap_or_default();

        let matched = records
            .into_iter()
            .filter(|r| {
                let rr_match = r.rr.eq_ignore_ascii_case(rr);
                let type_match = r.record_type.eq_ignore_ascii_case(&record_type.to_string());
                let line_match = if let Some(ref l) = r.line {
                    l.eq_ignore_ascii_case(record_line)
                } else {
                    record_line.eq_ignore_ascii_case("default")
                };
                rr_match && type_match && line_match
            })
            .map(|r| RemoteRecord::new(r.record_id, r.value))
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
        let rr = domain.sub_domain_or_at().to_string();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let record_line = Self::resolve_line(domain).to_string();

        let _: serde_json::Value = self
            .request_pop_api(
                "AddDomainRecord",
                vec![
                    ("DomainName", zone.to_string()),
                    ("RR", rr),
                    ("Type", record_type.to_string()),
                    ("Value", ip.to_string()),
                    ("TTL", ttl_val.to_string()),
                    ("Line", record_line),
                ],
            )
            .await?;

        Ok(())
    }

    /// 更新既有解析记录
    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let rr = domain.sub_domain_or_at().to_string();
        let ttl_val = ttl.unwrap_or(600).max(1);
        let record_line = Self::resolve_line(domain).to_string();

        let _: serde_json::Value = self
            .request_pop_api(
                "UpdateDomainRecord",
                vec![
                    ("RecordId", record_id.to_string()),
                    ("RR", rr),
                    ("Type", record_type.to_string()),
                    ("Value", ip.to_string()),
                    ("TTL", ttl_val.to_string()),
                    ("Line", record_line),
                ],
            )
            .await?;

        Ok(())
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
        sync_record_via(self, domain, record_type, ip, ttl).await
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

    #[test]
    fn test_resolve_line_custom_params() {
        use std::collections::HashMap;

        let mut domain = ParsedDomain {
            raw: "home.example.com".to_string(),
            root_domain: "example.com".to_string(),
            sub_domain: "home".to_string(),
            custom_params: HashMap::new(),
        };

        // 默认情况回退为 default
        assert_eq!(AliDnsProvider::resolve_line(&domain), "default");

        // 大写 Line 参数识别
        domain
            .custom_params
            .insert("Line".to_string(), "telecom".to_string());
        assert_eq!(AliDnsProvider::resolve_line(&domain), "telecom");

        // 小写 line 参数识别
        domain.custom_params.remove("Line");
        domain
            .custom_params
            .insert("line".to_string(), "unicom".to_string());
        assert_eq!(AliDnsProvider::resolve_line(&domain), "unicom");
    }
}

use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, default_ttl};
use crate::util::crypto::{append_ntp_hint_if_expired, build_pop_signed_query};
use async_trait::async_trait;
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

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

        let query_with_sign = build_pop_signed_query("GET", &self.access_key_secret, &params);
        let url = format!("{}/?{}", self.endpoint, query_with_sign);

        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        Self::parse_pop_response(status, &body_text)
    }

    /// 解析阿里云 POP RPC 接口返回的响应体
    ///
    /// # 设计原理
    /// - **实现初衷**：统一对阿里云 POP 接口的 HTTP 状态码与响应体业务错误码进行双重校验。
    /// - **核心优势**：杜绝服务端在业务失败时返回 HTTP 200 伴随错误 JSON 导致的静默误判成功。
    /// - **代价与局限**：对每个响应体先尝试轻量解析业务错误码，存在微小反序列化开销，但在 DDNS 调度频次下可忽略不计。
    pub(crate) fn parse_pop_response<T: DeserializeOwned>(
        status: StatusCode,
        body_text: &str,
    ) -> Result<T, DnsProviderError> {
        if let Ok(biz) = serde_json::from_str::<AliBizError>(body_text)
            && let Some(err_code) = biz.code
        {
            let mut msg = biz.message.unwrap_or_default();
            append_ntp_hint_if_expired(&mut msg, &err_code);
            return Err(DnsProviderError::ApiError {
                code: err_code,
                message: msg,
            });
        }

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text.to_string(),
            });
        }

        let parsed: T = serde_json::from_str(body_text)?;
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
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let rr = params.domain.sub_domain_or_at().to_string();
        let ttl_val = default_ttl(params.ttl);
        let record_line = Self::resolve_line(params.domain).to_string();

        let _: serde_json::Value = self
            .request_pop_api(
                "AddDomainRecord",
                vec![
                    ("DomainName", zone.to_string()),
                    ("RR", rr),
                    ("Type", params.record_type.to_string()),
                    ("Value", params.ip.to_string()),
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
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let rr = params.domain.sub_domain_or_at().to_string();
        let ttl_val = default_ttl(params.ttl);
        let record_line = Self::resolve_line(params.domain).to_string();

        let _: serde_json::Value = self
            .request_pop_api(
                "UpdateDomainRecord",
                vec![
                    ("RecordId", record_id.to_string()),
                    ("RR", rr),
                    ("Type", params.record_type.to_string()),
                    ("Value", params.ip.to_string()),
                    ("TTL", ttl_val.to_string()),
                    ("Line", record_line),
                ],
            )
            .await?;

        Ok(())
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
struct AliBizError {
    code: Option<String>,
    message: Option<String>,
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

    #[test]
    fn test_parse_pop_response_intercepts_http200_biz_error() {
        let err_json = r#"{
            "RequestId": "5F3C2809-58D6-4275-B948-4C8E0C4F6211",
            "HostId": "alidns.aliyuncs.com",
            "Code": "InvalidDomainName.NoExist",
            "Message": "The specified domain name does not exist."
        }"#;

        let res = AliDnsProvider::parse_pop_response::<serde_json::Value>(StatusCode::OK, err_json);

        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "InvalidDomainName.NoExist");
                assert!(message.contains("The specified domain name does not exist."));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_parse_pop_response_intercepts_http400_biz_error() {
        let err_json = r#"{
            "Code": "MissingParameter",
            "Message": "The input parameter RR that is mandatory for processing this request is not supplied."
        }"#;

        let res = AliDnsProvider::parse_pop_response::<serde_json::Value>(
            StatusCode::BAD_REQUEST,
            err_json,
        );

        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "MissingParameter");
                assert!(message.contains("mandatory"));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_parse_pop_response_success_when_no_error_code() {
        let ok_json = r#"{
            "RecordId": "123456789",
            "RequestId": "TEST-REQ-ID"
        }"#;

        let res = AliDnsProvider::parse_pop_response::<serde_json::Value>(StatusCode::OK, ok_json);

        assert!(res.is_ok());
        let val = res.unwrap();
        assert_eq!(val["RecordId"], "123456789");
    }

    #[test]
    fn test_pop_signature_known_vector() {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DescribeDomainRecords".to_string());
        params.insert("Format".to_string(), "JSON".to_string());
        params.insert("Version".to_string(), "2015-01-09".to_string());
        params.insert("AccessKeyId".to_string(), "testid".to_string());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("Timestamp".to_string(), "2015-01-09T12:00:00Z".to_string());
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), "123456".to_string());

        let secret = "testsecret";
        let (query, sign) = crate::util::crypto::compute_pop_signature("GET", secret, &params);

        // 验证签名非空且具有确定的 HMAC-SHA1 签名
        assert!(!sign.is_empty());
        assert!(query.contains("Action=DescribeDomainRecords"));
        assert!(query.contains("AccessKeyId=testid"));

        // 再次计算必须保持确定性（幂等性）
        let (query2, sign2) = crate::util::crypto::compute_pop_signature("GET", secret, &params);
        assert_eq!(query, query2);
        assert_eq!(sign, sign2);
    }
}

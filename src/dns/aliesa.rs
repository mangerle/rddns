use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, default_ttl};
use crate::util::crypto::build_pop_signed_query;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;

const DEFAULT_ALIESA_ENDPOINT: &str = "https://esa.cn-hangzhou.aliyuncs.com";

/// 阿里云 ESA (Edge Security Acceleration) 提供商
pub struct AliEsaProvider {
    client: Client,
    access_key_id: String,
    access_key_secret: String,
    endpoint: String,
}

#[derive(Debug, Deserialize)]
struct AliEsaSite {
    #[serde(rename = "SiteId")]
    site_id: i64,
    #[serde(rename = "SiteName")]
    site_name: String,
}

#[derive(Debug, Deserialize)]
struct AliEsaSiteResp {
    #[serde(rename = "Sites")]
    sites: Option<Vec<AliEsaSite>>,
}

#[derive(Debug, Deserialize)]
struct AliEsaRecordData {
    #[serde(rename = "Value")]
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AliEsaRecord {
    #[serde(rename = "RecordId")]
    record_id: i64,
    #[serde(rename = "RecordName")]
    record_name: String,
    #[serde(rename = "Data")]
    data: Option<AliEsaRecordData>,
}

#[derive(Debug, Deserialize)]
struct AliEsaRecordResp {
    #[serde(rename = "Records")]
    records: Option<Vec<AliEsaRecord>>,
}

#[derive(Debug, Deserialize)]
struct AliEsaActionResp {
    #[serde(rename = "RecordId")]
    record_id: Option<i64>,
    #[serde(rename = "RequestId")]
    request_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AliEsaErrorResp {
    #[serde(rename = "Code")]
    code: Option<String>,
    #[serde(rename = "Message")]
    message: Option<String>,
}

impl AliEsaProvider {
    pub fn new(
        access_key_id: String,
        access_key_secret: String,
        endpoint: Option<String>,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if access_key_id.trim().is_empty() || access_key_secret.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "阿里云 ESA 需要配置 AccessKeyId 与 AccessKeySecret".to_string(),
            ));
        }

        let endpoint = endpoint
            .filter(|e| !e.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ALIESA_ENDPOINT.to_string());

        let client = crate::util::http::create_default_dns_client(http_interface);

        Ok(Self {
            client,
            access_key_id,
            access_key_secret,
            endpoint,
        })
    }

    /// 发送阿里云 POP API 请求
    async fn request_pop<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
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
        params.insert("Version".to_string(), "2024-09-10".to_string());
        params.insert("AccessKeyId".to_string(), self.access_key_id.clone());
        params.insert("SignatureMethod".to_string(), "HMAC-SHA1".to_string());
        params.insert("Timestamp".to_string(), timestamp);
        params.insert("SignatureVersion".to_string(), "1.0".to_string());
        params.insert("SignatureNonce".to_string(), nonce);
        params.insert("Action".to_string(), action.to_string());

        for (k, v) in custom_params {
            params.insert(k.to_string(), v);
        }

        let query_with_sign = build_pop_signed_query(method, &self.access_key_secret, &params);
        let url = format!("{}/?{}", self.endpoint, query_with_sign);

        let resp = if method == "POST" {
            self.client.post(&url).send().await?
        } else {
            self.client.get(&url).send().await?
        };

        let status = resp.status();
        let body_text = resp.text().await?;

        Self::parse_pop_response(status, &body_text)
    }

    /// 解析阿里云 ESA 响应体
    ///
    /// # 设计原理
    /// - **实现初衷**：统一对阿里云 ESA 接口的 HTTP 状态码与响应体业务错误码进行双重校验。
    /// - **核心优势**：杜绝服务端在业务失败时返回 HTTP 200 伴随错误 JSON 导致的静默误判成功。
    /// - **代价与局限**：对每个响应体先尝试轻量解析业务错误码，存在微小反序列化开销。
    pub(crate) fn parse_pop_response<T: DeserializeOwned>(
        status: StatusCode,
        body_text: &str,
    ) -> Result<T, DnsProviderError> {
        if let Ok(err_resp) = serde_json::from_str::<AliEsaErrorResp>(body_text)
            && let Some(code) = err_resp.code
        {
            return Err(DnsProviderError::ApiError {
                code,
                message: err_resp
                    .message
                    .unwrap_or_else(|| "阿里云 ESA 请求业务失败".to_string()),
            });
        }

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text.to_string(),
            });
        }

        let parsed = serde_json::from_str::<T>(body_text)?;
        Ok(parsed)
    }

    /// 获取站点 ID
    async fn get_site_id(&self, root_domain: &str) -> Result<i64, DnsProviderError> {
        let resp: AliEsaSiteResp = self
            .request_pop(
                "GET",
                "ListSites",
                vec![("SiteName", root_domain.to_string())],
            )
            .await?;

        let sites = resp.sites.unwrap_or_default();
        let site = sites
            .into_iter()
            .find(|s| s.site_name.eq_ignore_ascii_case(root_domain))
            .ok_or_else(|| DnsProviderError::ZoneNotFound(root_domain.to_string()))?;

        Ok(site.site_id)
    }
}

#[async_trait]
impl RecordOps for AliEsaProvider {
    fn provider_name(&self) -> &'static str {
        "阿里云 ESA (Edge Security Acceleration)"
    }

    async fn resolve_zone(&self, root_domain: &str) -> Result<String, DnsProviderError> {
        let site_id = self.get_site_id(root_domain).await?;
        Ok(site_id.to_string())
    }

    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let full_domain = domain.full_domain();
        let rec_resp: AliEsaRecordResp = self
            .request_pop(
                "GET",
                "ListRecords",
                vec![
                    ("SiteId", zone.to_string()),
                    ("RecordName", full_domain),
                    ("Type", record_type.to_string()),
                ],
            )
            .await?;

        let records = rec_resp.records.unwrap_or_default();
        let matched = records
            .into_iter()
            .filter(|r| domain.matches_record_name(&r.record_name))
            .filter_map(|r| {
                r.data
                    .and_then(|d| d.value)
                    .map(|v| RemoteRecord::new(r.record_id.to_string(), v))
            })
            .collect();

        Ok(matched)
    }

    async fn create_record(
        &self,
        zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let full_domain = params.domain.full_domain();
        let target_ip_str = params.ip.to_string();
        let ttl_val = default_ttl(params.ttl);
        let data_json = format!(r#"{{"Value":"{}"}}"#, target_ip_str);

        let act: AliEsaActionResp = self
            .request_pop(
                "POST",
                "CreateRecord",
                vec![
                    ("SiteId", zone.to_string()),
                    ("RecordName", full_domain),
                    ("Type", params.record_type.to_string()),
                    ("Data", data_json),
                    ("Ttl", ttl_val.to_string()),
                ],
            )
            .await?;

        if act.record_id.is_some() || act.request_id.is_some() {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: "AliEsaCreateError".to_string(),
                message: "阿里云 ESA 创建解析记录未返回有效结果".to_string(),
            })
        }
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let target_ip_str = params.ip.to_string();
        let ttl_val = default_ttl(params.ttl);
        let data_json = format!(r#"{{"Value":"{}"}}"#, target_ip_str);

        let act: AliEsaActionResp = self
            .request_pop(
                "POST",
                "UpdateRecord",
                vec![
                    ("RecordId", record_id.to_string()),
                    ("Type", params.record_type.to_string()),
                    ("Data", data_json),
                    ("Ttl", ttl_val.to_string()),
                ],
            )
            .await?;

        if act.record_id.is_some() || act.request_id.is_some() {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: "AliEsaUpdateError".to_string(),
                message: "阿里云 ESA 更新解析记录未返回有效结果".to_string(),
            })
        }
    }

    async fn delete_record(
        &self,
        _zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let act: AliEsaActionResp = self
            .request_pop(
                "POST",
                "DeleteRecord",
                vec![("RecordId", record.id.to_string())],
            )
            .await?;

        if act.record_id.is_some() || act.request_id.is_some() {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: "AliEsaDeleteError".to_string(),
                message: "阿里云 ESA 删除解析记录未返回有效结果".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aliesa_parse_pop_response_intercepts_biz_error() {
        let err_json = r#"{
            "Code": "InvalidSite.NotFound",
            "Message": "The specified site does not exist.",
            "RequestId": "ESA-REQ-001"
        }"#;

        let res = AliEsaProvider::parse_pop_response::<AliEsaActionResp>(StatusCode::OK, err_json);

        match res {
            Err(DnsProviderError::ApiError { code, message }) => {
                assert_eq!(code, "InvalidSite.NotFound");
                assert!(message.contains("The specified site does not exist."));
            }
            other => panic!("预期返回 ApiError，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_aliesa_parse_pop_response_success() {
        let ok_json = r#"{
            "RecordId": 12345678,
            "RequestId": "ESA-REQ-002"
        }"#;

        let res = AliEsaProvider::parse_pop_response::<AliEsaActionResp>(StatusCode::OK, ok_json);

        assert!(res.is_ok());
        let act = res.unwrap();
        assert_eq!(act.record_id, Some(12345678));
    }
}

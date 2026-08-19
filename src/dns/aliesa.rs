use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use crate::util::crypto::{hmac_sha1_base64, pop_url_encode};
use async_trait::async_trait;
use chrono::Utc;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;

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
        let nonce = format!("{}-{}", Utc::now().timestamp_millis(), fastrand::u32(..));

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

        let canonicalized_query: Vec<String> = params
            .iter()
            .map(|(k, v)| format!("{}={}", pop_url_encode(k), pop_url_encode(v)))
            .collect();
        let canonicalized_query_str = canonicalized_query.join("&");

        let string_to_sign = format!(
            "{}&{}&{}",
            method,
            pop_url_encode("/"),
            pop_url_encode(&canonicalized_query_str)
        );

        let sign_key = format!("{}&", self.access_key_secret);
        let signature = hmac_sha1_base64(sign_key.as_bytes(), string_to_sign.as_bytes());

        let mut query_with_sign = canonicalized_query_str;
        query_with_sign.push_str(&format!("&Signature={}", pop_url_encode(&signature)));

        let url = format!("{}/?{}", self.endpoint, query_with_sign);

        let resp = if method == "POST" {
            self.client.post(&url).send().await?
        } else {
            self.client.get(&url).send().await?
        };

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            if let Ok(err_resp) = serde_json::from_str::<AliEsaErrorResp>(&body_text) {
                return Err(DnsProviderError::ApiError {
                    code: err_resp.code.unwrap_or_else(|| status.to_string()),
                    message: err_resp
                        .message
                        .unwrap_or_else(|| "阿里云 ESA 请求失败".to_string()),
                });
            }
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: body_text,
            });
        }

        let parsed = serde_json::from_str::<T>(&body_text)?;
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
            .ok_or_else(|| {
                DnsProviderError::ZoneNotFound(format!(
                    "在阿里云 ESA 中未找到根域名 [{}] 对应的站点",
                    root_domain
                ))
            })?;

        Ok(site.site_id)
    }
}

#[async_trait]
impl DnsProvider for AliEsaProvider {
    fn provider_name(&self) -> &'static str {
        "阿里云 ESA (Edge Security Acceleration)"
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

        // 1. 获取站点 ID
        let site_id = self.get_site_id(&domain.root_domain).await?;

        // 2. 获取现有记录
        let rec_resp: AliEsaRecordResp = self
            .request_pop(
                "GET",
                "ListRecords",
                vec![
                    ("SiteId", site_id.to_string()),
                    ("RecordName", full_domain.clone()),
                    ("Type", record_type.to_string()),
                ],
            )
            .await?;

        let records = rec_resp.records.unwrap_or_default();
        let matched = records.into_iter().find(|r| {
            r.record_name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(full_domain.trim_end_matches('.'))
        });

        let data_json = format!(r#"{{"Value":"{}"}}"#, target_ip_str);

        if let Some(existing) = matched {
            let is_matched = existing
                .data
                .as_ref()
                .and_then(|d| d.value.as_deref())
                .map(|v| v == target_ip_str)
                .unwrap_or(false);

            if is_matched {
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

            // 更新记录 (POST UpdateRecord)
            let _: AliEsaActionResp = self
                .request_pop(
                    "POST",
                    "UpdateRecord",
                    vec![
                        ("RecordId", existing.record_id.to_string()),
                        ("Type", record_type.to_string()),
                        ("Data", data_json),
                        ("Ttl", ttl_val.to_string()),
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
            // 创建记录 (POST CreateRecord)
            let act: AliEsaActionResp = self
                .request_pop(
                    "POST",
                    "CreateRecord",
                    vec![
                        ("SiteId", site_id.to_string()),
                        ("RecordName", full_domain.clone()),
                        ("Type", record_type.to_string()),
                        ("Data", data_json),
                        ("Ttl", ttl_val.to_string()),
                    ],
                )
                .await?;

            if act.record_id.is_some() || act.request_id.is_some() {
                info!(
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
            } else {
                Err(DnsProviderError::ApiError {
                    code: "AliEsaCreateError".to_string(),
                    message: "阿里云 ESA 创建解析记录未返回有效结果".to_string(),
                })
            }
        }
    }
}

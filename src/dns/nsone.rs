use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

const NSONE_API_ENDPOINT: &str = "https://api.nsone.net/v1/zones";

/// IBM NS1 Connect DNS 提供商
pub struct NsOneProvider {
    client: Client,
}

#[derive(Debug, Deserialize)]
struct NsOneZone {
    #[serde(rename = "name")]
    _name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NsOneAnswer {
    answer: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NsOneRecordResp {
    answers: Option<Vec<NsOneAnswer>>,
}

#[derive(Debug, Serialize)]
struct NsOneRecordReq<'a> {
    zone: &'a str,
    domain: &'a str,
    #[serde(rename = "type")]
    record_type: &'a str,
    ttl: u32,
    answers: Vec<NsOneAnswer>,
}

impl NsOneProvider {
    pub fn new(api_key: String) -> Result<Self, DnsProviderError> {
        if api_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "IBM NS1 Connect 需要配置 API Key (Secret)".to_string(),
            ));
        }

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let mut auth_val = HeaderValue::from_str(api_key.trim()).map_err(|e| {
            DnsProviderError::MissingCredentials(format!("无效的 NS1 API Key: {}", e))
        })?;
        auth_val.set_sensitive(true);
        headers.insert("X-NSONE-Key", auth_val);

        let client = crate::util::http::create_http_client_builder()
            .timeout(Duration::from_secs(15))
            .default_headers(headers)
            .build()?;

        Ok(Self { client })
    }

    /// 检查 Zone 是否存在
    async fn check_zone(&self, root_domain: &str) -> Result<(), DnsProviderError> {
        let url = format!("{}/{}?records=false", NSONE_API_ENDPOINT, root_domain);
        let resp = self.client.get(&url).send().await?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Err(DnsProviderError::ZoneNotFound(format!(
                "在 IBM NS1 Connect 中未找到根域名 [{}]",
                root_domain
            )));
        }

        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(DnsProviderError::ApiError {
                code: "ZoneCheckFailed".to_string(),
                message: format!("查询 Zone 失败: {}", body),
            });
        }

        let _zone: NsOneZone = resp.json().await?;
        Ok(())
    }

    /// 获取已有记录
    async fn get_record(
        &self,
        root_domain: &str,
        full_domain: &str,
        record_type: &str,
    ) -> Result<Option<NsOneRecordResp>, DnsProviderError> {
        let url = format!(
            "{}/{}/{}/{}?records=false",
            NSONE_API_ENDPOINT, root_domain, full_domain, record_type
        );
        let resp = self.client.get(&url).send().await?;

        let status = resp.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !status.is_success() {
            let body = resp.text().await?;
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("查询 NS1 记录失败: {}", body),
            });
        }

        let parsed: NsOneRecordResp = resp.json().await?;
        Ok(Some(parsed))
    }
}

#[async_trait]
impl DnsProvider for NsOneProvider {
    fn provider_name(&self) -> &'static str {
        "IBM NS1 Connect"
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
        let ttl_val = ttl.unwrap_or(60).max(1);

        // 1. 检查 Zone
        self.check_zone(&domain.root_domain).await?;

        // 2. 查询已有记录
        let existing = self
            .get_record(&domain.root_domain, &full_domain, &record_type.to_string())
            .await?;

        let answers = vec![NsOneAnswer {
            answer: vec![target_ip_str.clone()],
        }];

        let req_payload = NsOneRecordReq {
            zone: &domain.root_domain,
            domain: &full_domain,
            record_type: &record_type.to_string(),
            ttl: ttl_val,
            answers,
        };

        if let Some(record) = existing {
            let current_ip = record
                .answers
                .as_ref()
                .and_then(|ans| ans.first())
                .and_then(|a| a.answer.first());

            if current_ip == Some(&target_ip_str) {
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

            // 更新记录 (POST)
            let url = format!(
                "{}/{}/{}/{}",
                NSONE_API_ENDPOINT, domain.root_domain, full_domain, record_type
            );

            let resp = self.client.post(&url).json(&req_payload).send().await?;
            let status = resp.status();
            let body = resp.text().await?;

            if !status.is_success() {
                return Err(DnsProviderError::ApiError {
                    code: status.to_string(),
                    message: format!("NS1 更新记录失败: {}", body),
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
            // 创建记录 (PUT)
            let url = format!(
                "{}/{}/{}/{}",
                NSONE_API_ENDPOINT, domain.root_domain, full_domain, record_type
            );

            let resp = self.client.put(&url).json(&req_payload).send().await?;
            let status = resp.status();
            let body = resp.text().await?;

            if !status.is_success() {
                return Err(DnsProviderError::ApiError {
                    code: status.to_string(),
                    message: format!("NS1 创建记录失败: {}", body),
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

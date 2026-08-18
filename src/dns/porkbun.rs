use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const PORKBUN_ENDPOINT: &str = "https://api.porkbun.com/api/json/v3/dns";

/// Porkbun DNS 提供商
pub struct PorkbunProvider {
    api_key: String,
    secret_key: String,
    client: Client,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct PorkbunRecord {
    #[serde(rename = "type")]
    record_type: Option<String>,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PorkbunQueryResponse {
    status: String,
    message: Option<String>,
    records: Option<Vec<PorkbunRecord>>,
}

#[derive(Debug, Deserialize)]
struct PorkbunBaseResponse {
    status: String,
    message: Option<String>,
}

impl PorkbunProvider {
    pub fn new(api_key: String, secret_key: String, http_interface: Option<&str>) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            api_key,
            secret_key,
            client,
        }
    }

    fn auth_payload(&self) -> serde_json::Value {
        json!({
            "apikey": self.api_key,
            "secretapikey": self.secret_key,
        })
    }
}

#[async_trait]
impl DnsProvider for PorkbunProvider {
    fn provider_name(&self) -> &'static str {
        "Porkbun"
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
        let ttl_val = ttl.unwrap_or(600).max(600).to_string();

        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_domain_param = if is_root { "" } else { &domain.sub_domain };

        // 1. 查询现有解析记录 (Porkbun 根域名不加子域名路径)
        let query_url = if sub_domain_param.is_empty() {
            format!(
                "{}/retrieveByNameType/{}/{}",
                PORKBUN_ENDPOINT, domain.root_domain, record_type
            )
        } else {
            format!(
                "{}/retrieveByNameType/{}/{}/{}",
                PORKBUN_ENDPOINT, domain.root_domain, record_type, sub_domain_param
            )
        };

        let query_resp = self
            .client
            .post(&query_url)
            .json(&self.auth_payload())
            .send()
            .await?;

        let query_status = query_resp.status();
        let query_text = query_resp.text().await?;
        if !query_status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: query_status.to_string(),
                message: format!("Porkbun 查询记录 HTTP 错误: {}", query_text),
            });
        }

        let query_result: PorkbunQueryResponse = serde_json::from_str(&query_text)?;

        if !query_result.status.eq_ignore_ascii_case("SUCCESS") {
            let msg = query_result
                .message
                .unwrap_or_else(|| "查询 Porkbun 解析记录失败".to_string());
            return Err(DnsProviderError::ApiError {
                code: query_result.status,
                message: msg,
            });
        }

        let existing_records = query_result.records.unwrap_or_default();
        if let Some(existing) = existing_records.first() {
            if existing.content.as_deref() == Some(&target_ip_str) {
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

            // 2. 编辑修改现有记录
            let edit_url = if sub_domain_param.is_empty() {
                format!(
                    "{}/editByNameType/{}/{}",
                    PORKBUN_ENDPOINT, domain.root_domain, record_type
                )
            } else {
                format!(
                    "{}/editByNameType/{}/{}/{}",
                    PORKBUN_ENDPOINT, domain.root_domain, record_type, sub_domain_param
                )
            };

            let mut edit_payload = self.auth_payload();
            edit_payload["content"] = json!(target_ip_str);
            edit_payload["ttl"] = json!(ttl_val);

            let edit_resp = self
                .client
                .post(&edit_url)
                .json(&edit_payload)
                .send()
                .await?;

            let edit_status = edit_resp.status();
            let edit_text = edit_resp.text().await?;
            if !edit_status.is_success() {
                return Err(DnsProviderError::ApiError {
                    code: edit_status.to_string(),
                    message: format!("Porkbun 更新记录 HTTP 错误: {}", edit_text),
                });
            }

            let edit_result: PorkbunBaseResponse = serde_json::from_str(&edit_text)?;
            if edit_result.status.eq_ignore_ascii_case("SUCCESS") {
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
                Err(DnsProviderError::ApiError {
                    code: edit_result.status,
                    message: edit_result
                        .message
                        .unwrap_or_else(|| "更新 Porkbun 记录失败".to_string()),
                })
            }
        } else {
            // 3. 创建新增记录
            let create_url = format!("{}/create/{}", PORKBUN_ENDPOINT, domain.root_domain);
            let mut create_payload = self.auth_payload();
            create_payload["name"] = json!(sub_domain_param);
            create_payload["type"] = json!(record_type.to_string());
            create_payload["content"] = json!(target_ip_str);
            create_payload["ttl"] = json!(ttl_val);

            let create_resp = self
                .client
                .post(&create_url)
                .json(&create_payload)
                .send()
                .await?;

            let create_status = create_resp.status();
            let create_text = create_resp.text().await?;
            if !create_status.is_success() {
                return Err(DnsProviderError::ApiError {
                    code: create_status.to_string(),
                    message: format!("Porkbun 创建记录 HTTP 错误: {}", create_text),
                });
            }

            let create_result: PorkbunBaseResponse = serde_json::from_str(&create_text)?;
            if create_result.status.eq_ignore_ascii_case("SUCCESS") {
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
            } else {
                Err(DnsProviderError::ApiError {
                    code: create_result.status,
                    message: create_result
                        .message
                        .unwrap_or_else(|| "新增 Porkbun 记录失败".to_string()),
                })
            }
        }
    }
}

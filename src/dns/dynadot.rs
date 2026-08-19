use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use std::net::IpAddr;

const DYNADOT_ENDPOINT: &str = "https://www.dynadot.com/set_ddns";

/// Dynadot 动态 DNS 提供商
pub struct DynadotProvider {
    password: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct DynadotResp {
    #[serde(rename = "error_code")]
    error_code: Option<i32>,
    content: Option<Vec<String>>,
}

impl DynadotProvider {
    pub fn new(password: String, http_interface: Option<&str>) -> Self {
        Self {
            password,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }
}

#[async_trait]
impl DnsProvider for DynadotProvider {
    fn provider_name(&self) -> &'static str {
        "Dynadot"
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
        let ttl_val = ttl.unwrap_or(600).max(1).to_string();
        let record_type_str = record_type.to_string();

        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_name = if is_root { "@" } else { &domain.sub_domain };

        let query = [
            ("domain", domain.root_domain.as_str()),
            ("subDomain", sub_name),
            ("type", record_type_str.as_str()),
            ("ip", &target_ip_str),
            ("pwd", &self.password),
            ("ttl", &ttl_val),
            ("containRoot", if is_root { "true" } else { "false" }),
        ];

        let resp = self
            .client
            .get(DYNADOT_ENDPOINT)
            .query(&query)
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Dynadot 请求失败: {}", body_text),
            });
        }

        match serde_json::from_str::<DynadotResp>(&body_text) {
            Ok(res_json) => {
                if res_json.error_code != Some(-1) {
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
                    let err_msg = res_json.content.unwrap_or_default().join(", ");
                    Err(DnsProviderError::ApiError {
                        code: "-1".to_string(),
                        message: format!("Dynadot 更新失败: {}", err_msg),
                    })
                }
            }
            Err(_) => {
                if body_text.to_lowercase().contains("success")
                    || body_text.to_lowercase().contains("ok")
                {
                    Ok(SyncRecordResult {
                        domain: full_domain,
                        record_type,
                        target_ip: target_ip_str,
                        status: SyncStatus::Updated,
                        message: format!("Dynadot 更新成功: {}", body_text),
                    })
                } else {
                    Err(DnsProviderError::ApiError {
                        code: status.to_string(),
                        message: format!("Dynadot 返回未知格式响应: {}", body_text),
                    })
                }
            }
        }
    }
}

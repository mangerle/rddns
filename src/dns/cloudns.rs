use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

const CLOUDNS_ENDPOINT: &str = "https://api.cloudns.net/dns";

/// ClouDNS 提供商
pub struct ClouDnsProvider {
    auth_id: String,
    auth_password: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct ClouDnsRecordItem {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    host: String,
    record: String,
}

#[derive(Debug, Deserialize)]
struct ClouDnsActionResp {
    status: Option<String>,
    #[serde(rename = "statusDescription")]
    status_description: Option<String>,
}

impl ClouDnsProvider {
    pub fn new(auth_id: String, auth_password: String, http_interface: Option<&str>) -> Self {
        Self {
            auth_id,
            auth_password,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }
}

#[async_trait]
impl DnsProvider for ClouDnsProvider {
    fn provider_name(&self) -> &'static str {
        "ClouDNS"
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
        let ttl_val = ttl.unwrap_or(3600).max(60).to_string();
        let sub = domain.sub_domain_or_at();
        let record_type_str = record_type.to_string();

        // 1. 查询现有解析记录
        let list_url = format!("{}/records.json", CLOUDNS_ENDPOINT);
        let list_form = [
            ("auth-id", self.auth_id.as_str()),
            ("auth-password", self.auth_password.as_str()),
            ("domain-name", domain.root_domain.as_str()),
            ("host", sub),
            ("type", record_type_str.as_str()),
        ];

        let list_resp = self.client.post(&list_url).form(&list_form).send().await?;
        let list_text = list_resp.text().await?;

        // 鲁棒解析字典或数组格式
        let mut matched: Option<ClouDnsRecordItem> = None;
        if let Ok(records_map) =
            serde_json::from_str::<HashMap<String, ClouDnsRecordItem>>(&list_text)
        {
            matched = records_map.into_values().find(|r| {
                r.record_type.eq_ignore_ascii_case(&record_type_str)
                    && r.host.eq_ignore_ascii_case(sub)
            });
        }

        if let Some(existing) = matched {
            if existing.record == target_ip_str {
                return Ok(SyncRecordResult::unchanged_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 更新记录
            let modify_url = format!("{}/modify-record.json", CLOUDNS_ENDPOINT);
            let modify_form = [
                ("auth-id", self.auth_id.as_str()),
                ("auth-password", self.auth_password.as_str()),
                ("domain-name", domain.root_domain.as_str()),
                ("record-id", existing.id.as_str()),
                ("host", sub),
                ("record", target_ip_str.as_str()),
                ("ttl", ttl_val.as_str()),
            ];

            let modify_resp = self
                .client
                .post(&modify_url)
                .form(&modify_form)
                .send()
                .await?;
            let modify_text = modify_resp.text().await?;
            let res: ClouDnsActionResp =
                serde_json::from_str(&modify_text).unwrap_or(ClouDnsActionResp {
                    status: None,
                    status_description: None,
                });

            if res.status.as_deref() == Some("Success") {
                Ok(SyncRecordResult::updated_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ))
            } else {
                let err_msg = res.status_description.unwrap_or(modify_text);
                Err(DnsProviderError::ApiError {
                    code: "ClouDnsModifyError".to_string(),
                    message: format!("ClouDNS 更新失败: {}", err_msg),
                })
            }
        } else {
            // 创建记录
            let add_url = format!("{}/add-record.json", CLOUDNS_ENDPOINT);
            let add_form = [
                ("auth-id", self.auth_id.as_str()),
                ("auth-password", self.auth_password.as_str()),
                ("domain-name", domain.root_domain.as_str()),
                ("host", sub),
                ("type", record_type_str.as_str()),
                ("record", target_ip_str.as_str()),
                ("ttl", ttl_val.as_str()),
            ];

            let add_resp = self.client.post(&add_url).form(&add_form).send().await?;
            let add_text = add_resp.text().await?;
            let res: ClouDnsActionResp =
                serde_json::from_str(&add_text).unwrap_or(ClouDnsActionResp {
                    status: None,
                    status_description: None,
                });

            if res.status.as_deref() == Some("Success") {
                Ok(SyncRecordResult::created_log(
                    self.provider_name(),
                    full_domain,
                    record_type,
                    target_ip_str,
                ))
            } else {
                let err_msg = res.status_description.unwrap_or(add_text);
                Err(DnsProviderError::ApiError {
                    code: "ClouDnsAddError".to_string(),
                    message: format!("ClouDNS 创建记录失败: {}", err_msg),
                })
            }
        }
    }
}

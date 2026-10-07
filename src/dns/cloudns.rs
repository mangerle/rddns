use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType, MIN_DNS_TTL, clamp_ttl};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

const CLOUDNS_ENDPOINT: &str = "https://api.cloudns.net/dns";
const CLOUDNS_DEFAULT_TTL: u32 = 3600;

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
impl RecordOps for ClouDnsProvider {
    fn provider_name(&self) -> &'static str {
        "ClouDNS"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let sub = domain.sub_domain_or_at();
        let record_type_str = record_type.to_string();

        let list_url = format!("{}/records.json", CLOUDNS_ENDPOINT);
        let list_form = [
            ("auth-id", self.auth_id.as_str()),
            ("auth-password", self.auth_password.as_str()),
            ("domain-name", domain.root_domain.as_str()),
            ("host", sub),
            ("type", record_type_str.as_str()),
        ];

        let list_resp = self.client.post(&list_url).form(&list_form).send().await?;
        let status = list_resp.status();
        let list_text = list_resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &list_text));
        }

        if let Ok(action_resp) = serde_json::from_str::<ClouDnsActionResp>(&list_text)
            && (action_resp.status.as_deref() == Some("Failed")
                || action_resp.status_description.is_some())
        {
            let err_msg = action_resp
                .status_description
                .unwrap_or_else(|| list_text.clone());
            return Err(DnsProviderError::ApiError {
                code: "ClouDnsQueryError".to_string(),
                message: format!("ClouDNS 查询记录业务失败: {}", err_msg),
            });
        }

        let mut matched = Vec::new();
        if let Ok(records_map) =
            serde_json::from_str::<HashMap<String, ClouDnsRecordItem>>(&list_text)
        {
            for r in records_map.into_values() {
                if r.record_type.eq_ignore_ascii_case(&record_type_str)
                    && r.host.eq_ignore_ascii_case(sub)
                {
                    matched.push(RemoteRecord::new(r.id, r.record));
                }
            }
        }

        Ok(matched)
    }

    async fn create_record(
        &self,
        _zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub = params.domain.sub_domain_or_at();
        let target_ip_str = params.ip.to_string();
        let record_type_str = params.record_type.to_string();
        let ttl_val = clamp_ttl(params.ttl, CLOUDNS_DEFAULT_TTL, MIN_DNS_TTL).to_string();

        let add_url = format!("{}/add-record.json", CLOUDNS_ENDPOINT);
        let add_form = [
            ("auth-id", self.auth_id.as_str()),
            ("auth-password", self.auth_password.as_str()),
            ("domain-name", params.domain.root_domain.as_str()),
            ("host", sub),
            ("type", record_type_str.as_str()),
            ("record", target_ip_str.as_str()),
            ("ttl", ttl_val.as_str()),
        ];

        let add_resp = self.client.post(&add_url).form(&add_form).send().await?;
        let status = add_resp.status();
        let add_text = add_resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &add_text));
        }

        let res: ClouDnsActionResp = serde_json::from_str(&add_text).unwrap_or(ClouDnsActionResp {
            status: None,
            status_description: None,
        });

        if res.status.as_deref() == Some("Success") {
            Ok(())
        } else {
            let err_msg = res.status_description.unwrap_or(add_text);
            Err(DnsProviderError::ApiError {
                code: "ClouDnsAddError".to_string(),
                message: format!("ClouDNS 创建记录失败: {}", err_msg),
            })
        }
    }

    async fn update_record(
        &self,
        _zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub = params.domain.sub_domain_or_at();
        let target_ip_str = params.ip.to_string();
        let ttl_val = clamp_ttl(params.ttl, CLOUDNS_DEFAULT_TTL, MIN_DNS_TTL).to_string();

        let modify_url = format!("{}/modify-record.json", CLOUDNS_ENDPOINT);
        let modify_form = [
            ("auth-id", self.auth_id.as_str()),
            ("auth-password", self.auth_password.as_str()),
            ("domain-name", params.domain.root_domain.as_str()),
            ("record-id", record_id),
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
        let status = modify_resp.status();
        let modify_text = modify_resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &modify_text));
        }

        let res: ClouDnsActionResp =
            serde_json::from_str(&modify_text).unwrap_or(ClouDnsActionResp {
                status: None,
                status_description: None,
            });

        if res.status.as_deref() == Some("Success") {
            Ok(())
        } else {
            let err_msg = res.status_description.unwrap_or(modify_text);
            Err(DnsProviderError::ApiError {
                code: "ClouDnsModifyError".to_string(),
                message: format!("ClouDNS 更新失败: {}", err_msg),
            })
        }
    }

    async fn delete_record(
        &self,
        _zone: &str,
        record: &RemoteRecord,
        _params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let delete_url = format!("{}/delete-record.json", CLOUDNS_ENDPOINT);
        let delete_form = [
            ("auth-id", self.auth_id.as_str()),
            ("auth-password", self.auth_password.as_str()),
            ("record-id", record.id.as_str()),
        ];

        let resp = self
            .client
            .post(&delete_url)
            .form(&delete_form)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(DnsProviderError::http_status(status, &text));
        }

        let res: ClouDnsActionResp = serde_json::from_str(&text).unwrap_or(ClouDnsActionResp {
            status: None,
            status_description: None,
        });

        if res.status.as_deref() == Some("Success") {
            Ok(())
        } else {
            let err_msg = res.status_description.unwrap_or(text);
            Err(DnsProviderError::ApiError {
                code: "ClouDnsDeleteError".to_string(),
                message: format!("ClouDNS 删除记录失败: {}", err_msg),
            })
        }
    }
}

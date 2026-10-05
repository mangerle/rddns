use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RemoteRecord, sync_record_via};
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const PORKBUN_ENDPOINT: &str = "https://api.porkbun.com/api/json/v3/dns";

/// Porkbun DNS 提供商
pub struct PorkbunProvider {
    api_key: String,
    secret_key: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct PorkbunRecord {
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
        Self {
            api_key,
            secret_key,
            client: crate::util::http::create_default_dns_client(http_interface),
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
impl RecordOps for PorkbunProvider {
    fn provider_name(&self) -> &'static str {
        "Porkbun"
    }

    async fn list_records(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_domain_param = if is_root { "" } else { &domain.sub_domain };

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
            return Err(DnsProviderError::http_status(query_status, &query_text));
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
        let mut remotes = Vec::with_capacity(existing_records.len());
        for rec in existing_records {
            if let Some(content) = rec.content {
                remotes.push(RemoteRecord::new("porkbun_record", content));
            }
        }
        Ok(remotes)
    }

    async fn create_record(
        &self,
        _zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(600).max(600).to_string();
        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_domain_param = if is_root { "" } else { &domain.sub_domain };

        let create_url = format!("{}/create/{}", PORKBUN_ENDPOINT, domain.root_domain);
        let mut create_payload = self.auth_payload();
        create_payload["name"] = json!(sub_domain_param);
        create_payload["type"] = json!(record_type.to_string());
        create_payload["content"] = json!(ip.to_string());
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
            return Err(DnsProviderError::http_status(create_status, &create_text));
        }

        let create_result: PorkbunBaseResponse = serde_json::from_str(&create_text)?;
        if create_result.status.eq_ignore_ascii_case("SUCCESS") {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: create_result.status,
                message: create_result
                    .message
                    .unwrap_or_else(|| "新增 Porkbun 记录失败".to_string()),
            })
        }
    }

    async fn update_record(
        &self,
        _zone: &str,
        _record_id: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> Result<(), DnsProviderError> {
        let ttl_val = ttl.unwrap_or(600).max(600).to_string();
        let is_root = domain.sub_domain.is_empty() || domain.sub_domain == "@";
        let sub_domain_param = if is_root { "" } else { &domain.sub_domain };

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
        edit_payload["content"] = json!(ip.to_string());
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
            return Err(DnsProviderError::http_status(edit_status, &edit_text));
        }

        let edit_result: PorkbunBaseResponse = serde_json::from_str(&edit_text)?;
        if edit_result.status.eq_ignore_ascii_case("SUCCESS") {
            Ok(())
        } else {
            Err(DnsProviderError::ApiError {
                code: edit_result.status,
                message: edit_result
                    .message
                    .unwrap_or_else(|| "更新 Porkbun 记录失败".to_string()),
            })
        }
    }
}

#[async_trait]
impl DnsProvider for PorkbunProvider {
    fn provider_name(&self) -> &'static str {
        <Self as RecordOps>::provider_name(self)
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

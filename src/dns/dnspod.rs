use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult};
use crate::util::crypto::{Tc3ApiEndpoint, request_tc3_api};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::time::Duration;

const DNSPOD_ENDPOINT: Tc3ApiEndpoint = Tc3ApiEndpoint {
    host: "dnspod.tencentcloudapi.com",
    service: "dnspod",
    version: "2021-03-23",
};

pub struct TencentCloudProvider {
    client: Client,
    secret_id: String,
    secret_key: String,
}

impl TencentCloudProvider {
    pub fn new(
        secret_id: String,
        secret_key: String,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        if secret_id.trim().is_empty() || secret_key.trim().is_empty() {
            return Err(DnsProviderError::MissingCredentials(
                "腾讯云 DNSPod 需要配置 SecretId 与 SecretKey".to_string(),
            ));
        }

        let client =
            crate::util::http::create_task_http_client(http_interface, Duration::from_secs(15))?;

        Ok(Self {
            client,
            secret_id,
            secret_key,
        })
    }

    async fn request_api<T: for<'de> Deserialize<'de>>(
        &self,
        action: &str,
        payload_json: serde_json::Value,
    ) -> Result<T, DnsProviderError> {
        request_tc3_api(
            &self.client,
            &self.secret_id,
            &self.secret_key,
            &DNSPOD_ENDPOINT,
            action,
            payload_json,
        )
        .await
    }
}

#[async_trait]
impl DnsProvider for TencentCloudProvider {
    fn provider_name(&self) -> &'static str {
        "腾讯云 (DNSPod)"
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
        let sub_domain = domain.sub_domain_or_at().to_string();
        let root_domain = domain.root_domain.clone();
        let record_line = domain
            .custom_params
            .get("line")
            .cloned()
            .unwrap_or_else(|| "默认".to_string());
        let ttl_val = ttl.unwrap_or(600).max(1);

        // 1. 查询现有解析记录列表 (单页最大 100 条)
        let list_payload = json!({
            "Domain": root_domain,
            "Subdomain": sub_domain,
            "RecordType": record_type.to_string(),
            "Limit": 100,
        });

        let list_res: Result<TcRecordListResponse, DnsProviderError> =
            self.request_api("DescribeRecordList", list_payload).await;

        let records = match list_res {
            Ok(data) => data.record_list.unwrap_or_default(),
            Err(DnsProviderError::ApiError { ref code, .. })
                if code == "ResourceNotFound.NoDataOfRecord"
                    || code == "ResourceNotFound.NoDataOfDomain" =>
            {
                // 腾讯云 DNSPod 在没有查到记录时会返回 ResourceNotFound 错误码，此处应视为空记录列表
                Vec::new()
            }
            Err(e) => return Err(e),
        };

        let matched = records.into_iter().find(|r| {
            let name_match = r.name.eq_ignore_ascii_case(&sub_domain);
            let type_match = r.record_type.eq_ignore_ascii_case(&record_type.to_string());
            let line_match = if let Some(ref l) = r.line {
                l.eq_ignore_ascii_case(&record_line)
            } else {
                true
            };
            name_match && type_match && line_match
        });

        if let Some(existing) = matched {
            if existing.value == target_ip_str {
                info!(
                    "[{}] 域名 {} 记录未变化 ({}), 跳过更新",
                    self.provider_name(),
                    full_domain,
                    target_ip_str
                );
                return Ok(SyncRecordResult::unchanged(
                    full_domain,
                    record_type,
                    target_ip_str,
                ));
            }

            // 修改记录
            let modify_payload = json!({
                "Domain": root_domain,
                "RecordId": existing.record_id,
                "SubDomain": sub_domain,
                "RecordType": record_type.to_string(),
                "RecordLine": record_line,
                "Value": target_ip_str,
                "TTL": ttl_val,
            });

            let _: serde_json::Value = self.request_api("ModifyRecord", modify_payload).await?;

            info!(
                "[{}] 成功更新域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult::updated(
                full_domain,
                record_type,
                target_ip_str,
            ))
        } else {
            // 创建记录
            let create_payload = json!({
                "Domain": root_domain,
                "SubDomain": sub_domain,
                "RecordType": record_type.to_string(),
                "RecordLine": record_line,
                "Value": target_ip_str,
                "TTL": ttl_val,
            });

            let _: serde_json::Value = self.request_api("CreateRecord", create_payload).await?;

            info!(
                "[{}] 成功创建域名 {} -> {}",
                self.provider_name(),
                full_domain,
                target_ip_str
            );
            Ok(SyncRecordResult::created(
                full_domain,
                record_type,
                target_ip_str,
            ))
        }
    }
}

#[derive(Debug, Deserialize)]
struct TcRecordListResponse {
    #[serde(rename = "RecordList")]
    record_list: Option<Vec<TcRecordItem>>,
}

#[derive(Debug, Deserialize)]
struct TcRecordItem {
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value")]
    value: String,
    #[serde(rename = "Line")]
    line: Option<String>,
}

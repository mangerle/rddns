use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;

const NAMECHEAP_ENDPOINT: &str = "https://dynamicdns.park-your-domain.com/update";

/// Namecheap 动态 DNS 提供商
pub struct NamecheapProvider {
    password: String,
    client: Client,
}

impl NamecheapProvider {
    pub fn new(password: String, http_interface: Option<&str>) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { password, client }
    }
}

#[async_trait]
impl DnsProvider for NamecheapProvider {
    fn provider_name(&self) -> &'static str {
        "Namecheap"
    }

    async fn sync_record(
        &self,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        _ttl: Option<u32>,
    ) -> Result<SyncRecordResult, DnsProviderError> {
        let full_domain = domain.full_domain();
        let target_ip_str = ip.to_string();

        // Namecheap 动态更新接口仅支持 IPv4 (A 记录)
        if record_type == DnsRecordType::AAAA {
            return Err(DnsProviderError::Other(
                "Namecheap 动态 DNS 官方接口目前仅支持 IPv4 (A 记录)，不支持 IPv6".to_string(),
            ));
        }

        let host = domain.sub_domain_or_at();

        let resp = self
            .client
            .get(NAMECHEAP_ENDPOINT)
            .query(&[
                ("host", host),
                ("domain", &domain.root_domain),
                ("password", &self.password),
                ("ip", &target_ip_str),
            ])
            .send()
            .await?;

        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Namecheap HTTP 请求异常: {}", body_text),
            });
        }

        // 解析 Namecheap XML 响应: <ErrCount>0</ErrCount> 或 <Done>true</Done>
        if body_text.contains("<ErrCount>0</ErrCount>")
            || body_text.contains("<Done>true</Done>")
            || body_text.contains("Success")
        {
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
            Err(DnsProviderError::ApiError {
                code: "NamecheapError".to_string(),
                message: format!("Namecheap 更新失败: {}", body_text),
            })
        }
    }
}

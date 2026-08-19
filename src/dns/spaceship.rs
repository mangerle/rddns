use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::{info, warn};
use reqwest::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const SPACESHIP_API_BASE: &str = "https://spaceship.dev/api/v1/dns/records";

/// Spaceship DNS 提供商 (Namecheap 旗下新平台)
pub struct SpaceshipProvider {
    api_key: String,
    api_secret: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct SpaceshipItem {
    #[serde(rename = "type")]
    record_type: String,
    address: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct SpaceshipListResponse {
    items: Option<Vec<SpaceshipItem>>,
}

#[derive(Debug, Deserialize)]
struct SpaceshipErrorResponse {
    detail: Option<String>,
}

impl SpaceshipProvider {
    pub fn new(api_key: String, api_secret: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            api_secret,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(hv) = HeaderValue::from_str(&self.api_key) {
            headers.insert(HeaderName::from_static("x-api-key"), hv);
        }
        if let Ok(hv) = HeaderValue::from_str(&self.api_secret) {
            headers.insert(HeaderName::from_static("x-api-secret"), hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }
}

#[async_trait]
impl DnsProvider for SpaceshipProvider {
    fn provider_name(&self) -> &'static str {
        "Spaceship"
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
        let ttl_val = ttl.unwrap_or(600).max(60);

        let sub_name = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        let domain_url = format!("{}/{}", SPACESHIP_API_BASE, domain.root_domain);

        // 1. 查询现有解析记录列表
        let list_resp = self
            .client
            .get(&domain_url)
            .headers(self.build_headers())
            .query(&[("take", "500"), ("skip", "0")])
            .send()
            .await?;

        let status = list_resp.status();
        let body_text = list_resp.text().await?;

        if !status.is_success() {
            let err_detail = serde_json::from_str::<SpaceshipErrorResponse>(&body_text)
                .ok()
                .and_then(|e| e.detail)
                .unwrap_or(body_text);
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Spaceship 记录查询失败: {}", err_detail),
            });
        }

        let list_data: SpaceshipListResponse = serde_json::from_str(&body_text)?;
        let items = list_data.items.unwrap_or_default();

        let mut existing_ips = Vec::new();
        for item in &items {
            if item
                .record_type
                .eq_ignore_ascii_case(&record_type.to_string())
                && (item.name.eq_ignore_ascii_case(sub_name)
                    || (sub_name.is_empty() && item.name == "@"))
            {
                existing_ips.push(item.address.clone());
            }
        }

        if existing_ips.len() == 1 && existing_ips[0] == target_ip_str {
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

        // 2. 如果存在旧的其它 IP，先调用 DELETE 清理旧记录
        let old_ips: Vec<String> = existing_ips
            .into_iter()
            .filter(|ip_item| ip_item != &target_ip_str)
            .collect();

        if !old_ips.is_empty() {
            let del_payload: Vec<serde_json::Value> = old_ips
                .into_iter()
                .map(|old_ip| {
                    json!({
                        "type": record_type.to_string(),
                        "address": old_ip,
                        "name": sub_name
                    })
                })
                .collect();

            match self
                .client
                .delete(&domain_url)
                .headers(self.build_headers())
                .json(&del_payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        let text = resp.text().await.unwrap_or_default();
                        warn!("Spaceship 删除旧解析记录响应非成功状态: {}", text);
                    }
                }
                Err(e) => {
                    warn!("Spaceship 删除旧解析记录网络请求失败: {}", e);
                }
            }
        }

        // 3. 调用 PUT 创建/覆盖新记录
        let put_payload = json!({
            "force": true,
            "items": [
                {
                    "type": record_type.to_string(),
                    "address": target_ip_str,
                    "name": sub_name,
                    "ttl": ttl_val
                }
            ]
        });

        let put_resp = self
            .client
            .put(&domain_url)
            .headers(self.build_headers())
            .json(&put_payload)
            .send()
            .await?;

        let put_status = put_resp.status();
        if put_status.is_success() {
            info!(
                "[{}] 成功更新/创建域名 {} -> {}",
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
            let put_body = put_resp.text().await.unwrap_or_default();
            Err(DnsProviderError::ApiError {
                code: put_status.to_string(),
                message: format!("Spaceship 记录写入失败: {}", put_body),
            })
        }
    }
}

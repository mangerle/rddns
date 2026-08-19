use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;

const DYNV6_ENDPOINT: &str = "https://dynv6.com/api/v2";

/// Dynv6 免费 IPv6/IPv4 动态 DNS 提供商
pub struct Dynv6Provider {
    token: String,
    client: Client,
}

#[derive(Debug, Deserialize)]
struct Dynv6Zone {
    id: u64,
    name: String,
    #[serde(rename = "ipv4address")]
    ipv4_address: Option<String>,
    #[serde(rename = "ipv6prefix")]
    ipv6_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Dynv6Record {
    id: u64,
    name: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    data: Option<String>,
}

impl Dynv6Provider {
    pub fn new(token: String, http_interface: Option<&str>) -> Self {
        Self {
            token,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
    }

    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let auth_val = format!("Bearer {}", self.token);
        if let Ok(hv) = HeaderValue::from_str(&auth_val) {
            headers.insert(AUTHORIZATION, hv);
        }
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, DnsProviderError> {
        let url = format!("{}{}", DYNV6_ENDPOINT, path);
        let mut req = self
            .client
            .request(method, &url)
            .headers(self.build_headers());
        if let Some(b) = body {
            req = req.json(&b);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let body_text = resp.text().await?;

        if !status.is_success() {
            return Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: format!("Dynv6 API 响应异常: {}", body_text),
            });
        }

        let parsed: T = serde_json::from_str(&body_text)?;
        Ok(parsed)
    }
}

#[async_trait]
impl DnsProvider for Dynv6Provider {
    fn provider_name(&self) -> &'static str {
        "Dynv6"
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

        // 1. 查询账户下的所有 Zones
        let zones: Vec<Dynv6Zone> = self.request(Method::GET, "/zones", None).await?;

        let matched_zone = zones
            .into_iter()
            .find(|z| full_domain == z.name || full_domain.ends_with(&format!(".{}", z.name)));

        let zone = matched_zone.ok_or_else(|| {
            DnsProviderError::ZoneNotFound(format!(
                "在 Dynv6 账户中未找到与域名 [{}] 匹配的 Zone",
                full_domain
            ))
        })?;

        let is_main_domain = full_domain.eq_ignore_ascii_case(&zone.name);

        if is_main_domain {
            // 2. 主域名更新: 对比当前 IP 并 PATCH /zones/{zone_id}
            let cur_ip = match record_type {
                DnsRecordType::A => zone.ipv4_address.as_deref(),
                DnsRecordType::AAAA => zone.ipv6_prefix.as_deref(),
            };

            if cur_ip == Some(&target_ip_str) {
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

            let patch_body = match record_type {
                DnsRecordType::A => json!({ "ipv4address": target_ip_str }),
                DnsRecordType::AAAA => json!({ "ipv6prefix": target_ip_str }),
            };

            let _: serde_json::Value = self
                .request(
                    Method::PATCH,
                    &format!("/zones/{}", zone.id),
                    Some(patch_body),
                )
                .await?;

            info!(
                "[{}] 成功更新主域名 {} -> {}",
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
            // 3. 子域名更新: 计算子域名前缀
            let sub_name = full_domain
                .strip_suffix(&format!(".{}", zone.name))
                .unwrap_or(&domain.sub_domain);

            // 查询 Zone 下的所有 records
            let records: Vec<Dynv6Record> = self
                .request(Method::GET, &format!("/zones/{}/records", zone.id), None)
                .await?;

            let record_type_str = record_type.to_string();
            let matched_record = records.into_iter().find(|r| {
                r.name.as_deref() == Some(sub_name)
                    && r.record_type.as_deref() == Some(&record_type_str)
            });

            if let Some(record) = matched_record {
                if record.data.as_deref() == Some(&target_ip_str) {
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

                // 更新记录
                let patch_body = json!({
                    "type": record_type.to_string(),
                    "data": target_ip_str
                });
                let _: serde_json::Value = self
                    .request(
                        Method::PATCH,
                        &format!("/zones/{}/records/{}", zone.id, record.id),
                        Some(patch_body),
                    )
                    .await?;

                info!(
                    "[{}] 成功更新子域名记录 {} -> {}",
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
                // 创建记录
                let post_body = json!({
                    "name": sub_name,
                    "type": record_type.to_string(),
                    "data": target_ip_str
                });
                let _: serde_json::Value = self
                    .request(
                        Method::POST,
                        &format!("/zones/{}/records", zone.id),
                        Some(post_body),
                    )
                    .await?;

                info!(
                    "[{}] 成功创建子域名记录 {} -> {}",
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
}

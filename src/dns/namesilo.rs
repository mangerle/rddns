use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use reqwest::Client;
use std::net::IpAddr;
use std::time::Duration;

const NAMESILO_API_BASE: &str = "https://www.namesilo.com/api";

/// NameSilo DNS 提供商
pub struct NameSiloProvider {
    api_key: String,
    client: Client,
}

impl NameSiloProvider {
    pub fn new(api_key: String, http_interface: Option<&str>) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { api_key, client }
    }

    /// 简易提取 XML 标签中的内容
    fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
        let open_tag = format!("<{}>", tag);
        let close_tag = format!("</{}>", tag);
        let start = xml.find(&open_tag)? + open_tag.len();
        let end = xml[start..].find(&close_tag)? + start;
        Some(xml[start..end].trim().to_string())
    }

    /// 检查 XML 响应中的 <code> 是否为 300 (成功)
    fn is_success_code(xml: &str) -> bool {
        Self::extract_xml_tag(xml, "code")
            .map(|c| c == "300")
            .unwrap_or(false)
    }
}

#[async_trait]
impl DnsProvider for NameSiloProvider {
    fn provider_name(&self) -> &'static str {
        "NameSilo"
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
        let ttl_val = ttl.unwrap_or(3600).max(3600).to_string(); // NameSilo 最低 TTL 常见为 3600

        let sub_host = if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        };

        // 1. 查询现有解析记录
        let list_url = format!("{}/dnsListRecords", NAMESILO_API_BASE);
        let list_resp = self
            .client
            .get(&list_url)
            .query(&[
                ("version", "1"),
                ("type", "xml"),
                ("key", &self.api_key),
                ("domain", &domain.root_domain),
            ])
            .send()
            .await?;
        let list_xml = list_resp.text().await?;

        if !Self::is_success_code(&list_xml) {
            let detail = Self::extract_xml_tag(&list_xml, "detail")
                .unwrap_or_else(|| "查询 NameSilo 解析记录失败".to_string());
            return Err(DnsProviderError::ApiError {
                code: "NameSiloQueryError".to_string(),
                message: detail,
            });
        }

        // 解析 <resource_record> 列表
        let mut matched_record_id: Option<String> = None;
        let mut current_value: Option<String> = None;

        let items: Vec<&str> = list_xml.split("<resource_record>").skip(1).collect();
        for item in items {
            let block = item.split("</resource_record>").next().unwrap_or("");
            let rec_host = Self::extract_xml_tag(block, "host").unwrap_or_default();
            let rec_type = Self::extract_xml_tag(block, "type").unwrap_or_default();
            let rec_val = Self::extract_xml_tag(block, "value").unwrap_or_default();
            let rec_id = Self::extract_xml_tag(block, "record_id").unwrap_or_default();

            if rec_host.eq_ignore_ascii_case(&full_domain)
                && rec_type.eq_ignore_ascii_case(&record_type.to_string())
            {
                matched_record_id = Some(rec_id);
                current_value = Some(rec_val);
                break;
            }
        }

        if let Some(record_id) = matched_record_id {
            if current_value.as_deref() == Some(&target_ip_str) {
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

            // 更新记录
            let update_url = format!("{}/dnsUpdateRecord", NAMESILO_API_BASE);
            let update_resp = self
                .client
                .get(&update_url)
                .query(&[
                    ("version", "1"),
                    ("type", "xml"),
                    ("key", &self.api_key),
                    ("domain", &domain.root_domain),
                    ("rrid", &record_id),
                    ("rrhost", sub_host),
                    ("rrvalue", &target_ip_str),
                    ("rrttl", &ttl_val),
                ])
                .send()
                .await?;
            let update_xml = update_resp.text().await?;

            if Self::is_success_code(&update_xml) {
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
                let detail = Self::extract_xml_tag(&update_xml, "detail")
                    .unwrap_or_else(|| "更新 NameSilo 记录失败".to_string());
                Err(DnsProviderError::ApiError {
                    code: "NameSiloUpdateError".to_string(),
                    message: detail,
                })
            }
        } else {
            // 创建记录
            let add_url = format!("{}/dnsAddRecord", NAMESILO_API_BASE);
            let rec_type_str = record_type.to_string();
            let add_resp = self
                .client
                .get(&add_url)
                .query(&[
                    ("version", "1"),
                    ("type", "xml"),
                    ("key", &self.api_key),
                    ("domain", &domain.root_domain),
                    ("rrhost", sub_host),
                    ("rrtype", &rec_type_str),
                    ("rrvalue", &target_ip_str),
                    ("rrttl", &ttl_val),
                ])
                .send()
                .await?;
            let add_xml = add_resp.text().await?;

            if Self::is_success_code(&add_xml) {
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
                let detail = Self::extract_xml_tag(&add_xml, "detail")
                    .unwrap_or_else(|| "新增 NameSilo 记录失败".to_string());
                Err(DnsProviderError::ApiError {
                    code: "NameSiloAddError".to_string(),
                    message: detail,
                })
            }
        }
    }
}

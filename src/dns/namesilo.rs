use crate::core::domain::ParsedDomain;
use crate::dns::ops::{RecordOps, RecordParams, RemoteRecord};
use crate::dns::trait_def::{DnsProviderError, DnsRecordType};
use async_trait::async_trait;
use reqwest::Client;

const NAMESILO_API_BASE: &str = "https://www.namesilo.com/api";

/// NameSilo DNS 提供商
pub struct NameSiloProvider {
    api_key: String,
    client: Client,
}

impl NameSiloProvider {
    pub fn new(api_key: String, http_interface: Option<&str>) -> Self {
        Self {
            api_key,
            client: crate::util::http::create_default_dns_client(http_interface),
        }
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

    /// 解析 NameSilo 所需的主机记录名 (@ 映射为空字符串)
    fn resolve_sub_host(domain: &ParsedDomain) -> &str {
        if domain.sub_domain.is_empty() || domain.sub_domain == "@" {
            ""
        } else {
            &domain.sub_domain
        }
    }

    /// 计算并规范化 TTL（NameSilo 官方限制最低 TTL 为 3600 秒）
    ///
    /// # 设计原理
    /// - **实现初衷**: NameSilo API 强制要求 DNS 记录 TTL 必须 >= 3600 秒，否则直接报错拒绝。
    /// - **核心优势**: 当用户配置的 TTL 低于 3600 秒时，输出清晰提示日志并自动平滑调整，杜绝静默改动导致用户疑惑 (P2-18)。
    fn resolve_ttl(ttl: Option<u32>) -> String {
        const NAMESILO_MIN_TTL: u32 = 3600;
        let configured = ttl.unwrap_or(NAMESILO_MIN_TTL);
        if configured < NAMESILO_MIN_TTL {
            log::info!(
                "[NameSilo] 用户配置的 TTL ({} 秒) 低于服务商官方最低限制 (3600 秒)，已自动修正为 3600 秒",
                configured
            );
            NAMESILO_MIN_TTL.to_string()
        } else {
            configured.to_string()
        }
    }
}

#[async_trait]
impl RecordOps for NameSiloProvider {
    fn provider_name(&self) -> &'static str {
        "NameSilo"
    }

    /// 查询现有解析记录列表
    async fn list_records(
        &self,
        zone: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
    ) -> Result<Vec<RemoteRecord>, DnsProviderError> {
        let full_domain = domain.full_domain();
        let list_url = format!("{}/dnsListRecords", NAMESILO_API_BASE);
        let list_resp = self
            .client
            .get(&list_url)
            .query(&[
                ("version", "1"),
                ("type", "xml"),
                ("key", &self.api_key),
                ("domain", zone),
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

        let mut matched = Vec::new();
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
                matched.push(RemoteRecord::new(rec_id, rec_val));
            }
        }

        Ok(matched)
    }

    async fn create_record(
        &self,
        zone: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub_host = Self::resolve_sub_host(params.domain);
        let ttl_val = Self::resolve_ttl(params.ttl);
        let rec_type_str = params.record_type.to_string();
        let target_ip_str = params.ip.to_string();

        let add_url = format!("{}/dnsAddRecord", NAMESILO_API_BASE);
        let add_resp = self
            .client
            .get(&add_url)
            .query(&[
                ("version", "1"),
                ("type", "xml"),
                ("key", &self.api_key),
                ("domain", zone),
                ("rrhost", sub_host),
                ("rrtype", &rec_type_str),
                ("rrvalue", &target_ip_str),
                ("rrttl", &ttl_val),
            ])
            .send()
            .await?;
        let add_xml = add_resp.text().await?;

        if Self::is_success_code(&add_xml) {
            Ok(())
        } else {
            let detail = Self::extract_xml_tag(&add_xml, "detail")
                .unwrap_or_else(|| "新增 NameSilo 记录失败".to_string());
            Err(DnsProviderError::ApiError {
                code: "NameSiloAddError".to_string(),
                message: detail,
            })
        }
    }

    /// 更新既有解析记录
    async fn update_record(
        &self,
        zone: &str,
        record_id: &str,
        params: &RecordParams<'_>,
    ) -> Result<(), DnsProviderError> {
        let sub_host = Self::resolve_sub_host(params.domain);
        let ttl_val = Self::resolve_ttl(params.ttl);
        let target_ip_str = params.ip.to_string();

        let update_url = format!("{}/dnsUpdateRecord", NAMESILO_API_BASE);
        let update_resp = self
            .client
            .get(&update_url)
            .query(&[
                ("version", "1"),
                ("type", "xml"),
                ("key", &self.api_key),
                ("domain", zone),
                ("rrid", record_id),
                ("rrhost", sub_host),
                ("rrvalue", &target_ip_str),
                ("rrttl", &ttl_val),
            ])
            .send()
            .await?;
        let update_xml = update_resp.text().await?;

        if Self::is_success_code(&update_xml) {
            Ok(())
        } else {
            let detail = Self::extract_xml_tag(&update_xml, "detail")
                .unwrap_or_else(|| "更新 NameSilo 记录失败".to_string());
            Err(DnsProviderError::ApiError {
                code: "NameSiloUpdateError".to_string(),
                message: detail,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_tag() {
        let xml = "<namesilo><code>300</code><detail>success</detail></namesilo>";
        assert_eq!(
            NameSiloProvider::extract_xml_tag(xml, "code"),
            Some("300".to_string())
        );
        assert_eq!(
            NameSiloProvider::extract_xml_tag(xml, "detail"),
            Some("success".to_string())
        );
        assert_eq!(NameSiloProvider::extract_xml_tag(xml, "notfound"), None);
        assert!(NameSiloProvider::is_success_code(xml));
    }

    #[test]
    fn test_resolve_sub_host() {
        let mut domain = ParsedDomain {
            raw: "sub.example.com".to_string(),
            root_domain: "example.com".to_string(),
            sub_domain: "sub".to_string(),
            custom_params: std::collections::HashMap::new(),
        };
        assert_eq!(NameSiloProvider::resolve_sub_host(&domain), "sub");

        domain.sub_domain = "@".to_string();
        assert_eq!(NameSiloProvider::resolve_sub_host(&domain), "");

        domain.sub_domain = "".to_string();
        assert_eq!(NameSiloProvider::resolve_sub_host(&domain), "");
    }
}

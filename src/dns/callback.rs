use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

pub struct CallbackProvider {
    client: Client,
    url: String,
    method: String,
    headers: Option<HashMap<String, String>>,
    body: Option<String>,
}

impl CallbackProvider {
    pub fn new(
        url: String,
        method: String,
        headers: Option<HashMap<String, String>>,
        body: Option<String>,
        http_interface: Option<&str>,
    ) -> Result<Self, DnsProviderError> {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(15))
            .build()?;

        Ok(Self {
            client,
            url,
            method,
            headers,
            body,
        })
    }

    fn replace_variables(
        template: &str,
        domain: &ParsedDomain,
        record_type: DnsRecordType,
        ip: &IpAddr,
        ttl: Option<u32>,
    ) -> String {
        template
            .replace("#{ip}", &ip.to_string())
            .replace("#{ipv4Addr}", &ip.to_string())
            .replace("#{ipv6Addr}", &ip.to_string())
            .replace("#{domain}", &domain.full_domain())
            .replace("#{rootDomain}", &domain.root_domain)
            .replace("#{subDomain}", domain.sub_domain_or_at())
            .replace("#{recordType}", &record_type.to_string())
            .replace("#{ttl}", &ttl.unwrap_or(600).to_string())
    }
}

#[async_trait]
impl DnsProvider for CallbackProvider {
    fn provider_name(&self) -> &'static str {
        "自定义 Callback"
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

        let rendered_url = Self::replace_variables(&self.url, domain, record_type, ip, ttl);
        let http_method = Method::from_str(&self.method.to_uppercase()).unwrap_or(Method::GET);

        let mut req = self.client.request(http_method, &rendered_url);

        if let Some(ref hdrs) = self.headers {
            let mut header_map = HeaderMap::new();
            for (k, v) in hdrs {
                let rendered_v = Self::replace_variables(v, domain, record_type, ip, ttl);
                if let (Ok(hk), Ok(hv)) =
                    (HeaderName::from_str(k), HeaderValue::from_str(&rendered_v))
                {
                    header_map.insert(hk, hv);
                }
            }
            req = req.headers(header_map);
        }

        if let Some(ref body_tmpl) = self.body {
            let rendered_body = Self::replace_variables(body_tmpl, domain, record_type, ip, ttl);
            req = req.body(rendered_body);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            tracing::info!(
                "[{}] 成功触发 Callback: {} -> {}, 响应: {}",
                self.provider_name(),
                full_domain,
                target_ip_str,
                text
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Updated,
                message: format!("Callback 执行成功: {}", text),
            })
        } else {
            Err(DnsProviderError::ApiError {
                code: status.to_string(),
                message: text,
            })
        }
    }
}

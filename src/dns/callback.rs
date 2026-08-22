use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus,
};
use async_trait::async_trait;
use log::info;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

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
        let client = crate::util::http::create_default_dns_client(http_interface);

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
        url_encode: bool,
    ) -> String {
        let encode_fn = |s: &str| -> String {
            if url_encode {
                url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
            } else {
                s.to_string()
            }
        };

        let ip_str = ip.to_string();
        let full_domain = domain.full_domain();
        let root_domain = domain.root_domain.clone();
        let sub_domain = domain.sub_domain_or_at();
        let record_type_str = record_type.to_string();
        let ttl_str = ttl.unwrap_or(600).to_string();

        template
            .replace("#{ip}", &encode_fn(&ip_str))
            .replace("#{ipv4Addr}", &encode_fn(&ip_str))
            .replace("#{ipv6Addr}", &encode_fn(&ip_str))
            .replace("#{domain}", &encode_fn(&full_domain))
            .replace("#{rootDomain}", &encode_fn(&root_domain))
            .replace("#{subDomain}", &encode_fn(sub_domain))
            .replace("#{recordType}", &encode_fn(&record_type_str))
            .replace("#{ttl}", &encode_fn(&ttl_str))
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

        let rendered_url = Self::replace_variables(&self.url, domain, record_type, ip, ttl, true);
        let http_method = Method::from_str(&self.method.to_uppercase()).unwrap_or(Method::GET);

        let mut req = self.client.request(http_method, &rendered_url);

        if let Some(ref hdrs) = self.headers {
            let mut header_map = HeaderMap::new();
            for (k, v) in hdrs {
                let rendered_v =
                    Self::replace_variables(v, domain, record_type, ip, ttl, false);
                if let (Ok(hk), Ok(hv)) =
                    (HeaderName::from_str(k), HeaderValue::from_str(&rendered_v))
                {
                    header_map.insert(hk, hv);
                }
            }
            req = req.headers(header_map);
        }

        if let Some(ref body_tmpl) = self.body {
            let rendered_body =
                Self::replace_variables(body_tmpl, domain, record_type, ip, ttl, false);
            req = req.body(rendered_body);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();

        if status.is_success() {
            info!(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_callback_replace_variables_url_encode() {
        let domain = ParsedDomain {
            raw: "*.测试.example.com".to_string(),
            root_domain: "example.com".to_string(),
            sub_domain: "*.测试".to_string(),
            custom_params: HashMap::new(),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let url_tmpl = "https://api.example.com/update?sub=#{subDomain}&domain=#{domain}&ip=#{ip}";
        let rendered_url =
            CallbackProvider::replace_variables(url_tmpl, &domain, DnsRecordType::A, &ip, None, true);

        // 中文字符应该在 URL 模式下被 URL 编码
        assert!(!rendered_url.contains("*.测试"));
        assert!(rendered_url.contains("*.%E6%B5%8B%E8%AF%95"));
        assert!(rendered_url.contains("1.2.3.4"));

        // Body 模式下应保留原始字符
        let body_tmpl = r##"{"sub": "#{subDomain}", "domain": "#{domain}", "ip": "#{ip}"}"##;
        let rendered_body =
            CallbackProvider::replace_variables(body_tmpl, &domain, DnsRecordType::A, &ip, None, false);
        assert!(rendered_body.contains("*.测试"));
    }
}

use crate::core::domain::ParsedDomain;
use crate::dns::trait_def::{
    DnsProvider, DnsProviderError, DnsRecordType, SyncRecordResult, SyncStatus, default_ttl,
};
use crate::util::http::{create_default_dns_client, url_encode_if};
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
        let client = create_default_dns_client(http_interface);

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
        let ip_str = ip.to_string();
        let ipv4_str = if ip.is_ipv4() { ip_str.as_str() } else { "" };
        let ipv6_str = if ip.is_ipv6() { ip_str.as_str() } else { "" };
        let full_domain = domain.full_domain();
        let root_domain = domain.root_domain.clone();
        let sub_domain = domain.sub_domain_or_at();
        let record_type_str = record_type.to_string();
        let ttl_str = default_ttl(ttl).to_string();

        template
            .replace("#{ip}", &url_encode_if(&ip_str, url_encode))
            .replace("#{ipv4Addr}", &url_encode_if(ipv4_str, url_encode))
            .replace("#{ipv6Addr}", &url_encode_if(ipv6_str, url_encode))
            .replace("#{domain}", &url_encode_if(&full_domain, url_encode))
            .replace("#{rootDomain}", &url_encode_if(&root_domain, url_encode))
            .replace("#{subDomain}", &url_encode_if(sub_domain, url_encode))
            .replace(
                "#{recordType}",
                &url_encode_if(&record_type_str, url_encode),
            )
            .replace("#{ttl}", &url_encode_if(&ttl_str, url_encode))
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
                let rendered_v = Self::replace_variables(v, domain, record_type, ip, ttl, false);
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
        // 响应体读取失败必须传播而非静默吞掉：吞掉后空体会在下方
        // `status.is_success()` 分支被当作成功，并把空字符串写入
        // SyncRecordResult.message，向用户谎报「Callback 执行成功」(P1-7)
        let text = resp.text().await?;

        if status.is_success() {
            // 先按安全字符上限截断再执行凭据脱敏，防止对超大响应体执行全局正则回溯 (P1-7)
            let safe_resp = crate::dns::trait_def::format_sanitized_err(&text);
            info!(
                "[{}] 成功触发 Callback: {} -> {}, 响应: {}",
                self.provider_name(),
                full_domain,
                target_ip_str,
                safe_resp
            );
            Ok(SyncRecordResult {
                domain: full_domain,
                record_type,
                target_ip: target_ip_str,
                status: SyncStatus::Updated,
                message: format!("Callback 执行成功: {}", safe_resp),
            })
        } else {
            Err(DnsProviderError::http_status(status, &text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_callback_replace_variables_url_encode() {
        let domain = ParsedDomain {
            raw: "*.测试.example.com".to_string(),
            root_domain: "example.com".to_string(),
            sub_domain: "*.测试".to_string(),
            custom_params: HashMap::new(),
        };
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        let url_tmpl = "https://api.example.com/update?sub=#{subDomain}&domain=#{domain}&ip=#{ip}&v4=#{ipv4Addr}&v6=#{ipv6Addr}";
        let rendered_url = CallbackProvider::replace_variables(
            url_tmpl,
            &domain,
            DnsRecordType::A,
            &ip,
            None,
            true,
        );

        // 中文字符应该在 URL 模式下被 URL 编码，且 IPv4 场景下 #{ipv6Addr} 为空
        assert!(!rendered_url.contains("*.测试"));
        assert!(rendered_url.contains("*.%E6%B5%8B%E8%AF%95"));
        assert!(rendered_url.contains("v4=1.2.3.4&v6="));

        // IPv6 场景下 #{ipv4Addr} 为空，#{ipv6Addr} 填入 IPv6 地址
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let rendered_v6 = CallbackProvider::replace_variables(
            "v4=#{ipv4Addr}&v6=#{ipv6Addr}",
            &domain,
            DnsRecordType::AAAA,
            &ipv6,
            None,
            false,
        );
        assert_eq!(rendered_v6, "v4=&v6=2001:db8::1");

        // Body 模式下应保留原始字符
        let body_tmpl = r##"{"sub": "#{subDomain}", "domain": "#{domain}", "ip": "#{ip}"}"##;
        let rendered_body = CallbackProvider::replace_variables(
            body_tmpl,
            &domain,
            DnsRecordType::A,
            &ip,
            None,
            false,
        );
        assert!(rendered_body.contains("*.测试"));
    }
}

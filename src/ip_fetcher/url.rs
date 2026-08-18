use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{extract_ipv4, extract_ipv6};
use async_trait::async_trait;
use reqwest::Client;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// 基于 HTTP(S) URL 接口提取公网 IP
pub struct UrlIpFetcher {
    endpoints: Vec<String>,
    regex: Option<String>,
    client: Client,
}

impl UrlIpFetcher {
    pub fn new(
        endpoints: Vec<String>,
        regex: Option<String>,
        http_interface: Option<&str>,
    ) -> Self {
        let client = crate::util::http::create_task_http_client_builder(http_interface)
            .timeout(Duration::from_secs(5))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
            .build()
            .unwrap_or_default();

        Self {
            endpoints,
            regex,
            client,
        }
    }
}

#[async_trait]
impl IpFetcher for UrlIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        if self.endpoints.is_empty() {
            return Ok(None);
        }

        let mut last_err = None;
        for endpoint in &self.endpoints {
            match self.client.get(endpoint).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(body) => {
                        if let Some(ip) = extract_ipv4(&body, self.regex.as_deref()) {
                            tracing::debug!("从接口 {} 成功获取到 IPv4: {}", endpoint, ip);
                            return Ok(Some(ip));
                        } else {
                            tracing::debug!("接口 {} 返回内容无法解析为 IPv4: {}", endpoint, body);
                            last_err = Some(FetchError::NoValidIp(body));
                        }
                    }
                    Err(e) => {
                        tracing::debug!("读取接口 {} 响应体失败: {}", endpoint, e);
                        last_err = Some(FetchError::Http(e));
                    }
                },
                Err(e) => {
                    tracing::debug!("请求接口 {} 失败: {}", endpoint, e);
                    last_err = Some(FetchError::Http(e));
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| FetchError::Other("所有 IPv4 URL 接口均请求失败".to_string())))
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        if self.endpoints.is_empty() {
            return Ok(None);
        }

        let mut last_err = None;
        for endpoint in &self.endpoints {
            match self.client.get(endpoint).send().await {
                Ok(resp) => match resp.text().await {
                    Ok(body) => {
                        if let Some(ip) = extract_ipv6(&body, self.regex.as_deref()) {
                            tracing::debug!("从接口 {} 成功获取到 IPv6: {}", endpoint, ip);
                            return Ok(Some(ip));
                        } else {
                            tracing::debug!("接口 {} 返回内容无法解析为 IPv6: {}", endpoint, body);
                            last_err = Some(FetchError::NoValidIp(body));
                        }
                    }
                    Err(e) => {
                        tracing::debug!("读取接口 {} 响应体失败: {}", endpoint, e);
                        last_err = Some(FetchError::Http(e));
                    }
                },
                Err(e) => {
                    tracing::debug!("请求接口 {} 失败: {}", endpoint, e);
                    last_err = Some(FetchError::Http(e));
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| FetchError::Other("所有 IPv6 URL 接口均请求失败".to_string())))
    }
}

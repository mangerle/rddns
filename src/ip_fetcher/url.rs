use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::http::get_family_http_client;
use crate::util::net::{extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4};
use async_trait::async_trait;
use log::debug;
use reqwest::{Client, Response};
use std::fmt::Display;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// 基于 HTTP(S) URL 接口提取公网 IP 的探测器
pub struct UrlIpFetcher {
    endpoints: Vec<String>,
    regex: Option<String>,
    ipv4_client: Client,
    ipv6_client: Client,
}

impl UrlIpFetcher {
    /// 单个 IP 查询接口的请求超时
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
    /// 探测请求的 User-Agent，纳入客户端缓存键维度
    const USER_AGENT: &'static str =
        concat!("rddns/", env!("CARGO_PKG_VERSION"), " (Rust DDNS Client)");

    /// 创建基于 HTTP(S) URL 接口的公网 IP 探测器
    ///
    /// # 设计原理
    /// - **实现初衷**: 适用于绝大多数普通家用或云端服务器环境，通过请求公共的 IP 反射 API（如 ipify, icanhazip, cip.cc 等）直接获取对外公网 IP。
    /// - **核心优势**: 穿透能力最强，能穿越绝大多数 NAT、代理与安全网关；天然支持通过多端点列表进行多源主备容灾切换。
    /// - **代价与局限**: 依赖第三方公共 HTTP 服务的可用性与稳定性。
    pub fn new(
        endpoints: Vec<String>,
        regex: Option<String>,
        http_interface: Option<&str>,
    ) -> Self {
        let timeout = Self::REQUEST_TIMEOUT;
        let user_agent = Self::USER_AGENT;

        // 客户端按「网卡 + 协议族 + 超时 + UA」维度纳入全局缓存，
        // 避免每轮探测都重建连接池并重复进行 TCP/TLS 握手。
        let ipv4_client = get_family_http_client(http_interface, false, timeout, user_agent);
        let ipv6_client = get_family_http_client(http_interface, true, timeout, user_agent);

        Self {
            endpoints,
            regex,
            ipv4_client,
            ipv6_client,
        }
    }

    /// 流式限制读取响应体文本内容，防止恶意超大响应耗尽内存
    ///
    /// # Errors
    ///
    /// - 响应状态码非成功返回 [`FetchError::Other`]
    /// - 网络传输异常返回 [`FetchError::Http`]
    /// - 响应体超过 64KB 返回 [`FetchError::Other`]
    /// - 文本非 UTF-8 编码返回 [`FetchError::Other`]
    async fn read_limited_text(mut resp: Response) -> Result<String, FetchError> {
        let status = resp.status();
        if !status.is_success() {
            return Err(FetchError::Other(format!(
                "接口返回异常 HTTP 状态码: {}",
                status
            )));
        }

        const MAX_RESPONSE_BYTES: usize = 65536;
        let mut buffer = Vec::with_capacity(256);

        // 流式读取分块并在达到上限时立即中断，防止恶意大文件耗尽系统内存
        while let Some(chunk) = resp.chunk().await.map_err(FetchError::from)? {
            if buffer.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(FetchError::Other(format!(
                    "响应体体积超过安全限制 (已接收 > {} 字节)",
                    MAX_RESPONSE_BYTES
                )));
            }
            buffer.extend_from_slice(&chunk);
        }

        String::from_utf8(buffer)
            .map_err(|e| FetchError::Other(format!("响应内容非合法 UTF-8 文本: {}", e)))
    }

    /// 通用 URL 遍历与 IP 提取循环
    async fn fetch_ip_generic<T: Display>(
        &self,
        client: &Client,
        ip_name: &str,
        extractor: impl Fn(&str) -> Result<T, FetchError>,
    ) -> Result<Option<T>, FetchError> {
        if self.endpoints.is_empty() {
            return Ok(None);
        }

        let mut last_err = None;
        for endpoint in &self.endpoints {
            let safe_endpoint = crate::util::text::sanitize_sensitive_params(endpoint);
            match client.get(endpoint).send().await {
                Ok(resp) => match Self::read_limited_text(resp).await {
                    Ok(body) => match extractor(&body) {
                        Ok(ip) => {
                            debug!("从接口 {} 成功获取到 {}: {}", safe_endpoint, ip_name, ip);
                            return Ok(Some(ip));
                        }
                        Err(e) => {
                            debug!(
                                "接口 {} 返回内容提取 {} 失败: {:?}",
                                safe_endpoint, ip_name, e
                            );
                            last_err = Some(e);
                        }
                    },
                    Err(e) => {
                        debug!("读取接口 {} 响应体失败: {:?}", safe_endpoint, e);
                        last_err = Some(e);
                    }
                },
                Err(e) => {
                    let fetch_err = FetchError::from(e);
                    debug!("请求接口 {} 失败: {}", safe_endpoint, fetch_err);
                    last_err = Some(fetch_err);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| FetchError::Other(format!("所有 {} URL 接口均请求失败", ip_name))))
    }
}

#[async_trait]
impl IpFetcher for UrlIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        self.fetch_ip_generic(&self.ipv4_client, "IPv4", |body| {
            let ip = extract_ipv4(body, self.regex.as_deref())
                .ok_or_else(|| FetchError::NoValidIpv4(body.to_string()))?;
            // 必须校验为公网单播地址：若查询接口被劫持或遭 DNS 污染返回了
            // RFC1918 私网 / 运营商 CGNAT 地址，直接提交到公网 DNS 会使域名对外不可达。
            if is_public_ipv4(&ip) {
                Ok(ip)
            } else {
                Err(FetchError::NoValidIpv4(format!(
                    "接口返回的 IPv4 非公网单播地址: {}",
                    ip
                )))
            }
        })
        .await
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        self.fetch_ip_generic(&self.ipv6_client, "IPv6", |body| {
            let ip = extract_ipv6(body, self.regex.as_deref())
                .ok_or_else(|| FetchError::NoValidIpv6(body.to_string()))?;
            if is_global_unicast_ipv6(&ip) {
                Ok(ip)
            } else {
                Err(FetchError::NoValidIpv6(format!("非全球单播 IPv6: {}", ip)))
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// 构造仅执行提取与校验逻辑的提取器，验证公网判定行为（不发起真实网络请求）
    fn build_ipv4_extractor(regex: Option<&str>) -> impl Fn(&str) -> Result<Ipv4Addr, FetchError> {
        move |body: &str| {
            let ip = extract_ipv4(body, regex)
                .ok_or_else(|| FetchError::NoValidIpv4(body.to_string()))?;
            if is_public_ipv4(&ip) {
                Ok(ip)
            } else {
                Err(FetchError::NoValidIpv4(format!(
                    "接口返回的 IPv4 非公网单播地址: {}",
                    ip
                )))
            }
        }
    }

    #[test]
    fn test_fetch_ipv4_accepts_public_addresses() {
        let extract = build_ipv4_extractor(None);
        // 普通公网 IPv4 应当被接受
        assert_eq!(extract("1.2.3.4").unwrap(), Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(
            extract("当前 IP: 114.114.114.114").unwrap(),
            Ipv4Addr::new(114, 114, 114, 114)
        );
    }

    #[test]
    fn test_fetch_ipv4_rejects_private_and_cgnat_addresses() {
        let extract = build_ipv4_extractor(None);
        // RFC1918 私网地址必须被拒绝，避免内网地址被提交到公网 DNS
        for private in ["192.168.1.1", "10.0.0.5", "172.16.0.1"] {
            let res = extract(private);
            assert!(res.is_err(), "私网地址 {} 本应被拒绝", private);
            assert!(res.unwrap_err().to_string().contains("非公网单播"));
        }
        // 运营商 CGNAT(100.64.0.0/10) 同样必须被拒绝
        for cgnat in ["100.64.0.1", "100.127.255.254"] {
            assert!(extract(cgnat).is_err(), "CGNAT 地址 {} 本应被拒绝", cgnat);
        }
        // 回环与未指定地址
        for special in ["127.0.0.1", "0.0.0.0"] {
            assert!(extract(special).is_err(), "特殊地址 {} 本应被拒绝", special);
        }
    }
}

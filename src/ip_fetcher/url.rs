use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::http::{create_http_client, create_task_http_client_builder_for_family};
use crate::util::net::{extract_ipv4, extract_ipv6, is_global_unicast_ipv6};
use async_trait::async_trait;
use log::{debug, warn};
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
    /// 针对指定地址族构建具备超时与 User-Agent 的 HTTP 客户端
    fn build_client(
        http_interface: Option<&str>,
        is_ipv6: bool,
        timeout: Duration,
        user_agent: &'static str,
    ) -> Client {
        match create_task_http_client_builder_for_family(http_interface, is_ipv6)
            .timeout(timeout)
            .user_agent(user_agent)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                if let Some(iface) = http_interface {
                    warn!(
                        "为任务网卡 [{}] 构建 {} 专有客户端失败: {}，降级为通用客户端",
                        iface,
                        if is_ipv6 { "IPv6" } else { "IPv4" },
                        e
                    );
                }
                create_http_client(timeout).unwrap_or_else(|_| {
                    Client::builder()
                        .timeout(timeout)
                        .build()
                        .unwrap_or_default()
                })
            }
        }
    }

    /// 创建基于 HTTP(S) URL 接口的公网 IP 探测器
    ///
    /// # 设计原理
    /// - **实现初衷**: 适用于绝大多数普通家用或云端服务器环境，通过请求公共的 IP 反射 API（如 ipify, icanhazip, cip.cc 等）直接获取对外公网 IP。
    /// - **核心优势**: 穿透能力最强，能穿越绝大多数 NAT、代理与安全网关；天然支持通过多端点列表进行多源主备容灾切换。
    /// - **代价与局限**: 依赖第三方公共 HTTP 服务的可用性与稳定性；每次探测伴随完整的 TLS 握手与 HTTP 报文解析开销。
    pub fn new(
        endpoints: Vec<String>,
        regex: Option<String>,
        http_interface: Option<&str>,
    ) -> Self {
        let timeout = Duration::from_secs(5);
        let user_agent = "rddns/0.7.0 (Rust DDNS Client)";

        let ipv4_client = Self::build_client(http_interface, false, timeout, user_agent);
        let ipv6_client = Self::build_client(http_interface, true, timeout, user_agent);

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
        let mut buffer = Vec::new();

        // 流式读取分块并在达到上限时立即中断，防止恶意大文件耗尽系统内存
        while let Some(chunk) = resp.chunk().await.map_err(FetchError::Http)? {
            if buffer.len() + chunk.len() > MAX_RESPONSE_BYTES {
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
            match client.get(endpoint).send().await {
                Ok(resp) => match Self::read_limited_text(resp).await {
                    Ok(body) => match extractor(&body) {
                        Ok(ip) => {
                            debug!("从接口 {} 成功获取到 {}: {}", endpoint, ip_name, ip);
                            return Ok(Some(ip));
                        }
                        Err(e) => {
                            debug!("接口 {} 返回内容提取 {} 失败: {:?}", endpoint, ip_name, e);
                            last_err = Some(e);
                        }
                    },
                    Err(e) => {
                        debug!("读取接口 {} 响应体失败: {:?}", endpoint, e);
                        last_err = Some(e);
                    }
                },
                Err(e) => {
                    debug!("请求接口 {} 失败: {}", endpoint, e);
                    last_err = Some(FetchError::Http(e));
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
            extract_ipv4(body, self.regex.as_deref())
                .ok_or_else(|| FetchError::NoValidIpv4(body.to_string()))
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

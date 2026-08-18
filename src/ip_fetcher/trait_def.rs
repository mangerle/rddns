use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("网络请求错误: {0}")]
    Http(#[from] reqwest::Error),
    #[error("系统 I/O 或命令执行错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("命令执行超时")]
    Timeout,
    #[error("未找到指定的网卡: {0}")]
    InterfaceNotFound(String),
    #[error("未能从接口响应中提取到有效的 IPv4 地址 (接口返回: {0})")]
    NoValidIpv4(String),
    #[error("未能从接口响应中提取到有效的 IPv6 地址 (接口返回: {0})")]
    NoValidIpv6(String),
    #[error("从响应中未能提取到合法的 IP 地址: {0}")]
    NoValidIp(String),
    #[error("其他提取错误: {0}")]
    Other(String),
}

/// IP 提取器统一抽象接口
#[async_trait]
pub trait IpFetcher: Send + Sync {
    /// 获取当前公网 IPv4
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError>;

    /// 获取当前公网 IPv6
    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError>;
}

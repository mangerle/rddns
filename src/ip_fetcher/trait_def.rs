use async_trait::async_trait;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// IP 提取过程中可能发生的领域错误类型
#[derive(Debug, Error)]
pub enum FetchError {
    #[error("网络请求错误: {0}")]
    Http(#[from] reqwest::Error),
    #[error("系统 I/O 或命令执行错误: {0}")]
    Io(#[from] io::Error),
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
///
/// # 设计原理
/// - **实现初衷**: 将不同来源（HTTP API、本地网卡、STUN UDP 协议、外部脚本命令）的 IP 探测行为解耦为标准异步协议，实现上层调度引擎与具体探测实现的彻底隔离。
/// - **核心优势**: 统一管理 IPv4 与 IPv6 的双栈探测，各实现可按需返回 `Option<IpAddr>`，未配置或不支持某一地址族时返回 `Ok(None)`。
/// - **代价与局限**: 采用 `async_trait` 宏在底层生成堆分配的 `Pin<Box<dyn Future>>`，但在低频的 DDNS 定时轮询场景下该开销完全可忽略。
#[async_trait]
pub trait IpFetcher: Send + Sync {
    /// 获取当前公网 IPv4
    ///
    /// # Errors
    ///
    /// 当网络通信失败、网卡不存在或未能提取到合法 IP 时返回 [`FetchError`]。
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError>;

    /// 获取当前公网 IPv6
    ///
    /// # Errors
    ///
    /// 当网络通信失败、网卡不存在或未能提取到合法 IP 时返回 [`FetchError`]。
    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError>;
}

use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{extract_ipv4, extract_ipv6};
use async_trait::async_trait;
use log::warn;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// 基于外部命令/脚本提取 IP 的探测器
pub struct CommandIpFetcher {
    cmd: String,
    regex: Option<String>,
    timeout: Duration,
}

impl CommandIpFetcher {
    /// 创建基于外部命令的 IP 提取器
    ///
    /// # 设计原理
    /// - **实现初衷**: 面对复杂网络拓扑（如多拨 PPPoE、特种路由器 API、VPN 虚拟隧道或需调用私有认证脚本取 IP 时），为用户提供最大程度的灵活性，可通过自定义脚本或 CLI 工具提取 IP。
    /// - **核心优势**: 具备进程级隔离与强制生命周期管理（启用 `kill_on_drop` 与超时保护），杜绝孤儿进程与僵尸进程驻留。
    /// - **代价与局限**: 每次提取均需创建子进程，CPU 与系统上下文切换开销高于纯内存操作或原生 Socket，且依赖本地 Shell 环境安全性。
    pub fn new(cmd: String, regex: Option<String>, timeout_secs: u64) -> Self {
        let secs = if timeout_secs == 0 { 10 } else { timeout_secs };
        Self {
            cmd,
            regex,
            timeout: Duration::from_secs(secs),
        }
    }

    /// 执行外部命令并获取标准输出文本
    ///
    /// # Errors
    ///
    /// - 命令执行超时返回 [`FetchError::Timeout`]
    /// - 进程启动或 IO 异常返回 [`FetchError::Io`]
    /// - 命令非 0 退出码返回 [`FetchError::Other`]
    async fn execute(&self) -> Result<String, FetchError> {
        let mut command = if cfg!(target_os = "windows") {
            let mut c = Command::new("cmd");
            c.args(["/C", &self.cmd]);
            c
        } else {
            let mut c = Command::new("sh");
            c.args(["-c", &self.cmd]);
            c
        };
        command.kill_on_drop(true);

        let output_fut = command.output();
        let output = timeout(self.timeout, output_fut)
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(FetchError::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() {
            warn!(
                "执行命令 '{}' 退出码异常: {:?}, stderr: {}",
                self.cmd,
                output.status.code(),
                stderr
            );
            return Err(FetchError::Other(format!(
                "命令执行退出码异常 ({:?}): {}",
                output.status.code(),
                stderr.trim()
            )));
        }

        Ok(stdout)
    }
}

#[async_trait]
impl IpFetcher for CommandIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let text = self.execute().await?;
        if let Some(ip) = extract_ipv4(&text, self.regex.as_deref()) {
            Ok(Some(ip))
        } else {
            Err(FetchError::NoValidIp(text))
        }
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        let text = self.execute().await?;
        if let Some(ip) = extract_ipv6(&text, self.regex.as_deref()) {
            Ok(Some(ip))
        } else {
            Err(FetchError::NoValidIp(text))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_command_ip_fetcher_success() {
        let fetcher = CommandIpFetcher::new("echo 1.2.3.4".to_string(), None, 5);
        let ip = fetcher.fetch_ipv4().await.unwrap();
        assert_eq!(ip, Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[tokio::test]
    async fn test_command_ip_fetcher_timeout_and_kill() {
        // 测试命令超时场景
        let cmd = if cfg!(target_os = "windows") {
            "ping -n 5 127.0.0.1 >nul"
        } else {
            "sleep 5"
        };
        let fetcher = CommandIpFetcher::new(cmd.to_string(), None, 1);
        let res = fetcher.fetch_ipv4().await;
        assert!(matches!(res, Err(FetchError::Timeout)));
    }
}

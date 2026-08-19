use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{extract_ipv4, extract_ipv6};
use async_trait::async_trait;
use log::warn;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::process::Command;

/// 基于外部命令/脚本提取 IP
pub struct CommandIpFetcher {
    cmd: String,
    regex: Option<String>,
    timeout: Duration,
}

impl CommandIpFetcher {
    pub fn new(cmd: String, regex: Option<String>, timeout_secs: u64) -> Self {
        let secs = if timeout_secs == 0 { 10 } else { timeout_secs };
        Self {
            cmd,
            regex,
            timeout: Duration::from_secs(secs),
        }
    }

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
        let output = tokio::time::timeout(self.timeout, output_fut)
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

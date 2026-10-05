use crate::ip_fetcher::trait_def::{FetchError, IpFetcher};
use crate::util::net::{extract_ipv4, extract_ipv6, is_global_unicast_ipv6, is_public_ipv4};
use async_trait::async_trait;
use log::warn;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

/// 外部命令标准输出的最大读取字节上限 (64KB，与 URL 探测保持一致防范 OOM 风险)
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 65536;

/// 危险 Shell 注入与逃逸元字符集合 (包含 Unix 与 Windows cmd 敏感元字符及命令组合符)
pub const DANGEROUS_SHELL_CHARS: &[char] = &[
    '|', ';', '&', '`', '$', '>', '<', '\n', '\r', '^', '%', '{', '}', '(', ')',
];

/// 校验外部命令字符串的安全性与非空限制 (S-9)
///
/// # 设计原理
/// - **实现初衷**: 统一 Web 配置保存、应用启动配置加载与调度引擎各处命令的合法性校验，杜绝 Shell 注入。
/// - **核心优势**: 严格拦截命令拼接、转义与变量扩展元字符（包含 Windows ^ 与 %，以及大括号和圆括号），仅允许执行单个独立程序或带常规安全参数的脚本。
///
/// # Errors
/// 若命令为空、包含空字符或危险元字符返回中文错误提示。
pub fn validate_command_str(cmd: &str) -> Result<(), &'static str> {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return Err("命令内容不能为空");
    }
    if trimmed.contains('\0') {
        return Err("命令包含非法的空字符 (NULL Byte)");
    }
    if trimmed.chars().any(|c| DANGEROUS_SHELL_CHARS.contains(&c)) {
        return Err(
            "命令包含高风险 Shell 注入字符 (|;&`$><^%{}())，仅允许执行单个独立脚本或可执行文件及常规参数",
        );
    }
    Ok(())
}

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

    /// 执行外部命令并获取标准输出文本 (P-5: 流式限量 64KB 防爆内存)
    ///
    /// # Errors
    ///
    /// - 命令执行超时返回 [`FetchError::Timeout`]
    /// - 进程启动或 IO 异常（包括超限）返回 [`FetchError::Io`]
    /// - 命令非 0 退出码返回 [`FetchError::Other`]
    async fn execute(&self) -> Result<String, FetchError> {
        if let Err(e) = validate_command_str(&self.cmd) {
            return Err(FetchError::Other(e.to_string()));
        }

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
        // 置空标准输入，避免子进程继承父进程 stdin 导致交互式读取挂起
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        // 丢弃标准错误，避免因无读取方导致操作系统管道缓冲区写满（Windows 仅 4KB）引发子进程死锁与超时
        command.stderr(Stdio::null());

        let mut child = command.spawn().map_err(FetchError::Io)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| FetchError::Other("无法获取子进程标准输出".into()))?;

        let mut buf = Vec::with_capacity(4096);
        let mut chunk = [0u8; 4096];

        let read_fut = async {
            loop {
                let n = stdout.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                if buf.len().saturating_add(n) > MAX_COMMAND_OUTPUT_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("命令输出大小超过 {} 字节安全上限", MAX_COMMAND_OUTPUT_BYTES),
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let status = child.wait().await?;
            Ok((status, buf))
        };

        match timeout(self.timeout, read_fut).await {
            Ok(Ok((status, bytes))) => {
                if !status.success() {
                    warn!("执行命令 '{}' 退出码异常: {:?}", self.cmd, status.code());
                    return Err(FetchError::Other(format!(
                        "命令执行退出码异常 ({:?})",
                        status.code()
                    )));
                }
                Ok(String::from_utf8_lossy(&bytes).to_string())
            }
            Ok(Err(io_err)) => {
                let _ = child.kill().await;
                Err(FetchError::Io(io_err))
            }
            Err(_) => {
                let _ = child.kill().await;
                Err(FetchError::Timeout)
            }
        }
    }
}

#[async_trait]
impl IpFetcher for CommandIpFetcher {
    async fn fetch_ipv4(&self) -> Result<Option<Ipv4Addr>, FetchError> {
        let text = self.execute().await?;
        let Some(ip) = extract_ipv4(&text, self.regex.as_deref()) else {
            return Err(FetchError::NoValidIpv4(text));
        };
        // 与 URL / STUN 探测器保持一致：拒绝私网与 CGNAT 地址，避免提交到公网 DNS
        if is_public_ipv4(&ip) {
            Ok(Some(ip))
        } else {
            warn!("命令返回的 IPv4 非公网单播地址，已拒绝采纳: {}", ip);
            Err(FetchError::NoValidIpv4(format!(
                "命令返回的 IPv4 非公网单播地址: {}",
                ip
            )))
        }
    }

    async fn fetch_ipv6(&self) -> Result<Option<Ipv6Addr>, FetchError> {
        let text = self.execute().await?;
        let Some(ip) = extract_ipv6(&text, self.regex.as_deref()) else {
            return Err(FetchError::NoValidIpv6(text));
        };
        // 与 URL / STUN 探测器保持一致：拒绝链路本地、ULA 私网等非全球单播 IPv6
        if is_global_unicast_ipv6(&ip) {
            Ok(Some(ip))
        } else {
            warn!("命令返回的 IPv6 非全球单播地址，已拒绝采纳: {}", ip);
            Err(FetchError::NoValidIpv6(format!(
                "命令返回的 IPv6 非全球单播地址: {}",
                ip
            )))
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
    async fn test_command_ip_fetcher_ipv6_success() {
        let fetcher = CommandIpFetcher::new("echo 2408:8207:78cd:1234::1".to_string(), None, 5);
        let ip = fetcher.fetch_ipv6().await.unwrap();
        assert_eq!(
            ip,
            Some("2408:8207:78cd:1234::1".parse::<Ipv6Addr>().unwrap())
        );
    }

    #[tokio::test]
    async fn test_command_ip_fetcher_ipv6_rejects_link_local() {
        let fetcher = CommandIpFetcher::new("echo fe80::1".to_string(), None, 5);
        let res = fetcher.fetch_ipv6().await;
        assert!(matches!(res, Err(FetchError::NoValidIpv6(_))));
    }

    #[tokio::test]
    async fn test_command_ip_fetcher_timeout_and_kill() {
        // 测试命令超时场景
        let cmd = if cfg!(target_os = "windows") {
            "ping -n 5 127.0.0.1"
        } else {
            "sleep 5"
        };
        let fetcher = CommandIpFetcher::new(cmd.to_string(), None, 1);
        let res = fetcher.fetch_ipv4().await;
        assert!(matches!(res, Err(FetchError::Timeout)));
    }

    #[tokio::test]
    async fn test_command_ip_fetcher_rejects_dangerous_shell() {
        let fetcher = CommandIpFetcher::new("echo 1.2.3.4 | bash".to_string(), None, 5);
        let res = fetcher.fetch_ipv4().await;
        assert!(matches!(res, Err(FetchError::Other(_))));
    }

    #[test]
    fn test_validate_command_str_blocks_injection_variants() {
        // 正常命令
        assert!(validate_command_str("curl https://api.ipify.org").is_ok());
        assert!(validate_command_str("python3 /opt/scripts/get_ip.py --timeout 5").is_ok());

        // 空命令与 NULL Byte
        assert!(validate_command_str("   ").is_err());
        assert!(validate_command_str("echo 1.1.1.1\0whoami").is_err());

        // 管道与执行串联符
        assert!(validate_command_str("echo 1.1.1.1 | sh").is_err());
        assert!(validate_command_str("echo 1.1.1.1 ; calc").is_err());
        assert!(validate_command_str("echo 1.1.1.1 && calc").is_err());
        assert!(validate_command_str("echo `whoami`").is_err());
        assert!(validate_command_str("echo $(whoami)").is_err());

        // Windows ^ 转义与 % 环境变量注入
        assert!(validate_command_str("echo 1.1.1.1^&calc").is_err());
        assert!(validate_command_str("%COMSPEC% /c calc").is_err());

        // 括号与大括号代码块绕过
        assert!(validate_command_str("{cat,/etc/passwd}").is_err());
        assert!(validate_command_str("(calc)").is_err());
    }
}

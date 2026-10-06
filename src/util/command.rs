//! 外部系统命令安全校验基础设施
//!
//! # 设计原理
//! - **实现初衷**: 统一 Web 配置保存、应用启动配置加载与调度引擎各处命令的合法性校验，杜绝 Shell 注入。
//! - **分层定位**: 本模块沉淀为基础工具层，避免上层 `config` 模块反向依赖 `ip_fetcher`。
//! - **核心优势**: 严格拦截命令拼接、转义、bash 历史扩展与变量扩展元字符，禁止首个可执行文件以 '-' 开头避免参数被误当命令，且拒绝以 '-' 开头且含 '=' 的危险参数选项注入（如 `--config=/etc/passwd`）。
//! - **代价与局限**: 不支持管道 `|` 与复合命令串联，若需多阶段流水线处理，用户应自行封装为独立宿主脚本并在配置中调用该脚本。

/// 外部命令标准输出的最大读取字节上限 (64KB，与 URL 探测保持一致防范 OOM 风险)
pub const MAX_COMMAND_OUTPUT_BYTES: usize = 65536;

/// 危险 Shell 注入与逃逸元字符集合 (包含 Unix 与 Windows cmd 敏感元字符及命令组合符)
pub const DANGEROUS_SHELL_CHARS: &[char] = &[
    '|', ';', '&', '`', '$', '>', '<', '\n', '\r', '^', '%', '{', '}', '(', ')', '!',
];

/// 校验外部命令字符串的安全性与非空限制 (S-9/P-9)
///
/// # 设计原理
/// - **实现初衷**: 统一 Web 配置保存、应用启动配置加载与调度引擎各处命令的合法性校验，杜绝 Shell 注入。
/// - **核心优势**: 严格拦截命令拼接、转义、bash 历史扩展与变量扩展元字符，禁止首个可执行文件以 '-' 开头避免参数被误当命令，且拒绝以 '-' 开头且含 '=' 的危险参数选项注入（如 `--config=/etc/passwd`）。
///
/// # Errors
/// 若命令为空、包含空字符、危险元字符或高危参数格式时返回中文错误提示。
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
            "命令包含高风险 Shell 注入字符 (|;&`$><^%{}()!)，仅允许执行单个独立脚本或可执行文件及常规参数",
        );
    }

    // 检查首个可执行程序 token 与参数形式，防止参数注入攻击 (P-9)
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if let Some(&first_token) = tokens.first()
        && first_token.starts_with('-')
    {
        return Err("命令的可执行程序名称不能以 '-' 开头");
    }
    for &token in &tokens[1..] {
        if token.starts_with('-') && token.contains('=') {
            return Err("命令参数禁止包含以 '-' 开头且带有 '=' 的选项注入格式 (如 --config=xxx)");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Bash 历史扩展元字符 (!) (P-9)
        assert!(validate_command_str("echo !123").is_err());

        // 首个程序 token 不能以 '-' 开头 (P-9)
        assert!(validate_command_str("-c whoami").is_err());
        assert!(validate_command_str("--help").is_err());

        // 参数禁止以 '-' 开头且带 '=' 的注入格式 (P-9)
        assert!(validate_command_str("curl --config=/etc/shadow https://api.ipify.org").is_err());
        assert!(validate_command_str("mytool -o=/tmp/pwn").is_err());
    }
}

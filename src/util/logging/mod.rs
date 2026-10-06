pub mod buffer;
pub mod file;

pub use buffer::{LogBuffer, LogEntry};
pub use file::{SizeRollingWriter, init_file_writer};

use anyhow::{Context, Result};
use fern::Dispatch;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use std::env;
use std::path::{Path, PathBuf};

/// 退出时确保日志刷盘的 RAII 守护对象
///
/// # 设计原理
/// - **实现初衷**：在应用生命周期结束时确定性地触发日志缓冲区刷盘，防止最后时刻的关键排障信息丢失。
/// - **核心优势**：依托 RAII 机制在变量离开作用域时自动调用 `log::logger().flush()`。
#[derive(Debug, Default)]
pub struct LogGuard;

impl Drop for LogGuard {
    fn drop(&mut self) {
        log::logger().flush();
    }
}

/// 全局日志系统句柄
///
/// # 设计原理
/// - **实现初衷**：聚合日志输出通道的关键资源，包括非阻塞后台写入守护句柄与 Web 前端观察缓冲池。
/// - **核心优势**：通过 RAII `LogGuard` 确保应用进程退出时缓冲日志能够确定性完整刷盘。
pub struct LoggingHandle {
    /// 供 Web 服务与 SSE 推送使用的内存环形缓冲区
    pub log_buffer: LogBuffer,
    /// 确保退出时日志正确刷盘的守护句柄
    pub _guard: LogGuard,
    /// 实际生效的日志持久化目录
    pub log_dir: PathBuf,
}

/// 智能解析日志文件的持久化目录
///
/// # 设计原理
/// - **实现初衷**：解决程序作为后台守护进程、Windows NT 服务或 Linux systemd 服务启动时，
///   由于系统调度器将工作目录重定向至受限目录（如 `C:\Windows\System32` 或 `/`）导致日志写入失败或找不到文件的问题。
/// - **核心优势**：优先提取显式指定的配置文件所在目录，其次锚定可执行文件同级目录；当在开发调试或常规终端环境下启动时，
///   智能保留当前工作目录下的 `logs/`，确保跨平台与全场景开箱即用。
/// - **代价与局限**：在极端只读介质环境下，需确保程序同级目录具备写权限。
pub fn resolve_log_dir() -> PathBuf {
    let args: Vec<String> = env::args().collect();
    let cwd = env::current_dir().ok();
    let exe = env::current_exe().ok();
    resolve_log_dir_internal(&args, cwd.as_deref(), exe.as_deref())
}

/// 内部解析日志目录核心逻辑（解耦环境参数便于单元测试覆盖）
fn resolve_log_dir_internal(
    args: &[String],
    cwd: Option<&Path>,
    exe_path: Option<&Path>,
) -> PathBuf {
    // 1. 优先尝试从命令行参数提取配置文件所在目录 (-c / --config)
    if let Some(config_parent) = extract_config_parent_from_args(args) {
        return config_parent.join("logs");
    }

    // 2. 检测当前工作目录是否为系统服务调度默认的根路径或系统目录
    let is_system_cwd = cwd.is_none_or(|p| {
        #[cfg(windows)]
        {
            let path_str = p.to_string_lossy().to_lowercase();
            path_str.ends_with(r"\system32")
                || path_str.ends_with(r"\syswow64")
                || path_str == r"c:\"
        }
        #[cfg(not(windows))]
        {
            p.as_os_str() == "/"
        }
    });

    let is_windows_service_env = args.iter().any(|arg| arg == "--windows-service");
    let exe_dir = exe_path.and_then(|p| p.parent());

    // 3. 若处于系统目录环境或明确为 Windows 服务调度，强制锚定可执行文件同级目录
    if let Some(dir) = exe_dir.filter(|_| is_system_cwd || is_windows_service_env) {
        return dir.join("logs");
    }

    // 4. 若当前工作目录下存在配置文件或已存在 logs 目录，优先使用当前工作目录
    if let Some(c) = cwd.filter(|c| c.join(".rddns.toml").exists() || c.join("logs").exists()) {
        return c.join("logs");
    }

    // 5. 兜底回退：优先可执行文件同级目录，其次工作目录
    if let Some(dir) = exe_dir {
        dir.join("logs")
    } else if let Some(c) = cwd {
        c.join("logs")
    } else {
        PathBuf::from("logs")
    }
}

/// 从参数列表中提取 -c 或 --config 指定的父级目录
fn extract_config_parent_from_args(args: &[String]) -> Option<PathBuf> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-c" || arg == "--config" {
            if let Some(val) = iter.next() {
                let p = Path::new(val);
                if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
                    return Some(parent.to_path_buf());
                }
            }
        } else if let Some(stripped) = arg.strip_prefix("--config=") {
            let p = Path::new(stripped);
            if let Some(parent) = p.parent().filter(|p| !p.as_os_str().is_empty()) {
                return Some(parent.to_path_buf());
            }
        }
    }
    None
}

/// 解析环境变量 RUST_LOG 对应的日志级别过滤器
fn resolve_level_filter() -> LevelFilter {
    env::var("RUST_LOG")
        .ok()
        .and_then(|v| v.parse::<LevelFilter>().ok())
        .unwrap_or(LevelFilter::Info)
}

/// 统一初始化全局日志系统 (控制台彩色输出 + 本地文件按大小轮转 + Web内存环形缓冲)
///
/// # 设计原理
/// - **实现初衷**：提供一体化多管道日志分发，同时兼顾终端开发调试体验、生产排障文件持久化与前端实时观测面板。
/// - **核心优势**：基于纯正 `log` 门面与轻量 `fern` 派发器，杜绝 tracing 桥接元数据污染，显著削减依赖与二进制体积。
///
/// # Errors
/// 当本地日志目录无法创建、日志文件无法打开或全局 Logger 重复初始化失败时返回错误。
pub fn init_logger() -> Result<LoggingHandle> {
    // 1. 初始化内存环形日志缓冲区 (最大 500 条)
    let log_buffer = LogBuffer::new(500);

    // 2. 解析日志级别过滤器 (默认 info，可通过 RUST_LOG 环境变量动态覆盖)
    let level_filter = resolve_level_filter();

    // 3. 控制台日志输出通道 (带 ANSI 终端彩色高亮)
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red)
        .debug(Color::Cyan)
        .trace(Color::BrightBlack);

    let console_dispatch = Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{}] [{}] [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                colors.color(record.level()),
                record.target(),
                message
            ))
        })
        .chain(std::io::stdout());

    // 4. 解析日志存储目录并初始化本地文件日志写入通道 (单文件上限 10MB，最多保留 5 个备份归档)
    let log_dir = resolve_log_dir();
    let file_writer = init_file_writer(&log_dir, "rddns.log", 10 * 1024 * 1024, 5)
        .with_context(|| format!("初始化本地文件日志写入器失败，目录: {}", log_dir.display()))?;
    let file_dispatch = Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}] [{}] [{}] {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .chain(Box::new(file_writer) as Box<dyn std::io::Write + Send>);

    // 5. Web 内存环形缓冲通道 (供前端 API 观测与 SSE 实时广播)
    let log_buffer_for_chain = log_buffer.clone();
    let buffer_dispatch = Dispatch::new().chain(fern::Output::call(move |record| {
        log_buffer_for_chain.push(record.level(), record.target(), record.args().to_string());
    }));

    // 6. 组合多目标派发器并注册到全局 log 门面
    Dispatch::new()
        .level(level_filter)
        .chain(console_dispatch)
        .chain(file_dispatch)
        .chain(buffer_dispatch)
        .apply()
        .context("注册全局日志分发器失败")?;

    Ok(LoggingHandle {
        log_buffer,
        _guard: LogGuard,
        log_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_log_dir_from_config_args() {
        // 测试从 -c 提取绝对路径父目录
        let args = vec![
            "rddns".to_string(),
            "-c".to_string(),
            if cfg!(windows) {
                r"C:\Program Files\rddns\.rddns.toml".to_string()
            } else {
                "/etc/rddns/config.toml".to_string()
            },
        ];
        let res = resolve_log_dir_internal(&args, None, None);
        if cfg!(windows) {
            assert_eq!(res, PathBuf::from(r"C:\Program Files\rddns\logs"));
        } else {
            assert_eq!(res, PathBuf::from("/etc/rddns/logs"));
        }

        // 测试从 --config= 提取父目录
        let args2 = vec![
            "rddns".to_string(),
            if cfg!(windows) {
                r"--config=D:\rddns\conf.toml".to_string()
            } else {
                "--config=/opt/rddns/conf.toml".to_string()
            },
        ];
        let res2 = resolve_log_dir_internal(&args2, None, None);
        if cfg!(windows) {
            assert_eq!(res2, PathBuf::from(r"D:\rddns\logs"));
        } else {
            assert_eq!(res2, PathBuf::from("/opt/rddns/logs"));
        }
    }

    #[test]
    fn test_resolve_log_dir_system_cwd_fallback() {
        // 模拟 Windows Service 场景：cwd 为 System32，但 exe 为 D:\rddns\rddns.exe
        let args = vec!["rddns".to_string(), "--windows-service".to_string()];
        let cwd = if cfg!(windows) {
            Path::new(r"C:\Windows\System32")
        } else {
            Path::new("/")
        };
        let exe = if cfg!(windows) {
            Path::new(r"D:\rddns\rddns.exe")
        } else {
            Path::new("/usr/local/bin/rddns")
        };

        let res = resolve_log_dir_internal(&args, Some(cwd), Some(exe));
        if cfg!(windows) {
            assert_eq!(res, PathBuf::from(r"D:\rddns\logs"));
        } else {
            assert_eq!(res, PathBuf::from("/usr/local/bin/logs"));
        }
    }
}

pub mod buffer;
pub mod file;

pub use buffer::{LogBuffer, LogEntry};
pub use file::{SizeRollingWriter, init_file_writer};

use anyhow::{Context, Result};
use fern::Dispatch;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use std::env;

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

    // 4. 本地文件日志写入通道 (单文件上限 10MB，最多保留 5 个备份归档)
    let file_writer = init_file_writer("logs", "rddns.log", 10 * 1024 * 1024, 5)
        .context("初始化本地文件日志写入器失败")?;
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
    })
}

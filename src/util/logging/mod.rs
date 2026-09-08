pub mod buffer;
pub mod file;

pub use buffer::{BufferLogLayer, LogBuffer, LogEntry};
pub use file::init_file_appender;

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt, registry};

/// 全局日志系统句柄
///
/// # 设计原理
/// - **实现初衷**：聚合日志输出通道的关键资源，包括非阻塞后台写入守护句柄与 Web 前端观察缓冲池。
/// - **核心优势**：通过 RAII `WorkerGuard` 确保应用进程退出时缓冲日志能够确定性完整刷盘。
pub struct LoggingHandle {
    /// 供 Web 服务与 SSE 推送使用的内存环形缓冲区
    pub log_buffer: LogBuffer,
    /// 确保退出时非阻塞文件日志正确刷盘的守护句柄
    pub _guard: WorkerGuard,
}

/// 统一初始化全局日志系统 (控制台彩色输出 + 本地文件按大小轮转 + Web内存环形缓冲)
///
/// # 设计原理
/// - **实现初衷**：提供一体化的日志记录流水线，同时兼顾终端开发调试体验、生产排障文件持久化与前端实时观测面板。
/// - **核心优势**：基于 `tracing` 高性能门面，文件日志使用独立后台工作线程非阻塞异步刷盘，杜绝文件 IO 拖慢主业务。
///
/// # Errors
/// 当本地日志目录无法创建或日志文件无法打开时返回错误。
pub fn init_logger() -> Result<LoggingHandle> {
    // 1. 初始化内存环形日志缓冲区 (最大 50 条)
    let log_buffer = LogBuffer::new(50);
    let buffer_layer = BufferLogLayer::new(log_buffer.clone());

    // 2. 日志级别过滤器 (默认 info，可通过 RUST_LOG 环境变量动态覆盖)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // 3. 本地文件日志写入器 (单文件上限 10MB，最多保留 5 个备份归档)
    let (file_writer, guard) = init_file_appender("logs", "rddns.log", 10 * 1024 * 1024, 5)
        .context("初始化本地文件日志 Appender 失败")?;
    let file_layer = fmt::layer().with_ansi(false).with_writer(file_writer);

    // 4. 控制台日志输出 (启用 ANSI 彩色)
    let console_layer = fmt::layer().with_ansi(true);

    // 5. 组合注册全局 Tracing 订阅者 (try_init 会自动初始化 log 门面桥接，并安全防止重复初始化时 panic)
    let _ = registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .with(buffer_layer)
        .try_init();

    Ok(LoggingHandle {
        log_buffer,
        _guard: guard,
    })
}

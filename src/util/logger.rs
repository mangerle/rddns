use crate::util::log_buffer::{BufferLogLayer, LogBuffer};
use crate::util::log_file::init_file_appender;
use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// 全局日志系统句柄
pub struct LoggingHandle {
    /// 供 Web 服务与 SSE 推送使用的内存环形缓冲区
    pub log_buffer: LogBuffer,
    /// 确保退出时非阻塞文件日志正确刷盘的守护句柄
    pub _guard: WorkerGuard,
}

/// 统一初始化全局日志系统 (控制台彩色输出 + 本地文件按大小轮转 + Web内存环形缓冲)
pub fn init_logger() -> Result<LoggingHandle> {
    // 0. 桥接标准 log crate 日志门面到 Tracing 体系
    let _ = tracing_log::LogTracer::init();

    // 1. 初始化内存环形日志缓冲区 (最大 300 条)
    let log_buffer = LogBuffer::new(50);
    let buffer_layer = BufferLogLayer::new(log_buffer.clone());

    // 2. 日志级别过滤器 (默认 info，可通过 RUST_LOG 环境变量动态覆盖)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // 3. 本地文件日志写入器 (单文件上限 10MB，最多保留 5 个备份归档)
    let (file_writer, guard) = init_file_appender("logs", "rddns.log", 10 * 1024 * 1024, 5)
        .context("初始化本地文件日志 Appender 失败")?;
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(file_writer);

    // 4. 控制台日志输出 (启用 ANSI 彩色)
    let console_layer = tracing_subscriber::fmt::layer().with_ansi(true);

    // 5. 组合注册全局 Tracing 订阅者
    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .with(buffer_layer)
        .init();

    Ok(LoggingHandle {
        log_buffer,
        _guard: guard,
    })
}

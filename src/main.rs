mod config;
mod core;
mod dns;
mod ip_fetcher;
mod notifier;
mod util;
mod web;

use clap::Parser;
use config::model::UserAuthConfig;
use config::storage::ConfigManager;
use core::engine::DdnsEngine;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use util::log_buffer::{BufferLogLayer, LogBuffer};
use web::server::WebServer;

#[derive(Parser, Debug)]
#[command(name = "rddns", author, version, about = "基于 Rust 的高性能动态域名解析 (DDNS) 服务端工具", long_about = None)]
struct CliArgs {
    /// 自定义配置文件路径
    #[arg(short = 'c', long = "config", default_value = ".rddns_config.yaml")]
    config: PathBuf,

    /// 覆盖 Web 服务监听地址 (例如 127.0.0.1:9876)
    #[arg(short = 'l', long = "listen")]
    listen: Option<String>,

    /// 覆盖同步间隔时间 (秒)
    #[arg(short = 'f', long = "frequency")]
    frequency: Option<u64>,

    /// 不启动 Web 管理界面 (纯后台守护模式)
    #[arg(long = "noweb", default_value_t = false)]
    no_web: bool,

    /// 重置 Web 管理员密码并退出
    #[arg(long = "reset-password")]
    reset_password: Option<String>,

    /// 在后台静默运行 (守护进程模式)
    #[arg(short = 'd', long = "daemon", default_value_t = false)]
    daemon: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    // 如果指定了 -d 且当前不是派生的后台子进程，则启动独立守护进程并退出当前父终端
    if args.daemon && !util::daemon::is_daemon_child() {
        util::daemon::run_as_daemon()?;
        return Ok(());
    }

    // 1. 初始化内存环形日志缓冲区与 Tracing 订阅者
    let log_buffer = LogBuffer::new(300);
    let buffer_layer = BufferLogLayer::new(log_buffer.clone());
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_ansi(true))
        .with(buffer_layer)
        .init();

    tracing::info!("==========================================");
    tracing::info!(
        "🚀 rddns 动态域名解析系统 v{} 正在启动",
        env!("CARGO_PKG_VERSION")
    );
    tracing::info!("==========================================");

    // 2. 解析配置文件路径（若为相对路径，自动锚定至可执行文件所在目录，防止作为系统服务启动时工作目录漂移）
    let config_path = if args.config.is_relative() {
        if let Ok(exe_path) = std::env::current_exe() {
            exe_path
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .join(&args.config)
        } else {
            args.config
        }
    } else {
        args.config
    };

    let config_manager = Arc::new(ConfigManager::load_or_create(config_path)?);

    // 处理重置密码指令
    if let Some(new_pwd) = args.reset_password {
        let mut conf = (*config_manager.get_config()).clone();
        let hash = bcrypt::hash(&new_pwd, bcrypt::DEFAULT_COST)?;
        let username = conf
            .auth
            .as_ref()
            .map(|a| a.username.clone())
            .unwrap_or_else(|| "admin".to_string());
        conf.auth = Some(UserAuthConfig {
            username: username.clone(),
            password_hash: hash,
        });
        config_manager.update_config(conf)?;
        println!("✅ 用户 [{}] 的密码已成功重置！", username);
        return Ok(());
    }

    // 处理命令行参数覆盖
    if args.frequency.is_some() {
        let mut conf = (*config_manager.get_config()).clone();
        if let Some(f) = args.frequency {
            conf.interval_secs = f;
        }
        config_manager.update_config(conf)?;
    }

    let cancel_token = CancellationToken::new();

    // 3. 开机自启网络就绪探测（最大等待 120 秒，每 3 秒重试一次，规避开机未拨号完成时的大量网络异常）
    util::wait_internet::wait_for_internet(120, 3).await;

    // 4. 初始化 DDNS 调度引擎
    let (engine, trigger_tx) = DdnsEngine::new(config_manager.clone());
    let engine_token = cancel_token.clone();
    let engine_handle = tokio::spawn(async move {
        engine.run_loop(engine_token).await;
    });

    // 4. 初始化 Web 管理服务器
    let web_handle = if !args.no_web {
        let web_server =
            WebServer::new(config_manager.clone(), trigger_tx, log_buffer, args.listen);
        let web_token = cancel_token.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = web_server.run(web_token).await {
                tracing::error!("Web 服务发生异常: {}", e);
            }
        }))
    } else {
        tracing::info!("已开启 --noweb 模式，跳过 Web 服务启动");
        None
    };

    // 5. 监听系统中断信号 (Ctrl+C)
    let cancel_token_clone = cancel_token.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("收到中断信号 (Ctrl+C)，开始优雅退出流程...");
                cancel_token_clone.cancel();
            }
            Err(err) => {
                tracing::error!("监听 Ctrl+C 信号异常: {}", err);
            }
        }
    });

    // 等待引擎与 Web 服务退出
    let _ = engine_handle.await;
    if let Some(wh) = web_handle {
        let _ = wh.await;
    }

    tracing::info!("👋 rddns 已完全停止运行");
    Ok(())
}

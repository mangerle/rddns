mod config;
mod core;
mod dns;
mod ip_fetcher;
mod notifier;
mod util;
mod web;

use crate::config::model::UserAuthConfig;
use crate::config::storage::ConfigManager;
use crate::core::engine::DdnsEngine;
use crate::util::daemon::{is_daemon_child, run_as_daemon};
use crate::util::dns_resolver::set_custom_dns_server;
use crate::util::http::set_skip_verify;
use crate::util::logging::init_logger;
use crate::util::service::handle_service_command;
use crate::util::update::upgrade_self;
use crate::web::server::WebServer;
use anyhow::{Context, Result};
use bcrypt::{DEFAULT_COST, hash};
use clap::Parser;
use log::{error, info};
use std::env::{current_dir, current_exe};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use tokio::signal::ctrl_c;
use tokio::spawn;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(name = "rddns", author, version, about = "基于 Rust 的高性能动态域名解析 (DDNS) 服务端工具", long_about = None)]
struct CliArgs {
    /// 自定义配置文件路径
    #[arg(short = 'c', long = "config", default_value = ".rddns_config.yaml")]
    config: PathBuf,

    /// 覆盖 Web 服务监听地址或端口 (支持 -l / -p / --listen / --port，例如 127.0.0.1:9876 或 :9876 或 9876)
    #[arg(short = 'l', short_alias = 'p', long = "listen", alias = "port")]
    listen: Option<String>,

    /// 覆盖同步间隔时间 (秒)
    #[arg(short = 'f', long = "frequency")]
    frequency: Option<u64>,

    /// 不启动 Web 管理界面 (纯后台守护模式)
    #[arg(long = "noweb", default_value_t = false)]
    no_web: bool,

    /// 自定义公共 DNS 递归解析服务器 (例如 223.5.5.5 或 1.1.1.1:53，用于抗 Local DNS 污染)
    #[arg(long = "dns")]
    dns: Option<String>,

    /// 跳过 HTTPS / TLS 证书有效性验证 (支持 --skip-verify / --skipVerify)
    #[arg(long = "skip-verify", alias = "skipVerify", default_value_t = false)]
    skip_verify: bool,

    /// 重置 Web 管理员密码并退出 (支持 --reset-password / --resetPassword)
    #[arg(long = "reset-password", alias = "resetPassword")]
    reset_password: Option<String>,

    /// 在后台静默运行 (守护进程模式)
    #[arg(short = 'd', long = "daemon", default_value_t = false)]
    daemon: bool,

    /// 系统自启服务管理 (install | uninstall | start | stop | restart | status)
    #[arg(short = 's', long = "service")]
    service: Option<String>,

    /// 检查并自动升级至最新版本
    #[arg(short = 'u', long = "upgrade", default_value_t = false)]
    upgrade: bool,
}

/// 智能判定与解析配置文件实际物理路径
fn resolve_config_path(cli_path: &Path) -> PathBuf {
    if !cli_path.is_relative() {
        return cli_path.to_path_buf();
    }

    let cwd_path = current_dir()
        .map(|d| d.join(cli_path))
        .unwrap_or_else(|_| cli_path.to_path_buf());
    let exe_dir_path = current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(cli_path)));

    if cwd_path.exists() {
        cwd_path
    } else if let Some(exe_cfg) = exe_dir_path {
        if exe_cfg.exists() { exe_cfg } else { cwd_path }
    } else {
        cwd_path
    }
}

/// 执行管理员密码重置并保存至配置文件
fn handle_reset_password(config_manager: &ConfigManager, new_pwd: &str) -> Result<()> {
    let trimmed = new_pwd.trim();
    if trimmed.is_empty() {
        error!("重置密码失败：新密码不能为空");
        exit(1);
    }
    let mut conf = (*config_manager.get_config()).clone();
    let hash_val = hash(trimmed, DEFAULT_COST).context("生成密码哈希失败")?;
    let username = conf
        .auth
        .as_ref()
        .map(|a| a.username.clone())
        .unwrap_or_else(|| "admin".to_string());
    conf.auth = Some(UserAuthConfig {
        username: username.clone(),
        password_hash: hash_val,
    });
    config_manager
        .update_config(conf)
        .context("保存新密码至配置文件失败")?;

    info!("==========================================");
    info!("管理员密码重置成功");
    info!("管理员账号: {}", username);
    info!("新登录密码: {}", trimmed);
    info!("配置文件:   {}", config_manager.get_config_path().display());
    info!("==========================================");
    Ok(())
}

/// 启动后台系统退出信号监听器 (支持 Ctrl+C 与 Unix SIGTERM)
fn spawn_signal_listener(cancel_token: CancellationToken) {
    spawn(async move {
        #[cfg(unix)]
        {
            use tokio::select;
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("注册 SIGTERM 信号监听失败: {}", e);
                    None
                }
            };

            select! {
                res = ctrl_c() => {
                    if let Err(e) = res {
                        error!("监听 Ctrl+C (SIGINT) 异常: {}", e);
                    } else {
                        info!("收到中断信号 (SIGINT/Ctrl+C)，开始优雅退出流程...");
                    }
                }
                _ = async {
                    if let Some(ref mut st) = sigterm {
                        st.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    info!("收到终止信号 (SIGTERM)，开始优雅退出流程...");
                }
            }
        }

        #[cfg(not(unix))]
        {
            if let Err(err) = ctrl_c().await {
                error!("监听 Ctrl+C 信号异常: {}", err);
            } else {
                info!("收到中断信号 (Ctrl+C)，开始优雅退出流程...");
            }
        }

        cancel_token.cancel();
    });
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // 1. 初始化全局日志系统
    let logging_handle = init_logger().context("初始化全局日志系统失败")?;
    let log_buffer = logging_handle.log_buffer;
    let _log_guard = logging_handle._guard;

    let args = CliArgs::parse();

    info!("==========================================");
    info!(
        "rddns 动态域名解析系统 v{} 正在启动",
        env!("CARGO_PKG_VERSION")
    );

    if args.skip_verify {
        set_skip_verify(true);
    }

    if args.upgrade {
        if let Err(e) = upgrade_self().await {
            error!("自动升级失败: {:#}", e);
            exit(1);
        }
        return Ok(());
    }

    if args.daemon && !is_daemon_child() {
        run_as_daemon().context("启动守护进程失败")?;
        return Ok(());
    }

    let config_path = resolve_config_path(&args.config);
    if let Some(ref action) = args.service {
        handle_service_command(action, &config_path).context("执行系统服务管理指令失败")?;
        return Ok(());
    }

    let config_manager =
        Arc::new(ConfigManager::load_or_create(config_path).context("加载或初始化配置文件失败")?);

    if let Some(ref dns_srv) = args.dns {
        set_custom_dns_server(dns_srv.clone());
    } else if let Some(dns_srv) = config_manager
        .get_config()
        .dns_server
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        set_custom_dns_server(dns_srv.trim().to_string());
    }

    if let Some(ref new_pwd) = args.reset_password {
        return handle_reset_password(&config_manager, new_pwd);
    }

    if let Some(f) = args.frequency {
        let mut conf = (*config_manager.get_config()).clone();
        conf.interval_secs = f;
        config_manager.update_runtime_config(conf);
    }

    let cancel_token = CancellationToken::new();

    // 2. 初始化 DDNS 调度引擎
    let (engine, trigger_tx) = DdnsEngine::new(config_manager.clone());
    let engine_token = cancel_token.clone();
    let engine_handle = spawn(async move {
        engine.run_loop(engine_token).await;
    });

    // 3. 初始化 Web 管理服务器
    let web_handle = if !args.no_web {
        let web_server =
            WebServer::new(config_manager.clone(), trigger_tx, log_buffer, args.listen);
        let web_token = cancel_token.clone();
        Some(spawn(async move {
            if let Err(e) = web_server.run(web_token).await {
                error!("Web 服务发生异常: {}", e);
            }
        }))
    } else {
        info!("已开启 --noweb 模式，跳过 Web 服务启动");
        None
    };

    // 4. 监听系统退出信号
    spawn_signal_listener(cancel_token.clone());

    let _ = engine_handle.await;
    if let Some(wh) = web_handle {
        let _ = wh.await;
    }

    info!("rddns 已完全停止运行");
    Ok(())
}

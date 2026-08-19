mod config;
mod core;
mod dns;
mod ip_fetcher;
mod notifier;
mod util;
mod web;

use crate::util::logger::init_logger;
use anyhow::{Context, Result};
use clap::Parser;
use config::model::UserAuthConfig;
use config::storage::ConfigManager;
use core::engine::DdnsEngine;
use log::{error, info};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use web::server::WebServer;

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // 1. 在程序最开头初始化全局日志体系 (控制台彩色输出 + 本地文件按大小轮转 + Web内存环形缓冲)
    let logging_handle = init_logger().context("初始化全局日志系统失败")?;
    let log_buffer = logging_handle.log_buffer;
    let _log_guard = logging_handle._guard;

    let args = CliArgs::parse();

    info!("==========================================");
    info!(
        "rddns 动态域名解析系统 v{} 正在启动",
        env!("CARGO_PKG_VERSION")
    );

    // 如果配置了自定义 DNS 解析服务器
    if let Some(ref dns_srv) = args.dns {
        util::dns_resolver::set_custom_dns_server(dns_srv.clone());
    }

    // 如果开启了跳过证书验证，配置全局 HTTP 策略
    if args.skip_verify {
        util::http::set_skip_verify(true);
    }

    // 如果指定了 -u 则执行自动升级并退出
    if args.upgrade {
        if let Err(e) = util::update::upgrade_self().await {
            error!("自动升级失败: {:#}", e);
            eprintln!("自动升级失败: {:#}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // 如果指定了 -d 且当前不是派生的后台子进程，则启动独立守护进程并退出当前父终端
    if args.daemon && !util::daemon::is_daemon_child() {
        util::daemon::run_as_daemon().context("启动守护进程失败")?;
        return Ok(());
    }

    // 解析配置文件路径：
    // 若为相对路径，按如下优先级智能判定：
    // - 优先级 1：当前工作目录 (CWD) 下若已存在该文件，优先读取当前目录；
    // - 优先级 2：可执行文件所在目录下若存在该文件，优先读取程序同级目录；
    // - 优先级 3：若均不存在（首次运行），默认在当前工作目录下创建。
    let config_path = if args.config.is_relative() {
        let cwd_path = std::env::current_dir()
            .map(|d| d.join(&args.config))
            .unwrap_or_else(|_| args.config.clone());
        let exe_dir_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(&args.config)));

        if cwd_path.exists() {
            cwd_path
        } else if let Some(ref exe_cfg) = exe_dir_path {
            if exe_cfg.exists() {
                exe_cfg.clone()
            } else {
                cwd_path
            }
        } else {
            cwd_path
        }
    } else {
        args.config
    };

    // 处理系统服务管理指令 (-s install/uninstall/restart/status...)
    if let Some(ref action) = args.service {
        util::service::handle_service_command(action, &config_path)
            .context("执行系统服务管理指令失败")?;
        return Ok(());
    }

    let config_manager =
        Arc::new(ConfigManager::load_or_create(config_path).context("加载或初始化配置文件失败")?);

    // 初始化/覆盖自定义 DNS 解析服务器（优先级：CLI 参数 > 配置文件）
    if let Some(ref dns_srv) = args.dns {
        util::dns_resolver::set_custom_dns_server(dns_srv.clone());
    } else if let Some(dns_srv) = config_manager
        .get_config()
        .dns_server
        .as_ref()
        .filter(|s| !s.trim().is_empty())
    {
        util::dns_resolver::set_custom_dns_server(dns_srv.trim().to_string());
    }

    // 处理重置密码指令 (--reset-password / --resetPassword)
    if let Some(new_pwd) = args.reset_password {
        if new_pwd.trim().is_empty() {
            error!("重置密码失败：新密码不能为空！");
            std::process::exit(1);
        }
        let mut conf = (*config_manager.get_config()).clone();
        let hash = bcrypt::hash(&new_pwd, bcrypt::DEFAULT_COST).context("生成密码哈希失败")?;
        let username = conf
            .auth
            .as_ref()
            .map(|a| a.username.clone())
            .unwrap_or_else(|| "admin".to_string());
        conf.auth = Some(UserAuthConfig {
            username: username.clone(),
            password_hash: hash,
        });
        config_manager
            .update_config(conf)
            .context("保存新密码至配置文件失败")?;
        println!("==========================================");
        println!("管理员密码重置成功！");
        println!("管理员账号: {}", username);
        println!("新登录密码: {}", new_pwd);
        println!("配置文件:   {}", config_manager.get_config_path().display());
        println!("==========================================");
        return Ok(());
    }

    // 处理命令行参数覆盖 (仅在当前运行时生效，不写入磁盘配置文件)
    if let Some(f) = args.frequency {
        let mut conf = (*config_manager.get_config()).clone();
        conf.interval_secs = f;
        config_manager.update_runtime_config(conf);
    }

    let cancel_token = CancellationToken::new();

    // 3. 初始化 DDNS 调度引擎 (网络探测将在引擎后台异步执行，避免阻塞 Web 界面启动)
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
                error!("Web 服务发生异常: {}", e);
            }
        }))
    } else {
        info!("已开启 --noweb 模式，跳过 Web 服务启动");
        None
    };

    // 5. 监听系统退出信号 (支持 Ctrl+C / SIGINT 与 Linux systemd SIGTERM 优雅退出)
    let cancel_token_clone = cancel_token.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!("注册 SIGTERM 信号监听失败: {}", e);
                    None
                }
            };

            tokio::select! {
                res = tokio::signal::ctrl_c() => {
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
            if let Err(err) = tokio::signal::ctrl_c().await {
                error!("监听 Ctrl+C 信号异常: {}", err);
            } else {
                info!("收到中断信号 (Ctrl+C)，开始优雅退出流程...");
            }
        }

        cancel_token_clone.cancel();
    });

    // 等待引擎与 Web 服务退出
    let _ = engine_handle.await;
    if let Some(wh) = web_handle {
        let _ = wh.await;
    }

    info!("rddns 已完全停止运行");
    Ok(())
}

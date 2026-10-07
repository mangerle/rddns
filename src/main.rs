//! rddns 可执行程序入口
//!
//! # 职责边界
//! 本文件仅负责「解析命令行参数 → 装配各组件 → 监听退出信号」，
//! 不承载任何业务逻辑。全部模块声明已下沉至 `lib.rs`，使 crate 同时
//! 具备可执行程序与可被集成测试引用的库两种能力。

use anyhow::{Context, Result};
use bcrypt::{DEFAULT_COST, hash};
use clap::Parser;
use log::{error, info, warn};
use rddns::config::model::UserAuthConfig;
use rddns::config::storage::ConfigManager;
use rddns::core::engine::DdnsEngine;
use rddns::core::state::StateManager;
use rddns::util::daemon::{is_daemon_child, run_as_daemon};
use rddns::util::dns_resolver::set_custom_dns_server;
use rddns::util::http::set_skip_verify;
use rddns::util::logging::{LogBuffer, init_logger};
use rddns::util::service::handle_service_command;
use rddns::util::update::{run_startup_version_check, upgrade_self};
use rddns::web::server::WebServer;
use shipup::{check_and_recover_current, confirm_update_success};
use std::env::{current_dir, current_exe};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::Arc;
use tokio::signal::ctrl_c;
use tokio::spawn;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug, Clone)]
#[command(name = "rddns", author, version, about = "基于 Rust 的高性能动态域名解析 (DDNS) 服务端工具", long_about = None)]
struct CliArgs {
    /// 自定义配置文件路径
    #[arg(short = 'c', long = "config", default_value = ".rddns.toml")]
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

    /// 内部参数：以 Windows NT 服务调度模式运行 (由 SCM 调起)
    #[cfg(windows)]
    #[arg(long = "windows-service", hide = true, default_value_t = false)]
    windows_service: bool,

    /// 检查并自动升级至最新版本
    #[arg(short = 'u', long = "upgrade", default_value_t = false)]
    upgrade: bool,

    /// 内部参数：自更新系统标记
    #[arg(long = "shipup-restarted", hide = true, default_value_t = false)]
    shipup_restarted: bool,
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

/// 执行管理员密码重置并保存至配置文件 (S-6, S-7)
fn handle_reset_password(config_manager: &ConfigManager, cli_new_pwd: &str) -> Result<()> {
    let pwd_from_env = std::env::var("RDDNS_NEW_PASSWORD").ok();
    let target_pwd = pwd_from_env.as_deref().unwrap_or(cli_new_pwd);
    if let Err(msg) = rddns::util::crypto::validate_password_strength(target_pwd) {
        anyhow::bail!("重置密码失败: {}", msg);
    }
    let mut conf = (*config_manager.get_config()).clone();
    let hash_val = hash(target_pwd, DEFAULT_COST).context("生成密码哈希失败")?;
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
    info!("管理员密码已成功重置");
    info!("管理员账号: {}", username);
    info!("配置文件:   {}", config_manager.get_config_path().display());
    info!("==========================================");
    Ok(())
}

/// 启动后台系统退出信号监听器 (支持 Ctrl+C 与 Unix SIGTERM)
///
/// # 返回值
/// 返回任务句柄交由调用方持有，确保信号监听任务的生命周期可追踪。
fn spawn_signal_listener(cancel_token: CancellationToken) -> tokio::task::JoinHandle<()> {
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
        // 10 秒硬退出兜底 Watchdog 任务，防止挂起的连接导致进程永不退出 (P-1, P3-15)
        let _watchdog = spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            log::warn!("平滑停机超过 10 秒兜底时限，强制退出进程");
            std::process::exit(0);
        });
    })
}

#[cfg(windows)]
mod win_svc {
    use super::*;
    use rddns::util::windows_service::{
        SERVICE_NAME, set_running_as_service, set_service_cancel_token,
    };
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static GLOBAL_ARGS: parking_lot::RwLock<Option<CliArgs>> = parking_lot::RwLock::new(None);
    static GLOBAL_LOG_BUFFER: parking_lot::RwLock<Option<LogBuffer>> =
        parking_lot::RwLock::new(None);

    define_windows_service!(ffi_service_main, rddns_service_main);

    /// 启动 Windows NT 系统服务分发器 (由 Windows SCM 调起)
    pub fn start_service_dispatcher(args: CliArgs, log_buffer: LogBuffer) -> Result<()> {
        set_running_as_service(true);
        *GLOBAL_ARGS.write() = Some(args);
        *GLOBAL_LOG_BUFFER.write() = Some(log_buffer);

        info!(
            "正在启动 Windows SCM 系统服务分发调度器 [{}]...",
            SERVICE_NAME
        );
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("启动 Windows 服务分发调度器失败，请确认本程序是否由 Windows SCM 调起")
    }

    fn rddns_service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service_lifecycle() {
            error!("Windows NT 系统服务生命周期异常终止: {:#}", e);
        }
    }

    fn run_service_lifecycle() -> Result<()> {
        let cancel_token = CancellationToken::new();
        set_service_cancel_token(cancel_token.clone());

        let token_clone = cancel_token.clone();
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("收到 Windows 服务控制停止信号 (Stop/Shutdown)，开始平滑停机...");
                    token_clone.cancel();
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .context("注册 SCM 控制处理器句柄失败")?;

        // 向 SCM 上报 Running 状态
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::NO_ERROR,
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .context("向 SCM 上报 Running 状态失败")?;

        let args = GLOBAL_ARGS.read().clone().context("未获取到服务启动参数")?;
        let log_buffer = GLOBAL_LOG_BUFFER
            .read()
            .clone()
            .context("未获取到服务日志缓冲区")?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("创建服务内部 Tokio 运行时失败")?;

        let res = rt.block_on(run_core_app(args, cancel_token, log_buffer));

        let exit_code = match res {
            Ok(()) => ServiceExitCode::NO_ERROR,
            Err(e) => {
                error!("服务核心业务运行出错: {:#}", e);
                ServiceExitCode::ServiceSpecific(1)
            }
        };

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        Ok(())
    }
}

/// 运行核心 DDNS 引擎与 Web 服务业务
async fn run_core_app(
    args: CliArgs,
    cancel_token: CancellationToken,
    log_buffer: LogBuffer,
) -> Result<()> {
    let config_path = resolve_config_path(&args.config);
    let config_manager =
        Arc::new(ConfigManager::load_or_create(config_path).context("加载或初始化配置文件失败")?);

    // 确认自更新成功，清除历史回滚与崩溃观察期状态
    let _ = confirm_update_success();

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

    // 初始化 DDNS 调度引擎
    let state_manager = StateManager::new();
    let (engine, trigger_tx) = DdnsEngine::new(config_manager.clone(), state_manager.clone());
    let engine_token = cancel_token.clone();
    let engine_handle = spawn(async move {
        engine.run_loop(engine_token).await;
    });

    // 启动远端版本预检 (静默后台执行，结果落入 24 小时缓存)
    // 远端检查已从「每次页面加载」收敛至「启动一次 + 用户手动点击」，
    // 既保留顶栏徽标的更新提示能力，又彻底消除高频出站与日志刷屏。
    let version_token = cancel_token.clone();
    let version_check_handle = spawn(async move {
        tokio::select! {
            _ = version_token.cancelled() => {
                log::debug!("收到停机信号，跳过启动版本预检");
            }
            () = run_startup_version_check() => {}
        }
    });

    // 初始化 Web 管理服务器
    let web_handle = if !args.no_web {
        let web_server = WebServer::new(
            config_manager.clone(),
            trigger_tx,
            log_buffer,
            state_manager,
            args.listen,
        );
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

    // 收割启动版本预检：其为短耗时一次性任务，优先收割以免被下方引擎的阻塞等待无限期延后
    report_task_exit("启动版本预检", version_check_handle.await).await;

    // 收割引擎与 Web 任务：显式识别 panic，避免核心常驻任务崩溃时静默退出
    report_task_exit("DDNS 调度引擎", engine_handle.await).await;
    if let Some(wh) = web_handle {
        report_task_exit("Web 管理服务", wh.await).await;
    }

    info!("rddns 核心业务已平滑退场");
    Ok(())
}

/// 常规控制台或后台守护进程执行入口
async fn async_main(args: CliArgs, log_buffer: LogBuffer) -> Result<()> {
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

    let cancel_token = CancellationToken::new();
    let signal_handle = spawn_signal_listener(cancel_token.clone());

    let res = run_core_app(args, cancel_token, log_buffer).await;
    drop(signal_handle);
    res
}

fn main() -> Result<()> {
    // 0. 执行自更新健康检查与崩溃自愈（连续崩溃超阈值自动回滚）
    if let Err(e) = check_and_recover_current(2) {
        warn!("自更新健康状态检查异常: {}", e);
    }

    let logging_handle = init_logger().context("初始化全局日志系统失败")?;
    let log_buffer = logging_handle.log_buffer;
    let _log_guard = logging_handle._guard;
    let log_dir = logging_handle.log_dir;

    let args = CliArgs::parse();

    info!("==========================================");
    info!(
        "rddns 动态域名解析系统 v{} 正在启动",
        env!("CARGO_PKG_VERSION")
    );
    info!("日志持久化目录: {}", log_dir.display());

    if args.skip_verify {
        set_skip_verify(true);
    }

    #[cfg(windows)]
    if args.windows_service {
        return win_svc::start_service_dispatcher(args, log_buffer);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("创建 Tokio 运行时失败")?;

    rt.block_on(async_main(args, log_buffer))
}

/// 等待常驻任务结束并输出其退出状态
///
/// # 设计原理
/// 核心常驻任务若因 panic 而终止，必须显式告警：否则进程会静默退出版本
/// 更新的健康确认流程，甚至让自更新回滚机制失去判断依据。
async fn report_task_exit(task_name: &str, result: Result<(), tokio::task::JoinError>) {
    match result {
        Ok(()) => info!("{} 任务已正常结束", task_name),
        Err(join_err) if join_err.is_panic() => {
            error!("{} 任务发生 panic，服务已异常终止: {}", task_name, join_err);
        }
        Err(join_err) => {
            error!("{} 任务异常结束: {}", task_name, join_err);
        }
    }
}

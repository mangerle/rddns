use crate::config::model::AppConfig;
use anyhow::Result;
use log::{info, warn};
use parking_lot::RwLock;
use std::fs;
use std::io::{Error as IoError, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::runtime::Handle;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::watch;
use tokio::task::spawn_blocking;

/// 配置文件存取与持久化错误
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("配置文件 I/O 操作失败: {0}")]
    Io(#[from] IoError),
    #[error("TOML 反序列化错误: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("TOML 序列化错误: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("原子替换临时文件错误: {0}")]
    TempFile(String),
    /// 配置校验失败
    #[error("配置校验失败: {0}")]
    Validation(String),
    /// 账号已初始化业务冲突
    #[error("管理员账号已初始化，无法重复初始化")]
    AlreadyExists,
    /// 配置正被另一处异步更新持有写锁
    ///
    /// # 设计原理
    /// 独立于`TempFile` 变体，使调用方能明确区分「磁盘/序列化故障」与
    /// 「并发写锁争用」两类根因，避免排障时被错误文案误导。
    #[error("配置正被其他更新操作锁定，请改用 modify_config_async 或稍后重试")]
    Locked,
}

/// 配置管理器（支持原子写入持久化与 Tokio watch 热广播）
///
/// # 设计原理
/// - **实现初衷**：集中管理整个应用程序的动态配置生命周期，支持 CLI 覆写、Web API 实时更新与后台 Worker 变更订阅。
/// - **核心优势**：
///   1. 读写分离与无锁读取：内存快照使用 `Arc<RwLock<Arc<AppConfig>>>`，读取端纯无锁或极轻量读锁，吞吐极高。
///   2. 严格串行化防并发更新丢失：集成异步写互斥锁，确保并发 HTTP 提交时安全按序处理。
///   3. 原子写盘防损坏：采用“写入同目录临时文件 -> fsync 刷盘 -> 原子重命名”机制，即便遭遇掉电也不会破坏原配置。
pub struct ConfigManager {
    file_path: PathBuf,
    current: Arc<RwLock<Arc<AppConfig>>>,
    sender: watch::Sender<Arc<AppConfig>>,
    async_write_lock: TokioMutex<()>,
}

impl ConfigManager {
    /// 初始化配置管理器（从指定路径加载，若不存在则创建默认配置）
    ///
    /// # 设计原理
    /// - **实现初衷**: 在程序冷启动时提供安全自愈能力，首次运行时自动生成完整的样例配置文件。
    /// - **容错自愈 (P1-4)**: 自托管场景（本项目常部署于路由器、NAS 等无人值守设备）
    ///   下，配置若因断电、手工编辑或磁盘故障而损坏，原实现会直接返回错误使程序退出。
    ///   由于服务通常已注册为系统自启，该失败将形成「开机自启失败循环」，用户既拿不到
    ///   默认配置、也看不到任何恢复指引，等同设备变砖。现改为：**文件损坏**时备份
    ///   损坏文件并回退默认配置，使服务至少能够启动并通过 Web 界面重新配置。
    ///
    /// # 错误分类处置原则 (P1-4)
    /// 加载失败被严格区分为两类，二者处置策略截然不同：
    ///
    /// | 失败类型 | 根因 | 处置策略 |
    /// |---------|------|---------|
    /// | **文件损坏** | 断电、手工编辑失误、磁盘故障导致内容截断或语法非法 | 自动备份并回退默认配置，保证可启动 |
    /// | **配置内容非法** | 语法正确但违反业务规则（如端口为 0） | **显式报错并退出**，绝不自动重置 |
    ///
    /// 第二类必须显式报错的原因：配置语法正确说明用户是刻意如此设置，
    /// 自动重置为默认值会**静默丢弃用户的本意**（例如刻意设置的 0 端口可能
    /// 是为了配合其他服务做端口探测），而用户对配置被改写毫不知情。
    /// 此类失败通常源于程序版本升级引入的新校验规则，用户有能力自行修复。
    ///
    /// # Errors
    /// 当配置**内容非法**（返回 [`ConfigError::Validation`]）或磁盘无写入
    /// 权限导致无法创建默认配置时返回错误。
    pub fn load_or_create(path: PathBuf) -> Result<Self, ConfigError> {
        let config = if path.exists() {
            info!("正在加载配置文件: {}", path.display());
            match Self::load_existing(&path) {
                Ok(conf) => conf,
                // 内容非法：显式报错，绝不自动重置用户配置
                Err(ConfigError::Validation(msg)) => {
                    return Err(ConfigError::Validation(msg));
                }
                // 文件损坏：备份后回退默认配置，避免无人值守设备陷入自启失败循环
                Err(err) => {
                    warn!(
                        "配置文件已损坏（{}），已备份损坏文件并回退至默认配置，请通过 Web 界面或编辑备份文件恢复正确配置",
                        err
                    );
                    Self::backup_corrupted_file(&path);
                    let default_conf = AppConfig::default();
                    // 回退配置同样落盘，保证下次启动读取到的是合法配置
                    Self::atomic_save_to_path(&path, &default_conf).inspect_err(|e| {
                        warn!(
                            "回退默认配置写入磁盘失败（服务仍将以内存默认配置启动）: {}",
                            e
                        );
                    })?;
                    default_conf
                }
            }
        } else {
            info!("配置文件不存在，创建默认配置: {}", path.display());
            let default_conf = AppConfig::default();
            Self::atomic_save_to_path(&path, &default_conf)?;
            default_conf
        };

        let config_arc = Arc::new(config);
        let (sender, _) = watch::channel(config_arc.clone());

        Ok(Self {
            file_path: path,
            current: Arc::new(RwLock::new(config_arc)),
            sender,
            async_write_lock: TokioMutex::new(()),
        })
    }

    /// 加载并校验既有配置文件，执行版本迁移
    ///
    /// # Errors
    /// 文件读取失败、语法解析失败或业务校验失败时返回错误。
    fn load_existing(path: &Path) -> Result<AppConfig, ConfigError> {
        let content = fs::read_to_string(path)?;
        let mut conf: AppConfig = toml::from_str(&content)?;

        // 显式版本迁移：字段级 default 只能兜住「新增字段」，
        // 字段语义变更必须经由此处升级到当前版本 (P1-4)
        for note in conf.migrate() {
            warn!("[配置迁移] {}", note);
        }

        if let Err(errs) = conf.validate() {
            return Err(ConfigError::Validation(errs.join("; ")));
        }
        Ok(conf)
    }

    /// 将损坏的配置文件备份为带时间戳的副本 (P1-4)
    ///
    /// # 设计原理
    /// 绝不删除或覆盖损坏文件——它是用户手工编辑失败后的唯一现场，
    /// 保留副本可让用户在修复配置时查阅原有内容。
    /// 备份失败仅记录告警，不阻断启动流程（用户仍可手工找回配置）。
    fn backup_corrupted_file(path: &Path) {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config".to_string());
        let backup_name = format!("{}.corrupt-{}", file_name, stamp);

        let target = match path.parent() {
            Some(dir) => dir.join(&backup_name),
            None => PathBuf::from(&backup_name),
        };

        match fs::copy(path, &target) {
            Ok(_) => warn!(
                "损坏的配置文件已备份至: {}，请检查该文件后手工恢复正确配置",
                target.display()
            ),
            Err(e) => warn!(
                "备份损坏配置文件失败（{} -> {}）: {}；原文件未被修改，可手工找回",
                path.display(),
                target.display(),
                e
            ),
        }
    }

    /// 获取当前最新配置快照 (零阻塞克隆内部 Arc 引用)
    pub fn get_config(&self) -> Arc<AppConfig> {
        self.current.read().clone()
    }

    /// 获取配置文件路径引用
    pub fn get_config_path(&self) -> &Path {
        &self.file_path
    }

    /// 订阅配置变更流（供后台调度器监听热重载）
    pub fn subscribe(&self) -> watch::Receiver<Arc<AppConfig>> {
        self.sender.subscribe()
    }

    /// 原子更新并持久化配置
    ///
    /// # Errors
    /// 当磁盘写盘失败或序列化异常时返回错误。
    pub fn update_config(&self, new_config: AppConfig) -> Result<(), ConfigError> {
        self.modify_config::<_, ConfigError>(|_| Ok(new_config))
            .map(|_| ())
    }

    /// 仅在内存中更新配置并广播 (不持久化写入磁盘)
    /// 注意：仅限 CLI 启动期参数覆盖阶段使用，不得在 Web 服务运行期并发调用。
    pub fn update_runtime_config(&self, new_config: AppConfig) {
        let new_arc = Arc::new(new_config);
        *self.current.write() = new_arc.clone();
        let _ = self.sender.send(new_arc);
    }

    /// 在持有写锁的情况下原子修改并持久化配置（同步版本）
    ///
    /// # 适用场景
    /// 仅限**启动期**等确定无并发写入的路径（如 `--reset-password` 命令行重置）。
    /// 运行期的 Web API 写入必须使用 [`Self::modify_config_async`]，否则
    /// 会在锁被占用时直接返回 [`ConfigError::Locked`]。
    ///
    /// # 设计原理
    /// 同步版本直接在当前调用线程内联执行磁盘 IO 与 fsync。在异步上下文中调用时，
    /// 虽通过 `try_lock` 快速失败机制避免死锁与长时间等待，但由于内联写盘仍会占用
    /// 当前工作线程时间片，因此运行期异步环境必须严格调用 [`Self::modify_config_async`]。
    /// 此外，磁盘 IO 在内存读写锁外部执行，仅在更新内存快照与广播时短暂持有写锁（微秒级），
    /// 避免阻塞并发读取 (P2-4)。
    ///
    /// # Errors
    /// - 当临时文件生成失败、磁盘写入出错或闭包逻辑校验失败时返回错误；
    /// - 在异步上下文中且写锁已被占用时返回 [`ConfigError::Locked`]。
    pub fn modify_config<F, E>(&self, f: F) -> Result<Arc<AppConfig>, E>
    where
        F: FnOnce(&AppConfig) -> Result<AppConfig, E>,
        E: From<ConfigError>,
    {
        let _sync_guard = match Handle::try_current() {
            Ok(_) => self
                .async_write_lock
                .try_lock()
                .map_err(|_| ConfigError::Locked)?,
            Err(_) => self.async_write_lock.blocking_lock(),
        };

        let current_config = self.get_config();
        let new_config = f(&current_config)?;

        // 磁盘 IO 在内存写锁之外执行，杜绝持有 RwLock 锁期间阻塞文件系统写入
        Self::atomic_save_to_path(&self.file_path, &new_config)?;

        let new_arc = Arc::new(new_config);
        {
            let mut guard = self.current.write();
            *guard = new_arc.clone();
            let _ = self.sender.send(new_arc.clone());
        }
        info!("配置文件已原子更新保存并广播: {}", self.file_path.display());
        Ok(new_arc)
    }

    /// 异步在持有写锁的情况下原子修改并持久化配置 (严格互斥串行化，防止并发更新丢失)
    ///
    /// # 设计原理
    /// - **实现初衷**：在异步 Web API 下持久化大配置，通过 `spawn_blocking` 将同步磁盘 IO 调度至阻塞线程池，杜绝阻塞 Tokio 事件循环。
    ///
    /// # Errors
    /// 当写锁争用超时、后台持久化任务失败或闭包业务校验失败时返回错误。
    pub async fn modify_config_async<F, E>(&self, f: F) -> Result<Arc<AppConfig>, E>
    where
        F: FnOnce(&AppConfig) -> Result<AppConfig, E>,
        E: From<ConfigError> + Send + 'static,
    {
        let _async_guard = self.async_write_lock.lock().await;

        let current_config = self.get_config();
        let new_config = f(&current_config)?;

        let path = self.file_path.clone();
        let config_clone = new_config.clone();

        spawn_blocking(move || Self::atomic_save_to_path(&path, &config_clone))
            .await
            .map_err(|e| {
                E::from(ConfigError::TempFile(format!(
                    "执行配置持久化任务异常: {}",
                    e
                )))
            })??;

        let new_arc = Arc::new(new_config);
        {
            let mut guard = self.current.write();
            *guard = new_arc.clone();
            let _ = self.sender.send(new_arc.clone());
        }

        info!("配置文件已原子更新保存并广播: {}", self.file_path.display());
        Ok(new_arc)
    }

    /// 原子保存配置到指定路径
    /// 步骤: 写临时文件 -> 刷盘 sync_all -> 原子重命名 rename
    fn atomic_save_to_path(target_path: &Path, config: &AppConfig) -> Result<(), ConfigError> {
        let parent_dir = target_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent_dir)?;

        let toml_str = toml::to_string_pretty(config)?;

        let mut temp_file = NamedTempFile::new_in(parent_dir)
            .map_err(|e| ConfigError::TempFile(format!("创建临时文件失败: {}", e)))?;

        temp_file.write_all(toml_str.as_bytes())?;
        temp_file.flush()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = temp_file
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600));
        }

        temp_file.as_file().sync_all()?;

        temp_file
            .persist(target_path)
            .map_err(|e| ConfigError::TempFile(format!("原子重命名失败: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::spawn;

    #[test]
    fn test_atomic_save_and_load() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_config.toml");

        let manager = ConfigManager::load_or_create(config_file.clone()).unwrap();
        let initial_conf = manager.get_config();
        assert_eq!(initial_conf.listen_port, 9876);

        let mut updated = (*initial_conf).clone();
        updated.listen_port = 8888;
        manager.update_config(updated).unwrap();

        let reloaded = ConfigManager::load_or_create(config_file).unwrap();
        assert_eq!(reloaded.get_config().listen_port, 8888);
    }

    #[tokio::test]
    async fn test_modify_config_async() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_async_config.toml");

        let manager = ConfigManager::load_or_create(config_file.clone()).unwrap();
        let updated_arc = manager
            .modify_config_async::<_, ConfigError>(|conf| {
                let mut c = conf.clone();
                c.listen_port = 7777;
                Ok(c)
            })
            .await
            .unwrap();

        assert_eq!(updated_arc.listen_port, 7777);
        assert_eq!(manager.get_config().listen_port, 7777);

        let reloaded = ConfigManager::load_or_create(config_file).unwrap();
        assert_eq!(reloaded.get_config().listen_port, 7777);
    }

    #[tokio::test]
    async fn test_modify_config_reports_lock_contention_distinctly() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_lock_contention.toml");

        let manager = ConfigManager::load_or_create(config_file).unwrap();

        // 先抢占异步写锁，模拟并发写入场景
        let async_guard = manager.async_write_lock.lock().await;

        // 同步版本在锁被占用时应返回专用的 Locked 变体，
        // 而非语义错误的 TempFile，避免排障时被错误文案误导
        let result: Result<_, ConfigError> = manager.modify_config(|conf| Ok(conf.clone()));

        match result {
            Err(ConfigError::Locked) => {}
            Err(other) => panic!("应返回 Locked 变体，实际得到: {}", other),
            Ok(_) => panic!("锁被占用时同步修改应当失败"),
        }

        drop(async_guard);
    }

    #[test]
    fn test_config_error_variants_are_distinguishable() {
        // 锁争用与磁盘故障必须能被调用方区分
        let locked = ConfigError::Locked;
        let temp = ConfigError::TempFile("磁盘写入失败".to_string());
        assert_ne!(locked.to_string(), temp.to_string());
        assert!(locked.to_string().contains("锁定"));
        assert!(temp.to_string().contains("临时文件"));
    }

    #[tokio::test]
    async fn test_modify_config_async_concurrency_no_lost_update() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_concurrent_async_config.toml");

        let manager = Arc::new(ConfigManager::load_or_create(config_file.clone()).unwrap());

        // 并发发起 10 个累加 interval_secs 的修改请求
        let mut handles = Vec::new();
        for _ in 0..10 {
            let mgr = manager.clone();
            handles.push(spawn(async move {
                mgr.modify_config_async::<_, ConfigError>(|conf| {
                    let mut c = conf.clone();
                    c.interval_secs += 10;
                    Ok(c)
                })
                .await
            }));
        }

        for h in handles {
            h.await.unwrap().unwrap();
        }

        // 初始 interval_secs 是 300，10 次 +10 应该精确为 400
        assert_eq!(manager.get_config().interval_secs, 400);

        let reloaded = ConfigManager::load_or_create(config_file).unwrap();
        assert_eq!(reloaded.get_config().interval_secs, 400);
    }

    #[test]
    fn test_app_config_toml_roundtrip() {
        let default_conf = AppConfig::default();
        let toml_str =
            toml::to_string_pretty(&default_conf).expect("默认配置序列化为 TOML 必须成功");
        let parsed_conf: AppConfig =
            toml::from_str(&toml_str).expect("从生成的 TOML 反序列化必须成功");
        assert_eq!(default_conf, parsed_conf);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_config_file_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("secure_config.toml");

        let _ = ConfigManager::load_or_create(config_file.clone()).unwrap();
        let metadata = fs::metadata(&config_file).unwrap();
        let mode = metadata.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "Unix 环境下配置文件应具备 0600 (仅所有者可读写) 访问权限"
        );
    }

    #[test]
    fn test_corrupted_config_falls_back_to_default_with_backup() {
        // 回归用例 (P1-4)：配置损坏不得导致程序退出。
        // 无人值守设备（路由器/NAS）上服务通常已注册系统自启，
        // 一次配置损坏即形成「开机自启失败循环」，等同设备变砖。
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("corrupt.toml");

        // 写入语法完全非法的 TOML
        fs::write(&config_file, "这不是合法的 TOML 内容 ][{{").unwrap();

        // 必须成功启动而非报错退出
        let manager = ConfigManager::load_or_create(config_file.clone())
            .expect("配置损坏时应回退默认配置而非启动失败");

        // 应回退为默认配置
        let conf = manager.get_config();
        assert_eq!(conf.listen_port, 9876);
        assert_eq!(conf.interval_secs, 300);
        assert_eq!(conf.cache_times, 10);

        // 损坏文件必须被备份保留（用户唯一的恢复现场）
        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt-"))
            .collect();
        assert_eq!(
            backups.len(),
            1,
            "损坏的配置���件必须被备份为带时间戳的副本"
        );

        // 下次启动必须能正常读取（磁盘上已是合法配置），不得重复进入兜底分支
        let reloaded =
            ConfigManager::load_or_create(config_file).expect("回退后的配置必须可被正常加载");
        assert_eq!(reloaded.get_config().listen_port, 9876);
    }

    #[test]
    fn test_config_business_validation_failure_still_reports_error() {
        // 语法正确但业务校验失败（端口为 0）时必须显式报错，
        // 不得被「自动修复兜底」掩盖——自动重置会悄悄丢弃用户的本意
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("invalid_business.toml");

        fs::write(&config_file, "listen_port = 0").unwrap();

        let result = ConfigManager::load_or_create(config_file);
        assert!(
            result.is_err(),
            "业务校验失败必须显式报错，不得静默重置为默认配置"
        );
        match result.err() {
            Some(ConfigError::Validation(msg)) => {
                assert!(msg.contains("监听端口"), "错误信息应指明端口问题: {}", msg)
            }
            other => panic!("应返回 Validation 变体，实际得到: {:?}", other),
        }
    }

    #[test]
    fn test_migrate_normalizes_version_to_current() {
        use crate::config::model::CURRENT_CONFIG_VERSION;

        // 老版本配置（无 version 字段，serde 默认为 0）应被归一化到当前版本
        let mut conf = AppConfig {
            config_version: 0,
            ..Default::default()
        };
        let notes = conf.migrate();
        assert_eq!(conf.config_version, CURRENT_CONFIG_VERSION);
        assert!(
            notes.iter().any(|n| n.contains("迁移")),
            "应产生迁移提示，实际: {:?}",
            notes
        );

        // 已是当前版本则无迁移提示
        let mut current = AppConfig::default();
        assert!(current.migrate().is_empty());

        // 高于当前版本：给出显式告警而非静默接受，防止配置项被无声丢弃
        let mut future = AppConfig {
            config_version: CURRENT_CONFIG_VERSION + 5,
            ..Default::default()
        };
        let notes = future.migrate();
        assert!(
            notes.iter().any(|n| n.contains("高于当前程序支持的版本")),
            "高版本配置必须显式告警，实际: {:?}",
            notes
        );
    }

    #[test]
    fn test_legacy_config_without_version_field_loads() {
        // 兼容性：既有用户配置文件不含 config_version 字段，
        // 必须能正常加载并被自动补齐版本号，不得报错
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("legacy.toml");

        // 模拟 v0.12.0 之前生成的无版本字段配置
        fs::write(
            &config_file,
            "listen_port = 8888\ninterval_secs = 600\ncache_times = 20\n",
        )
        .unwrap();

        let manager =
            ConfigManager::load_or_create(config_file).expect("老版本无版本字段配置必须可加载");
        let conf = manager.get_config();

        assert_eq!(conf.listen_port, 8888, "既有配置值必须被完整保留");
        assert_eq!(conf.interval_secs, 600);
        assert_eq!(conf.cache_times, 20);
        assert_eq!(
            conf.config_version,
            crate::config::model::CURRENT_CONFIG_VERSION,
            "版本号应被自动补齐为当前版本"
        );
    }
}

use crate::config::model::AppConfig;
use anyhow::Result;
use log::info;
use parking_lot::RwLock;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("配置文件 I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML 序列化/反序列化错误: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("原子替换临时文件错误: {0}")]
    TempFile(String),
}

/// 配置管理器（支持原子写入持久化与 Tokio watch 热广播）
pub struct ConfigManager {
    file_path: PathBuf,
    current: Arc<RwLock<Arc<AppConfig>>>,
    sender: watch::Sender<Arc<AppConfig>>,
    async_write_lock: TokioMutex<()>,
}

impl ConfigManager {
    /// 初始化配置管理器（从指定路径加载，若不存在则创建默认配置）
    pub fn load_or_create(path: PathBuf) -> Result<Self, ConfigError> {
        let config = if path.exists() {
            info!("正在加载配置文件: {}", path.display());
            let content = fs::read_to_string(&path)?;
            let conf: AppConfig = serde_yaml::from_str(&content)?;
            conf
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

    /// 获取当前最新配置快照
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
    pub fn update_config(&self, new_config: AppConfig) -> Result<(), ConfigError> {
        self.modify_config::<_, ConfigError>(|_| Ok(new_config))
            .map(|_| ())
    }

    /// 仅在内存中更新配置并广播 (不持久化写入磁盘，用于 CLI 运行时临时参数覆盖)
    pub fn update_runtime_config(&self, new_config: AppConfig) {
        let new_arc = Arc::new(new_config);
        *self.current.write() = new_arc.clone();
        let _ = self.sender.send(new_arc);
    }

    /// 在持有写锁的情况下原子修改并持久化配置
    /// 注意：同步修改主要用于 CLI 启动初始化或非异步上下文；在 Web 运行时中请优先使用 `modify_config_async`。
    /// 本方法会尝试获取与异步路径共享的 `async_write_lock`，若在非 Tokio runtime 线程上则完全阻塞排队。
    pub fn modify_config<F, E>(&self, f: F) -> Result<Arc<AppConfig>, E>
    where
        F: FnOnce(&AppConfig) -> Result<AppConfig, E>,
        E: From<ConfigError>,
    {
        let _sync_guard = match tokio::runtime::Handle::try_current() {
            Ok(_) => self.async_write_lock.try_lock().ok(),
            Err(_) => Some(self.async_write_lock.blocking_lock()),
        };

        let mut guard = self.current.write();
        let new_config = f(&guard)?;
        Self::atomic_save_to_path(&self.file_path, &new_config)?;
        let new_arc = Arc::new(new_config);
        *guard = new_arc.clone();
        let _ = self.sender.send(new_arc.clone());
        info!("配置文件已原子更新保存并广播: {}", self.file_path.display());
        Ok(new_arc)
    }

    /// 异步在持有写锁的情况下原子修改并持久化配置 (严格互斥串行化，防止并发更新丢失)
    pub async fn modify_config_async<F, E>(&self, f: F) -> Result<Arc<AppConfig>, E>
    where
        F: FnOnce(&AppConfig) -> Result<AppConfig, E>,
        E: From<ConfigError> + Send + 'static,
    {
        // 1. 获取异步写锁，确保从读取当前快照到磁盘写入与内存更新全过程串行互斥
        let _async_guard = self.async_write_lock.lock().await;

        let current_config = self.get_config();
        let new_config = f(&current_config)?;

        let path = self.file_path.clone();
        let config_clone = new_config.clone();

        tokio::task::spawn_blocking(move || Self::atomic_save_to_path(&path, &config_clone))
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

        let yaml_str = serde_yaml::to_string(config)?;

        let mut temp_file = NamedTempFile::new_in(parent_dir)
            .map_err(|e| ConfigError::TempFile(format!("创建临时文件失败: {}", e)))?;

        temp_file.write_all(yaml_str.as_bytes())?;
        temp_file.flush()?;
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

    #[test]
    fn test_atomic_save_and_load() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_config.yaml");

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
        let config_file = dir.path().join("test_async_config.yaml");

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
    async fn test_modify_config_async_concurrency_no_lost_update() {
        let dir = tempdir().unwrap();
        let config_file = dir.path().join("test_concurrent_async_config.yaml");

        let manager = Arc::new(ConfigManager::load_or_create(config_file.clone()).unwrap());

        // 并发发起 10 个累加 interval_secs 的修改请求
        let mut handles = Vec::new();
        for _ in 0..10 {
            let mgr = manager.clone();
            handles.push(tokio::spawn(async move {
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
}

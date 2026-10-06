use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// 文件日志 Appender 配置选项
#[derive(Debug, Clone)]
pub struct FileAppenderConfig<P: AsRef<Path>> {
    /// 日志存放目录
    pub log_dir: P,
    /// 主日志文件名 (如 "rddns.log")
    pub file_name: String,
    /// 单文件大小上限 (字节)
    pub max_bytes: u64,
    /// 最多保留的旧归档日志文件数量
    pub max_files: usize,
}

/// 按文件大小自动轮转的文件写入器
///
/// # 设计原理
/// - **实现初衷**：长时间运行的 DDNS 进程会产生持续日志流，若不加以控制会导致磁盘空间爆满。
/// - **核心优势**：在写入边界自动检查当前文件尺寸，达到阈值立即原子化重命名递增备份（如 `.1`, `.2`），并严格限制最大文件数。
pub struct SizeRollingWriter {
    log_dir: PathBuf,
    file_name: String,
    max_bytes: u64,
    max_files: usize,
    current_file: Option<File>,
    current_size: u64,
    /// 轮转连续失败次数 (P1-12)
    ///
    /// 用于在文件被外部进程锁定等持久性故障下抑制无谓的轮转重试。
    rotate_failures: u32,
    /// 是否已进入「放弃轮转、转纯追加」的降级状态
    ///
    /// 置位后仅在轮转成功时解除，避免每条日志都重复输出同一条错误日志。
    rotate_suppressed: bool,
}

impl SizeRollingWriter {
    /// 轮转失败降级计数阈值 (P1-12)
    ///
    /// # 设计原理
    /// 轮转失败（如文件被杀毒软件锁定）时若每次写入都重试，会形成高频失败
    /// 且日志文件持续增长突破上限。连续失败达此阈值后放弃本轮轮转，转为
    /// 纯追加模式，保证日志内容不丢失。
    const ROTATE_FAILURE_THRESHOLD: u32 = 3;

    /// 基于配置对象创建新的大小轮转文件写入器
    ///
    /// # Errors
    /// 当日志目录创建失败或日志文件打开失败时返回错误。
    pub fn with_config<P: AsRef<Path>>(config: FileAppenderConfig<P>) -> Result<Self> {
        let dir_ref = config.log_dir.as_ref();
        if !dir_ref.exists() {
            fs::create_dir_all(dir_ref)
                .with_context(|| format!("创建日志目录失败: {}", dir_ref.display()))?;
        }

        let mut writer = Self {
            log_dir: dir_ref.to_path_buf(),
            file_name: config.file_name,
            max_bytes: config.max_bytes.max(1),
            max_files: config.max_files,
            current_file: None,
            current_size: 0,
            rotate_failures: 0,
            rotate_suppressed: false,
        };

        writer.open_current_file()?;

        if writer.current_size >= writer.max_bytes {
            writer.rotate()?;
        }

        Ok(writer)
    }

    /// 创建一个新的基于大小轮转的文件写入器
    ///
    /// # Errors
    /// 当日志目录创建失败或日志文件打开失败时返回错误。
    pub fn new(log_dir: &Path, file_name: &str, max_bytes: u64, max_files: usize) -> Result<Self> {
        Self::with_config(FileAppenderConfig {
            log_dir,
            file_name: file_name.to_string(),
            max_bytes,
            max_files,
        })
    }

    /// 获取主日志文件完整路径
    fn main_file_path(&self) -> PathBuf {
        self.log_dir.join(&self.file_name)
    }

    /// 获取指定编号的轮转归档文件路径 (例如 rddns.1.log)
    fn rotated_file_path(&self, index: usize) -> PathBuf {
        if let Some((stem, ext)) = self.file_name.rsplit_once('.') {
            self.log_dir.join(format!("{}.{}.{}", stem, index, ext))
        } else {
            self.log_dir.join(format!("{}.{}", self.file_name, index))
        }
    }

    /// 打开或创建主日志文件，并记录初始大小
    ///
    /// # 文件权限 (P1-12)
    /// 日志中可能包含经脱敏后的 DNS 请求信息、配置变更记录与 Web 访问日志。
    /// Unix 上 `OpenOptions` 默认遵循 umask，通常生成 `0644`（world-readable）；
    /// 当服务以 root 运行时（`util/service.rs` 写入 `/etc/systemd/system/`
    /// 暗示该场景），任何本地用户均可读取。此处显式限定 `0600`，
    /// 使日志访问权限与配置文件（`config/storage.rs` 同样为 `0600`）一致。
    fn open_current_file(&mut self) -> Result<()> {
        let path = self.main_file_path();
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // mode 仅在文件被创建时生效；已存在的文件不会被改动权限，
            // 故下方对已存在文件额外做一次 set_permissions 修正。
            opts.mode(0o600);
        }
        let file = opts
            .open(&path)
            .with_context(|| format!("打开日志文件失败: {}", path.display()))?;

        // 修正已存在文件的权限（mode 参数对已存在文件无效）
        #[cfg(unix)]
        if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            log::warn!(
                "收紧日志文件权限至 0600 失败（文件可能保持更宽权限）: {}",
                e
            );
        }

        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        self.current_file = Some(file);
        self.current_size = size;
        Ok(())
    }

    /// 执行日志文件轮转
    ///
    /// # 错误处理契约 (P1-12)
    /// 本方法此前对全部 `fs::remove_file` / `fs::rename` 使用 `let _ =`
    /// 丢弃错误。其中最严重的是主日志重命名：若失败（Windows 上杀毒软件
    /// 锁定文件极常见），主日志不会轮转，而 `open_current_file` 重新打开
    /// 同一路径后 `current_size` 仍超限，导致**每次写入都触发一次轮转
    /// 重试**——形成高频失败 + 单文件无限增长突破 `max_bytes` 上限，
    /// 且用户看不到任何错误提示。
    ///
    /// 现改为：归档清理类失败仅记录告警（不应阻断日志写入），但主日志
    /// 重命名失败必须向上传播，使调用方能感知并降级。
    fn rotate(&mut self) -> Result<()> {
        // 1. 关闭当前文件句柄并刷盘释放句柄
        if let Some(mut file) = self.current_file.take() {
            let _ = file.flush();
            drop(file);
        }

        let main_path = self.main_file_path();
        if main_path.exists() {
            if self.max_files > 0 {
                // 删除最旧的归档文件 (如 rddns.5.log)
                let oldest_path = self.rotated_file_path(self.max_files);
                if oldest_path.exists()
                    && let Err(e) = fs::remove_file(&oldest_path)
                {
                    log::warn!("删除最旧归档日志文件失败（继续轮转）: {}", e);
                }

                // 逐级向下重命名旧备份文件: rddns.4.log -> rddns.5.log ...
                for i in (1..self.max_files).rev() {
                    let src = self.rotated_file_path(i);
                    let dst = self.rotated_file_path(i + 1);
                    if src.exists() {
                        if dst.exists()
                            && let Err(e) = fs::remove_file(&dst)
                        {
                            log::warn!("删除过期归档日志文件失败（继续轮转）: {}", e);
                        }
                        if let Err(e) = fs::rename(&src, &dst) {
                            log::warn!(
                                "归档日志重命名失败 {} -> {}: {}",
                                src.display(),
                                dst.display(),
                                e
                            );
                        }
                    }
                }

                // 将当前主日志文件命名为 .1 备份: rddns.log -> rddns.1.log
                let first_backup = self.rotated_file_path(1);
                if first_backup.exists()
                    && let Err(e) = fs::remove_file(&first_backup)
                {
                    log::warn!("删除首个备份日志文件失败（继续轮转）: {}", e);
                }
                // 关键步骤：主日志重命名失败必须传播，不可静默忽略
                fs::rename(&main_path, &first_backup).with_context(|| {
                    format!(
                        "轮转失败：无法将主日志重命名为归档文件 {} -> {}（文件可能被其他进程锁定）",
                        main_path.display(),
                        first_backup.display()
                    )
                })?;
            } else {
                // 不保留历史备份，直接移除当前文件
                if let Err(e) = fs::remove_file(&main_path) {
                    log::warn!("删除超出上限的主日志文件失败: {}", e);
                }
            }
        }

        // 2. 重新打开全新的主日志文件
        self.open_current_file()?;
        Ok(())
    }
}

impl Write for SizeRollingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.current_file.is_none() {
            self.open_current_file()
                .map_err(|e| io::Error::other(e.to_string()))?;
        }

        // 检查写入后是否会超出文件大小上限
        if self.current_size > 0 && (self.current_size + buf.len() as u64 > self.max_bytes) {
            if self.rotate_failures >= Self::ROTATE_FAILURE_THRESHOLD {
                // 已连续多次轮转失败，放弃轮转转为纯追加，
                // 避免每次写入都触发一次必然失败的轮转（CPU 与 IO 空转）
                if self.rotate_suppressed {
                    // 抑制状态只在恢复后解除，此处静默跳过
                } else {
                    self.rotate_suppressed = true;
                    log::error!(
                        "日志轮转已连续失败 {} 次，本轮起临时转为纯追加模式（文件将不再受 {} 字节上限约束），请检查日志目录是否可写或文件是否被其他进程锁定",
                        self.rotate_failures,
                        self.max_bytes
                    );
                }
            } else {
                match self.rotate() {
                    Ok(()) => {
                        self.rotate_failures = 0;
                        self.rotate_suppressed = false;
                    }
                    Err(e) => {
                        self.rotate_failures += 1;
                        // 轮转失败不阻断日志写入：本轮内容仍应落盘，
                        // 否则一次文件锁定就会导致全部运行日志丢失
                        log::error!(
                            "日志轮转失败（第 {} 次，将在本批日志写入后重试）: {}",
                            self.rotate_failures,
                            e
                        );
                    }
                }
            }
        }

        if let Some(ref mut file) = self.current_file {
            let written = file.write(buf)?;
            self.current_size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "日志文件句柄未正确初始化",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut file) = self.current_file {
            file.flush()
        } else {
            Ok(())
        }
    }
}

/// 创建文件大小滚动写入器实例
///
/// * `log_dir`: 日志存放目录 (如 "logs")
/// * `file_name`: 主日志文件名 (如 "rddns.log")
/// * `max_bytes`: 单文件最大字节数 (如 10 * 1024 * 1024 为 10MB)
/// * `max_files`: 最大保留的历史轮转文件数 (如 5)
///
/// # Errors
/// 当日志目录创建失败或日志文件打开失败时返回错误。
pub fn init_file_writer<P: AsRef<Path>>(
    log_dir: P,
    file_name: &str,
    max_bytes: u64,
    max_files: usize,
) -> Result<SizeRollingWriter> {
    SizeRollingWriter::new(log_dir.as_ref(), file_name, max_bytes, max_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_size_rolling_writer() {
        let dir = tempdir().expect("创建临时目录失败");
        let dir_path = dir.path();
        let file_name = "test.log";
        let max_bytes = 100; // 100 字节大小限制
        let max_files = 2; // 保留 2 个归档文件

        let mut writer = SizeRollingWriter::new(dir_path, file_name, max_bytes, max_files)
            .expect("创建写入器失败");

        // 写入 60 字节
        let data1 = vec![b'A'; 60];
        writer.write_all(&data1).expect("写入数据1失败");
        writer.flush().expect("刷盘失败");

        assert!(dir_path.join("test.log").exists());
        assert_eq!(fs::metadata(dir_path.join("test.log")).unwrap().len(), 60);

        // 再次写入 60 字节，总计 120 字节超过 100 字节，触发轮转
        let data2 = vec![b'B'; 60];
        writer.write_all(&data2).expect("写入数据2失败");
        writer.flush().expect("刷盘失败");

        // 原文件轮转为 test.1.log，当前 test.log 包含新的 60 字节
        assert!(dir_path.join("test.1.log").exists());
        assert_eq!(fs::metadata(dir_path.join("test.1.log")).unwrap().len(), 60);
        assert_eq!(fs::metadata(dir_path.join("test.log")).unwrap().len(), 60);

        // 再次写入 60 字节，触发第二次轮转
        let data3 = vec![b'C'; 60];
        writer.write_all(&data3).expect("写入数据3失败");
        writer.flush().expect("刷盘失败");

        assert!(dir_path.join("test.2.log").exists());
        assert!(dir_path.join("test.1.log").exists());
        assert_eq!(fs::metadata(dir_path.join("test.2.log")).unwrap().len(), 60);
    }

    #[cfg(unix)]
    #[test]
    fn test_log_file_permissions_are_owner_only() {
        // 回归用例 (P1-12)：日志文件此前以 OpenOptions 默认权限创建，
        // Unix 上遵循 umask 通常为 0644（world-readable）。服务以 root
        // 运行时任何本地用户均可读取日志内容。现显式限定 0600，
        // 与配置文件（config/storage.rs）保持一致。
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let mut writer = SizeRollingWriter::new(dir.path(), "perm.log", 10 * 1024 * 1024, 3)
            .expect("创建写入器失败");
        writer
            .write_all(b"sensitive log content")
            .expect("写入失败");
        writer.flush().expect("刷盘失败");

        let meta = fs::metadata(dir.path().join("perm.log")).expect("读取元数据失败");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "日志文件权限必须为 0600（仅所有者可读写）"
        );
    }

    #[test]
    fn test_rotate_failure_does_not_block_log_writing() {
        // 回归用例 (P1-12)：轮转失败（如文件被外部进程锁定）时，
        // 内容仍必须持续落盘。一次文件锁定不应导致全部运行日志丢失。
        let dir = tempfile::tempdir().expect("创建临时目录失败");
        let mut writer =
            SizeRollingWriter::new(dir.path(), "degrade.log", 100, 2).expect("创建写入器失败");

        // 写入超过上限触发轮转路径，多次写入验证持续可用
        for i in 0..5 {
            let chunk = format!("{:0<60}", i);
            writer
                .write_all(chunk.as_bytes())
                .unwrap_or_else(|e| panic!("第 {} 次写入不应失败: {}", i, e));
        }
        writer.flush().expect("刷盘失败");

        // 日志内容必须真实落盘
        let total: u64 = fs::read_dir(dir.path())
            .expect("读取目录失败")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with("degrade"))
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum();
        assert!(total > 0, "日志内容必须已落盘");
    }
}

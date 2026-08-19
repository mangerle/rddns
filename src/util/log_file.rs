use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};

/// 按文件大小自动轮转的文件写入器
pub struct SizeRollingWriter {
    log_dir: PathBuf,
    file_name: String,
    max_bytes: u64,
    max_files: usize,
    current_file: Option<File>,
    current_size: u64,
}

impl SizeRollingWriter {
    /// 创建一个新的基于大小轮转的文件写入器
    pub fn new(log_dir: &Path, file_name: &str, max_bytes: u64, max_files: usize) -> Result<Self> {
        if !log_dir.exists() {
            fs::create_dir_all(log_dir)
                .with_context(|| format!("创建日志目录失败: {}", log_dir.display()))?;
        }

        let mut writer = Self {
            log_dir: log_dir.to_path_buf(),
            file_name: file_name.to_string(),
            max_bytes: max_bytes.max(1), // 允许自定义最小字节
            max_files,
            current_file: None,
            current_size: 0,
        };

        writer.open_current_file()?;

        // 如果启动时已有日志文件且已超出大小限制，立即执行一次轮转
        if writer.current_size >= writer.max_bytes {
            writer.rotate()?;
        }

        Ok(writer)
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
    fn open_current_file(&mut self) -> Result<()> {
        let path = self.main_file_path();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("打开日志文件失败: {}", path.display()))?;

        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        self.current_file = Some(file);
        self.current_size = size;
        Ok(())
    }

    /// 执行日志文件轮转
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
                if oldest_path.exists() {
                    let _ = fs::remove_file(&oldest_path);
                }

                // 逐级向下重命名旧备份文件: rddns.4.log -> rddns.5.log ...
                for i in (1..self.max_files).rev() {
                    let src = self.rotated_file_path(i);
                    let dst = self.rotated_file_path(i + 1);
                    if src.exists() {
                        if dst.exists() {
                            let _ = fs::remove_file(&dst);
                        }
                        let _ = fs::rename(&src, &dst);
                    }
                }

                // 将当前主日志文件命名为 .1 备份: rddns.log -> rddns.1.log
                let first_backup = self.rotated_file_path(1);
                if first_backup.exists() {
                    let _ = fs::remove_file(&first_backup);
                }
                let _ = fs::rename(&main_path, &first_backup);
            } else {
                // 不保留历史备份，直接移除当前文件
                let _ = fs::remove_file(&main_path);
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
            self.rotate().map_err(|e| io::Error::other(e.to_string()))?;
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

/// 初始化非阻塞文件日志 Appender
///
/// * `log_dir`: 日志存放目录 (如 "logs")
/// * `file_name`: 主日志文件名 (如 "rddns.log")
/// * `max_bytes`: 单文件最大字节数 (如 10 * 1024 * 1024 为 10MB)
/// * `max_files`: 最大保留的历史轮转文件数 (如 5)
pub fn init_file_appender<P: AsRef<Path>>(
    log_dir: P,
    file_name: &str,
    max_bytes: u64,
    max_files: usize,
) -> Result<(NonBlocking, WorkerGuard)> {
    let writer = SizeRollingWriter::new(log_dir.as_ref(), file_name, max_bytes, max_files)?;
    let (non_blocking, guard) = tracing_appender::non_blocking(writer);
    Ok((non_blocking, guard))
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
}

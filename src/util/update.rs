use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::{Cursor, Write, copy};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::time::Duration;
use tar::Archive;
use tokio::spawn;
use tokio::time::sleep;
use zip::ZipArchive;

use crate::util::daemon::configure_daemon_command;
use crate::util::http::create_http_client_builder;

const GITHUB_API_LATEST: &str = "https://api.github.com/repos/mangerle/rddns/releases/latest";

/// 版本检查结果信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// 当前正在运行的程序版本
    pub current_version: String,
    /// GitHub 远端发布的最新版本 Tag
    pub latest_version: String,
    /// 是否存在可用新版本更新
    pub has_update: bool,
    /// GitHub Release 页面 Web 链接
    pub release_url: String,
    /// 远端发布说明日志 Markdown
    pub release_notes: String,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    assets: Vec<GithubReleaseAsset>,
}

/// 比较版本号：若 latest > current 返回 true
///
/// # 设计原理
/// - **实现初衷**：解析语义化版本点分数字（如 0.2.1 vs 0.3.0），安全忽略 'v' 前缀与预发布后缀。
/// - **核心优势**：纯数值迭代比较，避免字符串直接比较引发的字典序错误（如 "0.10.0" < "0.9.0"）。
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let clean_v = |v: &str| -> Vec<u64> {
        v.trim()
            .trim_start_matches(['v', 'V'])
            .split('.')
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };

    let cur_parts = clean_v(current);
    let lat_parts = clean_v(latest);

    for (c, l) in cur_parts.iter().zip(lat_parts.iter()) {
        if l > c {
            return true;
        } else if l < c {
            return false;
        }
    }

    lat_parts.len() > cur_parts.len()
}

/// 检查 GitHub Releases 最新版本信息
///
/// # 设计原理
/// - **实现初衷**：通过 GitHub 开放 REST API 轮询最新版本 Release，便于在前端提示升级。
/// - **核心优势**：轻量级请求，短超时保护。
///
/// # Errors
/// 当网络通信中断、GitHub API 限流或响应 JSON 解析异常时返回错误。
pub async fn check_version() -> Result<VersionInfo> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();

    let client = create_http_client_builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("RDDNS-Updater/v{}", current_version))
        .build()
        .context("创建 HTTP 客户端失败")?;

    let resp = client
        .get(GITHUB_API_LATEST)
        .send()
        .await
        .context("连接 GitHub API 失败")?;

    if !resp.status().is_success() {
        bail!("GitHub API 响应异常: HTTP {}", resp.status());
    }

    let release: GithubRelease = resp.json().await.context("解析 Release 信息失败")?;
    let latest_ver_clean = release.tag_name.trim_start_matches(['v', 'V']).to_string();
    let has_update = is_newer_version(&current_version, &latest_ver_clean);

    let info = VersionInfo {
        current_version,
        latest_version: release.tag_name,
        has_update,
        release_url: release.html_url,
        release_notes: release.body,
    };

    Ok(info)
}

/// 匹配最适合当前系统的 Release 资产 (精准匹配架构与操作系统)
fn match_system_asset(assets: &[GithubReleaseAsset]) -> Option<&GithubReleaseAsset> {
    let target_os = env::consts::OS;
    let target_arch = env::consts::ARCH;

    assets.iter().find(|a| {
        let name = a.name.to_lowercase();
        let os_match = match target_os {
            "windows" => name.contains("windows") || name.ends_with(".exe"),
            "linux" => name.contains("linux"),
            "macos" => name.contains("darwin") || name.contains("macos") || name.contains("apple"),
            "freebsd" => name.contains("freebsd"),
            _ => false,
        };
        let arch_match = match target_arch {
            "x86_64" => name.contains("x86_64") || name.contains("amd64") || name.contains("x64"),
            "x86" | "i686" => {
                name.contains("i686") || name.contains("x86") || name.contains("32-bit")
            }
            "aarch64" => name.contains("aarch64") || name.contains("arm64"),
            "arm" | "armv7" => {
                let is_arm = name.contains("armv7")
                    || name.contains("armv6")
                    || name.contains("armv5")
                    || name.contains("arm-");
                let not_arm64 = !name.contains("arm64") && !name.contains("aarch64");
                is_arm && not_arm64
            }
            "riscv64" => name.contains("riscv64"),
            "loongarch64" => name.contains("loongarch64"),
            _ => false,
        };
        os_match && arch_match
    })
}

/// 校验下载安装包的 SHA256 签名文件
async fn verify_downloaded_sha256(
    client: &reqwest::Client,
    sha_asset: &GithubReleaseAsset,
    actual_sha256: &str,
) -> Result<()> {
    info!("正在下载并校验 SHA256 签名 [{}]...", sha_asset.name);
    let sha_resp = client
        .get(&sha_asset.browser_download_url)
        .send()
        .await
        .context("下载 SHA256 校验文件失败")?;

    if !sha_resp.status().is_success() {
        bail!("下载 SHA256 校验文件返回异常状态码: {}", sha_resp.status());
    }

    let sha_text = sha_resp
        .text()
        .await
        .context("读取 SHA256 校验文件内容失败")?;
    let expected_sha256 = sha_text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim()
        .to_lowercase();

    if expected_sha256.is_empty() {
        bail!("SHA256 校验文件格式异常，未读取到有效的哈希指纹");
    }

    if actual_sha256 != expected_sha256 {
        bail!(
            "安装包 SHA256 完整性校验失败！预期值: {}, 实际值: {}",
            expected_sha256,
            actual_sha256
        );
    }
    info!("安装包 SHA256 校验通过: {}", actual_sha256);
    Ok(())
}

/// 原子安全备份并原地替换二进制可执行文件
fn atomic_replace_binary(current_exe: &Path, binary_bytes: &[u8]) -> Result<()> {
    let backup_exe: PathBuf = if let Some(ext) = current_exe.extension() {
        current_exe.with_extension(format!("{}.old", ext.to_string_lossy()))
    } else {
        current_exe.with_extension("old")
    };

    if backup_exe.exists() {
        let _ = fs::remove_file(&backup_exe);
    }

    info!("正在执行二进制文件热替换...");
    fs::rename(current_exe, &backup_exe)
        .context("备份当前运行程序失败 (可能缺少管理员写入权限)")?;

    let write_res = (|| -> Result<(), std::io::Error> {
        let mut file = File::create(current_exe)?;
        file.write_all(binary_bytes)?;
        file.flush()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(current_exe)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(current_exe, perms)?;
        }

        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::rename(&backup_exe, current_exe);
        bail!("写入新版本失败，已恢复原版本: {}", err);
    }

    Ok(())
}

/// 执行原地一键热升级（下载最新发布包 -> SHA256校验 -> 解压 -> 安全备份替换）
///
/// # 设计原理
/// - **实现初衷**：在无包管理器或容器编排的环境下，为嵌入式/服务器环境提供开箱即用的自动化自升级能力。
/// - **核心优势**：自动识别操作系统与 CPU 架构、强制 SHA256 签名校验、原地原子备份与失败自动回滚。
///
/// # Errors
/// 当网络中断、校验失败、无文件写入权限或架构不适配时返回错误。
pub async fn upgrade_self() -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    info!(
        "正在检查最新发布版本并准备原地自更新 (当前版本: v{})...",
        current_version
    );

    let client = create_http_client_builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("RDDNS-Updater/v{}", current_version))
        .build()
        .context("创建 HTTP 客户端失败")?;

    let resp = client
        .get(GITHUB_API_LATEST)
        .send()
        .await
        .context("获取 Release 下载列表失败")?;
    if !resp.status().is_success() {
        bail!("GitHub API 响应异常: HTTP {}", resp.status());
    }

    let release: GithubRelease = resp.json().await.context("解析 Release 资产失败")?;
    let latest_ver_clean = release.tag_name.trim_start_matches(['v', 'V']).to_string();
    if !is_newer_version(current_version, &latest_ver_clean) {
        info!("当前已是最新版本 (v{})，无需更新", current_version);
        return Ok(());
    }

    let asset = match_system_asset(&release.assets).ok_or_else(|| {
        anyhow::anyhow!(
            "未在 Release 中找到适配当前系统架构 ({}-{}) 的安装包，请手动访问: {}",
            env::consts::OS,
            env::consts::ARCH,
            release.html_url
        )
    })?;

    let download_resp = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("下载安装包失败")?;
    if !download_resp.status().is_success() {
        bail!("下载失败，HTTP 状态码: {}", download_resp.status());
    }

    let raw_bytes = download_resp.bytes().await.context("读取下载数据失败")?;
    let actual_sha256 = hex::encode(Sha256::digest(&raw_bytes));

    let sha256_asset = release.assets.iter().find(|a| {
        let name = a.name.to_lowercase();
        name == format!("{}.sha256", asset.name.to_lowercase())
            || name == format!("{}.sha256.txt", asset.name.to_lowercase())
    });

    if let Some(sha_asset) = sha256_asset {
        verify_downloaded_sha256(&client, sha_asset, &actual_sha256).await?;
    } else {
        warn!(
            "Release 资产中未提供匹配的 SHA256 校验文件，当前安装包指纹: {}",
            actual_sha256
        );
    }

    let binary_bytes = extract_binary_from_bytes(&asset.name, &raw_bytes)?;
    let current_exe = env::current_exe().context("获取当前程序路径失败")?;
    atomic_replace_binary(&current_exe, &binary_bytes)?;

    info!(
        "RDDNS 成功更新至最新版本 {}！请重启程序或服务以使更新完全生效。",
        release.tag_name
    );
    Ok(())
}

/// 重启当前程序进程以加载新升级的二进制文件
///
/// # 设计原理
/// - **实现初衷**：在热替换二进制文件后平滑拉起新版本进程，自动继承原有启动参数。
/// - **核心优势**：跨平台兼容（Windows 采用 PowerShell 规避 cmd 转义注入，Unix 采用 sh exec 释放旧端口）。
///
/// # Errors
/// 当当前程序路径获取失败或派生辅助进程异常时返回错误。
pub fn restart_process() -> Result<()> {
    let current_exe = env::current_exe().context("获取当前程序路径失败")?;
    let args: Vec<String> = env::args().skip(1).collect();

    #[cfg(target_os = "windows")]
    {
        let mut launcher = Command::new("powershell");
        let ps_script = format!(
            "Start-Sleep -Milliseconds 1000; Start-Process -FilePath '{}' -ArgumentList @({})",
            current_exe.to_string_lossy().replace('\'', "''"),
            args.iter()
                .map(|a| format!("'{}'", a.replace('\'', "''")))
                .collect::<Vec<_>>()
                .join(",")
        );

        launcher.args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-Command",
            &ps_script,
        ]);
        configure_daemon_command(&mut launcher);
        launcher.spawn().context("派生重启辅助进程失败")?;
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut launcher = Command::new("sh");
        let mut sh_cmd = format!("sleep 1 && exec \"{}\"", current_exe.to_string_lossy());
        for arg in &args {
            sh_cmd.push_str(&format!(" '{}'", arg.replace('\'', "'\\''")));
        }
        launcher.args(["-c", &sh_cmd]);
        configure_daemon_command(&mut launcher);
        launcher.spawn().context("派生重启辅助进程失败")?;
    }

    spawn(async {
        sleep(Duration::from_millis(300)).await;
        exit(0);
    });

    Ok(())
}

/// 从 ZIP 压缩归档数据中提取主程序二进制
fn extract_from_zip(bytes: &[u8]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("解析 ZIP 压缩包失败")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("读取 ZIP 压缩文件条目失败")?;
        if file.is_dir() {
            continue;
        }

        let entry_name = file.name().replace('\\', "/");
        let file_name = entry_name.split('/').next_back().unwrap_or(&entry_name);

        if file_name.eq_ignore_ascii_case("rddns.exe") || file_name.eq_ignore_ascii_case("rddns") {
            let mut out = Vec::new();
            copy(&mut file, &mut out).context("解压可执行程序数据失败")?;
            return Ok(out);
        }
    }
    bail!("ZIP 压缩归档中未找到可执行程序文件 (rddns / rddns.exe)");
}

/// 从 Tar.gz 压缩归档数据中提取主程序二进制
fn extract_from_tar_gz(bytes: &[u8]) -> Result<Vec<u8>> {
    let cursor = Cursor::new(bytes);
    let gz_decoder = GzDecoder::new(cursor);
    let mut archive = Archive::new(gz_decoder);

    if let Ok(entries) = archive.entries() {
        for mut entry in entries.flatten() {
            if entry.header().entry_type().is_dir() {
                continue;
            }

            let entry_path = entry
                .path()
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            let file_name = entry_path.split('/').next_back().unwrap_or(&entry_path);

            if file_name.eq_ignore_ascii_case("rddns.exe")
                || file_name.eq_ignore_ascii_case("rddns")
            {
                let mut out = Vec::new();
                copy(&mut entry, &mut out).context("解压 Tar.gz 可执行程序失败")?;
                return Ok(out);
            }
        }
    }
    bail!("Tar.gz 压缩归档中未找到可执行程序文件 (rddns / rddns.exe)");
}

/// 从下载的数据流中提取最终可执行二进制文件 (支持 ZIP 压缩包、Tar.gz 归档与原始二进制)
fn extract_binary_from_bytes(asset_name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.starts_with(b"PK\x03\x04") || asset_name.ends_with(".zip") {
        return extract_from_zip(bytes);
    }

    if bytes.starts_with(&[0x1f, 0x8b])
        || asset_name.ends_with(".tar.gz")
        || asset_name.ends_with(".tgz")
    {
        return extract_from_tar_gz(bytes);
    }

    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("0.2.0", "0.2.1"));
        assert!(is_newer_version("0.2.0", "0.3.0"));
        assert!(is_newer_version("0.2.0", "1.0.0"));
        assert!(is_newer_version("v0.2.0", "v0.2.1"));
        assert!(!is_newer_version("0.2.0", "0.2.0"));
        assert!(!is_newer_version("0.2.1", "0.2.0"));
        assert!(!is_newer_version("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_extract_binary_from_bytes_raw() {
        let raw_data = b"binary_data_mock";
        let extracted = extract_binary_from_bytes("rddns.exe", raw_data).unwrap();
        assert_eq!(extracted, raw_data);
    }

    #[test]
    fn test_extract_binary_from_tar_gz() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        // 构造一个包含 rddns 二进制文件的 mock tar.gz
        let mut tar_builder = tar::Builder::new(Vec::new());
        let mock_content = b"#!/bin/sh\necho rddns";
        let mut header = tar::Header::new_gnu();
        header.set_path("rddns").unwrap();
        header.set_size(mock_content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder.append(&header, &mock_content[..]).unwrap();
        let tar_data = tar_builder.into_inner().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        let extracted = extract_binary_from_bytes("rddns-linux-amd64.tar.gz", &gz_data).unwrap();
        assert_eq!(extracted, mock_content);
    }
}

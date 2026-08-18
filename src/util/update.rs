use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

const GITHUB_API_LATEST: &str = "https://api.github.com/repos/mangerle/rddns/releases/latest";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub current_version: String,
    pub latest_version: String,
    pub has_update: bool,
    pub release_url: String,
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
pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let clean_v = |v: &str| -> Vec<u64> {
        v.trim()
            .trim_start_matches('v')
            .trim_start_matches('V')
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
pub async fn check_version() -> Result<VersionInfo, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();

    let client = crate::util::http::create_http_client_builder()
        .timeout(Duration::from_secs(10))
        .user_agent(format!("RDDNS-Updater/v{}", current_version))
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

    let resp = client
        .get(GITHUB_API_LATEST)
        .send()
        .await
        .map_err(|e| format!("连接 GitHub API 失败: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("GitHub API 响应异常: HTTP {}", resp.status()));
    }

    let release: GithubRelease = resp
        .json()
        .await
        .map_err(|e| format!("解析 Release 信息失败: {}", e))?;

    let latest_ver_clean = release.tag_name.trim_start_matches('v').to_string();
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

/// 执行原地一键热升级（下载最新发布包 -> 解压 -> 安全备份替换 -> 重启进程）
pub async fn upgrade_self() -> Result<(), String> {
    tracing::info!(
        "🔍 正在检查最新发布版本并准备原地自更新 (当前版本: v{})...",
        env!("CARGO_PKG_VERSION")
    );

    let current_version = env!("CARGO_PKG_VERSION");
    let client = crate::util::http::create_http_client_builder()
        .timeout(Duration::from_secs(60))
        .user_agent(format!("RDDNS-Updater/v{}", current_version))
        .build()
        .map_err(|e| format!("创建 HTTP 客户端失败: {}", e))?;

    let resp = client
        .get(GITHUB_API_LATEST)
        .send()
        .await
        .map_err(|e| format!("获取 Release 下载列表失败: {}", e))?;

    let release: GithubRelease = resp
        .json()
        .await
        .map_err(|e| format!("解析 Release 资产失败: {}", e))?;

    let target_os = env::consts::OS;
    let target_arch = env::consts::ARCH;

    // 匹配最适合当前系统的 Release 资产
    let matched_asset = release.assets.iter().find(|a| {
        let name = a.name.to_lowercase();
        let os_match = match target_os {
            "windows" => name.contains("windows") || name.ends_with(".exe"),
            "linux" => name.contains("linux"),
            "macos" => name.contains("darwin") || name.contains("macos") || name.contains("apple"),
            _ => false,
        };
        let arch_match = match target_arch {
            "x86_64" => name.contains("x86_64") || name.contains("amd64") || name.contains("x64"),
            "aarch64" => name.contains("aarch64") || name.contains("arm64"),
            "arm" => name.contains("armv7") || name.contains("arm"),
            _ => true,
        };
        os_match && arch_match
    });

    let asset = match matched_asset {
        Some(a) => a,
        None => {
            return Err(format!(
                "未在 Release 中找到适配当前系统架构 ({}-{}) 的安装包，请手动访问: {}",
                target_os, target_arch, release.html_url
            ));
        }
    };

    println!("📥 正在下载更新文件 [{}]...", asset.name);
    let download_resp = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .map_err(|e| format!("下载安装包失败: {}", e))?;

    if !download_resp.status().is_success() {
        return Err(format!("下载失败，HTTP 状态码: {}", download_resp.status()));
    }

    let raw_bytes = download_resp
        .bytes()
        .await
        .map_err(|e| format!("读取下载数据失败: {}", e))?;

    let binary_bytes = extract_binary_from_bytes(&asset.name, &raw_bytes)?;

    let current_exe = env::current_exe().map_err(|e| format!("获取当前程序路径失败: {}", e))?;
    let backup_exe: PathBuf = if let Some(ext) = current_exe.extension() {
        current_exe.with_extension(format!("{}.old", ext.to_string_lossy()))
    } else {
        current_exe.with_extension("old")
    };

    if backup_exe.exists() {
        let _ = fs::remove_file(&backup_exe);
    }

    println!("🔄 正在执行二进制文件热替换...");
    fs::rename(&current_exe, &backup_exe)
        .map_err(|e| format!("备份当前运行程序失败 (可能缺少管理员写入权限): {}", e))?;

    // 将解压/提取的新二进制文件写入当前程序路径
    let write_res = (|| -> Result<(), std::io::Error> {
        let mut file = fs::File::create(&current_exe)?;
        file.write_all(&binary_bytes)?;
        file.flush()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&current_exe)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&current_exe, perms)?;
        }

        Ok(())
    })();

    if let Err(err) = write_res {
        // 回滚备份
        let _ = fs::rename(&backup_exe, &current_exe);
        return Err(format!("写入新版本失败，已恢复原版本: {}", err));
    }

    println!("==========================================");
    println!("🎉 RDDNS 成功更新至最新版本 {}！", release.tag_name);
    println!("📌 请重启程序或服务以使更新完全生效。");
    println!("==========================================");

    Ok(())
}

/// 从下载的数据流中提取最终可执行二进制文件 (支持 ZIP 压缩包、Tar.gz 归档与原始二进制)
fn extract_binary_from_bytes(asset_name: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    // 1. 处理 ZIP 归档
    if bytes.starts_with(b"PK\x03\x04") || asset_name.ends_with(".zip") {
        let cursor = std::io::Cursor::new(bytes);
        let mut archive =
            zip::ZipArchive::new(cursor).map_err(|e| format!("解析 ZIP 压缩包失败: {}", e))?;

        for i in 0..archive.len() {
            let mut file = archive
                .by_index(i)
                .map_err(|e| format!("读取 ZIP 压缩文件条目失败: {}", e))?;
            let entry_name = file.name().to_string();

            // 寻找主程序文件 (如 rddns 或 rddns.exe)
            if entry_name.ends_with("rddns.exe")
                || entry_name.ends_with("rddns")
                || entry_name == "rddns.exe"
                || entry_name == "rddns"
            {
                let mut out = Vec::new();
                std::io::copy(&mut file, &mut out)
                    .map_err(|e| format!("解压可执行程序数据失败: {}", e))?;
                return Ok(out);
            }
        }
        return Err("ZIP 压缩归档中未找到可执行程序文件 (rddns / rddns.exe)".to_string());
    }

    // 2. 处理 Tar.gz / Tgz 归档 (Gzip 魔数 0x1F, 0x8B)
    if bytes.starts_with(&[0x1f, 0x8b])
        || asset_name.ends_with(".tar.gz")
        || asset_name.ends_with(".tgz")
    {
        let cursor = std::io::Cursor::new(bytes);
        let gz_decoder = flate2::read::GzDecoder::new(cursor);
        let mut archive = tar::Archive::new(gz_decoder);

        if let Ok(entries) = archive.entries() {
            for mut entry in entries.flatten() {
                let entry_path = entry
                    .path()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                if entry_path.ends_with("rddns.exe")
                    || entry_path.ends_with("rddns")
                    || entry_path == "rddns.exe"
                    || entry_path == "rddns"
                {
                    let mut out = Vec::new();
                    std::io::copy(&mut entry, &mut out)
                        .map_err(|e| format!("解压 Tar.gz 可执行程序失败: {}", e))?;
                    return Ok(out);
                }
            }
        }
        return Err("Tar.gz 压缩归档中未找到可执行程序文件 (rddns / rddns.exe)".to_string());
    }

    // 若非已知归档，直接作为原始二进制返回
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

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

    let client = reqwest::Client::builder()
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
        return Err(format!(
            "GitHub API 返回错误状态码: {} (可能触发 API 速率限制)",
            resp.status()
        ));
    }

    let release: GithubRelease = resp
        .json()
        .await
        .map_err(|e| format!("解析 Release 信息失败: {}", e))?;

    let clean_latest = release
        .tag_name
        .trim_start_matches('v')
        .trim_start_matches('V')
        .to_string();
    let has_update = is_newer_version(&current_version, &clean_latest);

    Ok(VersionInfo {
        current_version,
        latest_version: clean_latest,
        has_update,
        release_url: release.html_url,
        release_notes: release.body,
    })
}

/// 执行自身在线自更新 (热替换)
pub async fn upgrade_self() -> Result<(), String> {
    println!("🔍 正在检查最新版本发布信息...");
    let info = check_version().await?;

    if !info.has_update {
        println!(
            "✨ 当前已是最新版本 (v{})，无需更新！",
            info.current_version
        );
        return Ok(());
    }

    println!(
        "🚀 检测到新版本 v{} (当前: v{})，正在准备下载更新...",
        info.latest_version, info.current_version
    );

    let current_version = env!("CARGO_PKG_VERSION");
    let client = reqwest::Client::builder()
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

    let bytes = download_resp
        .bytes()
        .await
        .map_err(|e| format!("读取下载数据失败: {}", e))?;

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

    // 将下载的新文件写入当前程序路径
    let write_res = (|| -> Result<(), std::io::Error> {
        let mut file = fs::File::create(&current_exe)?;
        file.write_all(&bytes)?;
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
    println!("🎉 RDDNS 成功更新至最新版本 v{}！", info.latest_version);
    println!("📌 请重启程序或服务以使更新完全生效。");
    println!("==========================================");

    Ok(())
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
}

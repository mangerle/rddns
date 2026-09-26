#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
为 shipup 自动更新系统生成 GitHub Release 的 latest.json 发布清单文件。
本脚本在 GitHub Actions 发布流水线 (release.yml) 的 publish-manifest 任务中运行。
"""

import json
import os
import re
import sys
import urllib.request


def get_release_data(tag_name, repo, token):
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag_name}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "shipup-manifest-generator",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(api_url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return {
            "tagName": data["tag_name"],
            "body": data.get("body", ""),
            "createdAt": data.get("created_at", ""),
            "assets": [
                {
                    "name": a["name"],
                    "url": a.get("browser_download_url", ""),
                    "size": a.get("size", 0),
                }
                for a in data.get("assets", [])
            ],
        }


def fetch_sha256_content(url, token):
    headers = {"User-Agent": "shipup-manifest-generator"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        content = resp.read().decode("utf-8").strip()
        # 提取首个 64 位十六进制哈希值
        match = re.search(r"([a-fA-F0-9]{64})", content)
        if match:
            return match.group(1).lower()
        raise ValueError(f"未能从内容中解析出有效 SHA-256 哈希: {content}")


def main():
    tag_name = os.environ.get("TAG_NAME")
    if not tag_name:
        tag_name = os.environ.get("GITHUB_REF_NAME", "")
    if not tag_name:
        raise ValueError("缺少必要的环境变量 TAG_NAME 或 GITHUB_REF_NAME")

    repo = os.environ.get("GITHUB_REPOSITORY", "mangerle/rddns")
    token = os.environ.get("GITHUB_TOKEN", "")

    print(f"正在为仓库 {repo} 的 Release {tag_name} 构建 shipup 更新清单 (latest.json)...")
    data = get_release_data(tag_name, repo, token)

    clean_version = tag_name.lstrip("vV")
    body = data.get("body", "")
    created_at = data.get("createdAt", "")
    assets = data.get("assets", [])

    # 构建 asset 快速索引
    asset_map = {a["name"]: a for a in assets}

    packages = {}
    for name, asset in asset_map.items():
        # 仅匹配 rddns-<target>.zip 或 rddns-<target>.tar.gz
        match = re.match(r"^rddns-(.+)\.(zip|tar\.gz)$", name)
        if not match:
            continue

        target = match.group(1)
        download_url = asset.get("url") or asset.get("browser_download_url")
        size = asset.get("size", 0)

        # taiki-e/upload-rust-binary-action 生成的校验文件名为 rddns-<target>.sha256
        sha256_name = f"rddns-{target}.sha256"
        if sha256_name not in asset_map:
            # 兼容另一种命名：rddns-<target>.<ext>.sha256
            alt_sha256_name = f"{name}.sha256"
            if alt_sha256_name in asset_map:
                sha256_name = alt_sha256_name
            else:
                print(
                    f"警告: 未找到 {name} 对应的 SHA256 校验文件 ({sha256_name})，跳过该架构",
                    file=sys.stderr,
                )
                continue

        sha256_asset = asset_map[sha256_name]
        sha256_url = sha256_asset.get("url") or sha256_asset.get("browser_download_url")

        print(f"正在获取架构 [{target}] 的 SHA-256 指纹...")
        checksum_hex = fetch_sha256_content(sha256_url, token)

        executable_path = "rddns.exe" if "windows" in target else "rddns"

        packages[target] = {
            "url": download_url,
            "checksum": f"sha256:{checksum_hex}",
            "package_type": "archive",
            "executable_path": executable_path,
            "size": size,
        }

    manifest = {
        "version": clean_version,
        "notes": body,
        "pub_date": created_at,
        "packages": packages,
    }

    output_path = "latest.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    print(f"成功生成清单文件 {output_path}，包含 {len(packages)} 个架构平台配置！")


if __name__ == "__main__":
    main()

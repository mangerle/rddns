use std::fs;
use std::path::Path;

fn main() {
    // 注入编译目标平台 Target Triple，使代码可在编译期精确获取宿主架构
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );

    // 兜底保障：若本地未预先构建前端，自动创建 frontend/dist 占位目录以避免 rust-embed 编译中断
    let dist_dir = Path::new("frontend/dist");
    if !dist_dir.exists() {
        let _ = fs::create_dir_all(dist_dir);
    }
    let placeholder_index = dist_dir.join("index.html");
    if !placeholder_index.exists() {
        let _ = fs::write(
            &placeholder_index,
            b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>rddns</title></head><body><h1>rddns WebUI Placeholder</h1></body></html>",
        );
    }
}

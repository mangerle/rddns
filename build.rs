//! 构建脚本 (build.rs)
//!
//! 负责在编译期向 rustc 注入运行环境参数与构建依赖跟踪配置。

fn main() {
    // 注入编译目标平台 Target Triple，使代码可在编译期精确获取宿主架构
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );

    // 监听前端静态资源目录变动 (P1-23)
    // 强制依赖真实前端产物目录：若 frontend/dist 不存在，rust-embed 会在编译期显式报错阻断，
    // 严禁静默生成空壳占位页面掩盖构建缺失。
    println!("cargo:rerun-if-changed=frontend/dist");
}

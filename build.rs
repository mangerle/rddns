fn main() {
    // 注入编译目标平台 Target Triple，使代码可在编译期精确获取宿主架构
    println!(
        "cargo:rustc-env=TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
}

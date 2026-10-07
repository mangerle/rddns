use super::*;

#[test]
fn test_invalid_service_action() {
    let dummy_path = Path::new("dummy.yaml");
    let res = handle_service_command("invalid_action_xyz", dummy_path);
    assert!(res.is_err());
}

#[test]
fn test_clean_windows_path() {
    let unc_path = Path::new(r"\\?\C:\Program Files\rddns\rddns.exe");
    assert_eq!(
        clean_windows_path(unc_path),
        r"C:\Program Files\rddns\rddns.exe"
    );

    let normal_path = Path::new(r"C:\rddns\rddns.exe");
    assert_eq!(clean_windows_path(normal_path), r"C:\rddns\rddns.exe");
}

#[test]
fn test_decode_output() {
    // 1. 空字节测试
    assert_eq!(decode_output(b""), "");

    // 2. 标准 UTF-8 中文测试
    let utf8_bytes = "RDDNS 服务运行正常".as_bytes();
    assert_eq!(decode_output(utf8_bytes), "RDDNS 服务运行正常");

    // 3. GBK 编码转换测试
    #[cfg(windows)]
    {
        unsafe extern "system" {
            fn WideCharToMultiByte(
                code_page: u32,
                flags: u32,
                wide_char_str: *const u16,
                wide_char_len: i32,
                multi_byte_str: *mut u8,
                multi_byte_len: i32,
                default_char: *const u8,
                used_default_char: *mut i32,
            ) -> i32;
        }
        let original = "拒绝访问。提示：注册 Windows 系统服务需要管理员权限。";
        let wide: Vec<u16> = original.encode_utf16().collect();
        let len = unsafe {
            WideCharToMultiByte(
                936,
                0,
                wide.as_ptr(),
                wide.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert!(len > 0);
        let mut gbk_bytes = vec![0u8; len as usize];
        unsafe {
            WideCharToMultiByte(
                936,
                0,
                wide.as_ptr(),
                wide.len() as i32,
                gbk_bytes.as_mut_ptr(),
                len,
                std::ptr::null(),
                std::ptr::null_mut(),
            );
        }
        assert_eq!(decode_output(&gbk_bytes), original);
    }
}

#[test]
fn test_build_sc_create_command() {
    let exe = Path::new(r"C:\Program Files\rddns\rddns.exe");
    let cfg = Path::new(r"C:\Program Files\rddns\config.json");
    let cmd = build_sc_create_command("rddns", exe, cfg);
    let cmd_str = format!("{:?}", cmd);

    // 验证 sc.exe 指令结构与独立键值参数
    assert!(cmd_str.contains("\"sc.exe\""));
    assert!(cmd_str.contains("\"create\""));
    assert!(cmd_str.contains("\"rddns\""));
    assert!(cmd_str.contains("\"binPath=\""));
    assert!(cmd_str.contains("\"start=\""));
    assert!(cmd_str.contains("\"auto\""));
    assert!(cmd_str.contains("\"DisplayName=\""));
    assert!(cmd_str.contains(
        r#""C:\\Program Files\\rddns\\rddns.exe\" -c \"C:\\Program Files\\rddns\\config.json\" --windows-service"#
    ));
}

#[test]
fn test_escape_systemd_exec_arg_prevents_unit_injection() {
    // 回归用例 (P1-10)：配置文件路径由用户通过 -c 参数完全控制。
    // systemd 的引号解析不处理嵌入换行，恶意路径可注入任意 unit 指令
    // 实现提权（如注入 User=root / ExecStartPre=）。
    let malicious = "/tmp/a\nUser=root\nExecStartPre=/bin/sh -c 'id > /tmp/pwn'\nExecStart=";

    let escaped = escape_systemd_exec_arg(malicious);

    // 核心不变式：结果必须为单行，不含任何换行符。
    // 这正是注入被阻断的原理——systemd 按行解析 unit 文件，
    // 换行一旦消失，后续文本就只能作为 ExecStart 参数的一部分，
    // 而无法成为独立的 User= / ExecStartPre= 指令。
    assert!(
        !escaped.contains('\n') && !escaped.contains('\r'),
        "转义结果绝不可包含换行符，否则可注入 unit 指令: {:?}",
        escaped
    );
    // 注入内容可作为路径文本残留（无害），但绝不可产生新的行结构。
    // 逐行校验每一行都不含 unit 指令语法。
    for line in escaped.lines() {
        let trimmed = line.trim_start();
        assert!(
            !trimmed.starts_with("User=")
                && !trimmed.starts_with("ExecStartPre=")
                && !trimmed.starts_with("ExecStart="),
            "转义后不得出现独立的 unit 指令行，实际行: {:?}",
            line
        );
    }
    // 其余内容仍应保留（剔除控制字符而非整体丢弃路径）
    assert!(
        escaped.contains("/tmp/a"),
        "合法路径部分应被保留: {:?}",
        escaped
    );
    assert!(
        escaped.contains("User=root"),
        "注入文本可作为路径内容残留，但因无换行而不构成指令: {:?}",
        escaped
    );
}

#[test]
fn test_escape_systemd_exec_arg_escapes_quotes_and_specials() {
    // 双引号与反斜杠必须转义，否则可提前闭合引号改变解析结构
    assert_eq!(
        escape_systemd_exec_arg(r#"/path/with"quote"#),
        r#"/path/with\"quote"#
    );
    assert_eq!(
        escape_systemd_exec_arg(r"/path/with\backslash"),
        r"/path/with\\backslash"
    );
    // systemd 将 $ 与 % 用作变量/规格展开标记，需转义防注入
    assert_eq!(escape_systemd_exec_arg("/path/$USER"), r"/path/\$USER");
    assert_eq!(escape_systemd_exec_arg("/path/%i"), r"/path/\%i");
    // 空格与中文路径属合法内容，不应被破坏
    assert_eq!(
        escape_systemd_exec_arg("/opt/my apps/我的程序"),
        "/opt/my apps/我的程序"
    );
}

#[test]
fn test_escape_xml_text_prevents_plist_corruption() {
    // 回归用例 (P1-10)：macOS 路径可合法包含 & 与 <，直接嵌入会产生
    // 格式错误的 plist，恶意路径还可注入额外 XML 节点改写服务定义。
    let escaped = escape_xml_text("/Applications/A&B/rddns");
    assert_eq!(escaped, "/Applications/A&amp;B/rddns");

    // 节点注入尝试
    let injection = "/tmp/x</string></dict><dict><key>Label</key><string>evil</string>";
    let esc = escape_xml_text(injection);
    assert!(!esc.contains('<'));
    assert!(!esc.contains('>'));

    // 四类 XML 保留字符全覆盖
    assert_eq!(
        escape_xml_text(r#"<a href="x">&'</a>"#),
        "&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;"
    );
}

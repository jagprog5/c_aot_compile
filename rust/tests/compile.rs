use c_aot_compile::{compile, Error, Library};

// windows toolchains other than mingw gcc only export what is marked
const EXPORT: &str = if cfg!(windows) {
    "__declspec(dllexport) "
} else {
    ""
};

/// C source defining `int f(void) { return <body> }`, exported.
fn f_source(body: &str) -> String {
    format!("{EXPORT}int f(void) {{ return {body}; }}")
}

fn call_f(lib: &Library) -> i32 {
    // SAFETY: every test source defines `int f(void)`.
    let f = unsafe { lib.get::<extern "C" fn() -> i32>(c"f") }.expect("f");
    f()
}

#[test]
fn two_libraries_loaded_at_once_do_not_alias() {
    let a = compile(&f_source("1"), None, &[]).unwrap();
    let b = compile(&f_source("2"), None, &[]).unwrap();
    assert_eq!(call_f(&a), 1);
    assert_eq!(call_f(&b), 2);
}

#[test]
fn compile_error_carries_compiler_stderr() {
    match compile(&format!("{EXPORT}int f(void){{ syntax error }}"), None, &[]) {
        Err(Error::Compiler { stderr, .. }) => assert!(stderr.contains("error"), "{stderr}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn missing_compiler() {
    assert!(matches!(
        compile("", Some("/nonexistent/cc"), &[]),
        Err(Error::Io { .. })
    ));
}

#[test]
fn huge_input_with_dying_compiler_does_not_hang() {
    let big = "x".repeat(4 << 20);
    // exits at once without reading stdin: "false" via PATH (it's /bin/false on
    // linux, /usr/bin/false on macos); on windows gcc with a bad flag
    let (compiler, args): (&str, &[&str]) = if cfg!(windows) {
        ("gcc", &["-fno-such-flag-xyz"])
    } else {
        ("false", &[])
    };
    match compile(&big, Some(compiler), args) {
        Err(Error::Compiler { status, .. }) => assert!(status.contains('1'), "{status}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn extra_args_are_passed() {
    let lib = compile(&f_source("VALUE"), None, &["-DVALUE=7"]).unwrap();
    assert_eq!(call_f(&lib), 7);
}

#[test]
fn works_from_many_threads() {
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                call_f(&compile(&f_source(&i.to_string()), None, &[]).unwrap())
            })
        })
        .collect();
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), i as i32);
    }
}

#[test]
fn missing_symbol_is_none() {
    let lib = compile(&f_source("1"), None, &[]).unwrap();
    assert!(unsafe { lib.get::<extern "C" fn()>(c"nope") }.is_none());
}

#[test]
fn library_is_usable_after_other_libraries_drop() {
    let a = compile(&f_source("1"), None, &[]).unwrap();
    drop(compile(&f_source("2"), None, &[]).unwrap());
    assert_eq!(call_f(&a), 1);
}

#[test]
fn compiler_output_is_not_captured_as_result() {
    // warnings go to stderr, but a successful compile is still ok
    let lib = compile(&format!("{EXPORT}int f(void){{ int unused; return 3; }}"), None, &["-Wall"]).unwrap();
    assert_eq!(call_f(&lib), 3);
}

#[test]
fn source_with_non_ascii_and_large_size() {
    let mut src = f_source("4");
    src.push_str("\n/* héllo wörld */\n");
    src.push_str(&"/* padding */\n".repeat(200_000)); // ~2.8 MB
    assert_eq!(call_f(&compile(&src, None, &[]).unwrap()), 4);
}

#[test]
fn args_with_spaces_and_quotes_survive() {
    let lib = compile(
        &format!("{EXPORT}const char* f(void) {{ return MSG; }}"),
        None,
        &[r#"-DMSG="a b \"c\" d\\""#],
    )
    .unwrap();
    // SAFETY: f is `const char* f(void)`.
    let f = unsafe { lib.get::<extern "C" fn() -> *const std::ffi::c_char>(c"f") }.unwrap();
    let msg = unsafe { std::ffi::CStr::from_ptr(f()) };
    assert_eq!(msg.to_str().unwrap(), "a b \"c\" d\\");
}

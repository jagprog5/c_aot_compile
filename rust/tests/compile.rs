use c_aot_compile::{compile, Error, Library};

fn call_f(lib: &Library) -> i32 {
    // SAFETY: every test source defines `int f(void)`.
    let f = unsafe { lib.get::<extern "C" fn() -> i32>(c"f") }.expect("f");
    f()
}

#[test]
fn two_libraries_loaded_at_once_do_not_alias() {
    let a = compile("int f(void){return 1;}", None, &[]).unwrap();
    let b = compile("int f(void){return 2;}", None, &[]).unwrap();
    assert_eq!(call_f(&a), 1);
    assert_eq!(call_f(&b), 2);
}

#[test]
fn compile_error_carries_compiler_stderr() {
    match compile("int f(void){ syntax error }", None, &[]) {
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
    assert!(matches!(
        compile(&big, Some("/bin/false"), &[]),
        Err(Error::Compiler { .. })
    ));
}

#[test]
fn extra_args_are_passed() {
    let lib = compile("int f(void){return VALUE;}", None, &["-DVALUE=7"]).unwrap();
    assert_eq!(call_f(&lib), 7);
}

#[test]
fn works_from_many_threads() {
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                call_f(&compile(&format!("int f(void){{return {i};}}"), None, &[]).unwrap())
            })
        })
        .collect();
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), i as i32);
    }
}

#[test]
fn missing_symbol_is_none() {
    let lib = compile("int f(void){return 1;}", None, &[]).unwrap();
    assert!(unsafe { lib.get::<extern "C" fn()>(c"nope") }.is_none());
}

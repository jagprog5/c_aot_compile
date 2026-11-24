//! Own test binary: it changes the temp directory environment variable, which
//! would race with other tests in the same process.

use c_aot_compile::compile;

#[test]
fn temp_directory_is_removed_after_use() {
    let base = std::env::temp_dir().join(format!("c_aot_compile_test_{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    // unix reads TMPDIR, windows TMP
    let var = if cfg!(windows) { "TMP" } else { "TMPDIR" };
    // SAFETY: this is the only test in this process.
    unsafe { std::env::set_var(var, &base) };

    let entries = || std::fs::read_dir(&base).unwrap().count();

    // a failed compile leaves nothing behind
    assert!(compile("int f(void){ syntax error }", None, &[]).is_err());
    assert_eq!(entries(), 0);

    // a successful one leaves nothing once unloaded (on unix, not even while
    // loaded)
    let export = if cfg!(windows) { "__declspec(dllexport) " } else { "" };
    let lib = compile(&format!("{export}int f(void){{return 1;}}"), None, &[]).unwrap();
    if cfg!(unix) {
        assert_eq!(entries(), 0);
    }
    drop(lib);
    assert_eq!(entries(), 0);

    let _ = std::fs::remove_dir(&base);
}

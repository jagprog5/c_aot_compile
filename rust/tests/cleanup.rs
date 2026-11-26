//! Own test binary: it changes the temp directory environment variable, which
//! would race with other tests in the same process.

use c_aot_compile::{memory_first_candidates, Candidate, Compiler};

fn compiler() -> Compiler {
    let mut candidates = vec![Candidate::env("C_AOT_TEST_COMPILER")];
    // the preset's programs: this test is about their temp directory
    candidates.extend(memory_first_candidates(None).into_iter().filter(|c| !matches!(c, Candidate::TccLibrary { .. })));
    Compiler::resolve(&candidates).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn temp_directory_is_removed_after_use() {
    let base = std::env::temp_dir().join(format!("c_aot_compile_test_{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    // unix reads TMPDIR, windows TMP
    let var = if cfg!(windows) { "TMP" } else { "TMPDIR" };
    // resolved first: its test compile would otherwise land in the directory
    let compiler = compiler();
    // SAFETY: this is the only test in this process.
    unsafe { std::env::set_var(var, &base) };

    let entries = || std::fs::read_dir(&base).unwrap().count();

    // a failed compile leaves nothing behind
    assert!(compiler.compile("int f(void){ syntax error }").is_err());
    assert_eq!(entries(), 0);

    // a successful one leaves nothing once unloaded (on unix, not even while
    // loaded)
    let export = if cfg!(windows) { "__declspec(dllexport) " } else { "" };
    let lib = compiler.compile(&format!("{export}int f(void){{return 1;}}")).unwrap();
    if cfg!(unix) {
        assert_eq!(entries(), 0);
    }
    drop(lib);
    assert_eq!(entries(), 0);

    let _ = std::fs::remove_dir(&base);
}

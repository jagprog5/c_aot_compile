use c_aot_compile::{memory_first_candidates, Candidate, Compiler, CompilerKind, Error, Library};

// windows toolchains other than mingw gcc only export what is marked
const EXPORT: &str = if cfg!(windows) {
    "__declspec(dllexport) "
} else {
    ""
};

/// The compiler under test, resolved once: `C_AOT_TEST_COMPILER` (a name or
/// path; skipped when unset or empty), else the memory first preset's
/// programs: these tests are for one (libtcc has its own, and the system's may
/// be installed).
fn compiler() -> &'static Compiler {
    static COMPILER: std::sync::OnceLock<Compiler> = std::sync::OnceLock::new();
    COMPILER.get_or_init(|| {
        let mut candidates = vec![Candidate::env("C_AOT_TEST_COMPILER")];
        candidates.extend(memory_first_candidates(None).into_iter().filter(|c| !matches!(c, Candidate::TccLibrary { .. })));
        Compiler::resolve(&candidates).unwrap_or_else(|e| panic!("{e}"))
    })
}

fn compile(source: &str) -> Result<Library, Error> {
    compiler().compile(source)
}

/// Compiles with a compiler that is the one under test, with these args on its candidate.
fn compile_with_args(source: &str, args: &[&str]) -> Result<Library, Error> {
    let candidate = Candidate::executable_with_args(compiler().path(), args.iter().copied());
    Compiler::resolve(&[candidate]).unwrap_or_else(|e| panic!("{e}")).compile(source)
}

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
    let a = compile(&f_source("1")).unwrap();
    let b = compile(&f_source("2")).unwrap();
    assert_eq!(call_f(&a), 1);
    assert_eq!(call_f(&b), 2);
}

#[test]
fn compile_error_carries_compiler_stderr() {
    match compile(&format!("{EXPORT}int f(void){{ syntax error }}")) {
        Err(Error::Compiler { stderr, .. }) => assert!(stderr.contains("error"), "{stderr}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn resolution_reports_each_candidate() {
    // SAFETY: only this test touches this variable.
    unsafe { std::env::set_var("C_AOT_TEST_ARGS", "gcc -O2") };
    let err = Compiler::resolve(&[
        Candidate::executable("/nonexistent/cc"),
        Candidate::env("C_AOT_TEST_SURELY_UNSET"),
        Candidate::executable("./some/where"),
        Candidate::executable("no-such-compiler-xyz"),
        Candidate::env("C_AOT_TEST_ARGS"),
        Candidate::tcc_library("/nonexistent/libtcc.so"),
    ])
    .unwrap_err();
    assert_eq!(err.attempts.len(), 6);
    let text = err.to_string();
    for expected in ["/nonexistent/cc", "not set", "no such executable file", "not found in PATH", "arguments aren't supported", "libtcc"] {
        assert!(text.contains(expected), "{expected} in:\n{text}");
    }
    assert!(Compiler::resolve(&[]).unwrap_err().to_string().contains("no candidates"));
}

#[test]
fn resolution_falls_through_to_a_working_candidate() {
    let mut candidates = vec![Candidate::executable("/nonexistent/cc")];
    candidates.extend(memory_first_candidates(None));
    let c = Compiler::resolve(&candidates).unwrap();
    assert!(c.candidate() >= 1);
    // the system's libtcc may win, if it is installed
    assert!(c.kind() == CompilerKind::Tcc || c.path().is_absolute());
}

#[test]
fn huge_input_with_dying_compiler_does_not_hang() {
    let big = "x".repeat(4 << 20);
    // exits at once without reading stdin: "false" via PATH (it's /bin/false on
    // linux, /usr/bin/false on macos); on windows the compiler under test with a bad flag
    let (compiler, args): (std::path::PathBuf, &[&str]) = if cfg!(windows) {
        (compiler().path().to_path_buf(), &["--no-such-flag-xyz"])
    } else {
        (std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|d| d.join("false"))
            .find(|p| p.exists())
            .expect("false in PATH"), &[])
    };
    match c_aot_compile::__compile_with_executable(&compiler, args, &big) {
        Err(Error::Compiler { status, .. }) => assert!(status.contains('1'), "{status}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn extra_args_are_passed() {
    let lib = compile_with_args(&f_source("VALUE"), &["-DVALUE=7"]).unwrap();
    assert_eq!(call_f(&lib), 7);
}

#[test]
fn works_from_many_threads() {
    let threads: Vec<_> = (0..8)
        .map(|i| {
            std::thread::spawn(move || {
                call_f(&compile(&f_source(&i.to_string())).unwrap())
            })
        })
        .collect();
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), i as i32);
    }
}

#[test]
fn missing_symbol_is_none() {
    let lib = compile(&f_source("1")).unwrap();
    assert!(unsafe { lib.get::<extern "C" fn()>(c"nope") }.is_none());
}

#[test]
fn library_is_usable_after_other_libraries_drop() {
    let a = compile(&f_source("1")).unwrap();
    drop(compile(&f_source("2")).unwrap());
    assert_eq!(call_f(&a), 1);
}

#[test]
fn compiler_output_is_not_captured_as_result() {
    // warnings go to stderr, but a successful compile is still ok
    let lib = compile_with_args(&format!("{EXPORT}int f(void){{ int unused; return 3; }}"), &["-Wall"]).unwrap();
    assert_eq!(call_f(&lib), 3);
}

#[test]
fn source_with_non_ascii_and_large_size() {
    let mut src = f_source("4");
    src.push_str("\n/* héllo wörld */\n");
    src.push_str(&"/* padding */\n".repeat(200_000)); // ~2.8 MB
    assert_eq!(call_f(&compile(&src).unwrap()), 4);
}

#[test]
fn args_with_spaces_and_quotes_survive() {
    let lib = compile_with_args(
        &format!("{EXPORT}const char* f(void) {{ return MSG; }}"),
        &[r#"-DMSG="a b \"c\" d\\""#],
    )
    .unwrap();
    // SAFETY: f is `const char* f(void)`.
    let f = unsafe { lib.get::<extern "C" fn() -> *const std::ffi::c_char>(c"f") }.unwrap();
    let msg = unsafe { std::ffi::CStr::from_ptr(f()) };
    assert_eq!(msg.to_str().unwrap(), "a b \"c\" d\\");
}

// ---- tcc: runs only if C_AOT_TEST_TCC_DIR holds a built libtcc (and its
// libtcc1.a and include/)

fn tcc_library() -> Option<std::path::PathBuf> {
    let dir = std::env::var_os("C_AOT_TEST_TCC_DIR").filter(|d| !d.is_empty())?;
    let name = if cfg!(windows) {
        "libtcc.dll"
    } else if cfg!(target_os = "macos") {
        "libtcc.dylib"
    } else {
        "libtcc.so"
    };
    Some(std::path::Path::new(&dir).join(name))
}

fn tcc() -> Option<Compiler> {
    let library = tcc_library()?;
    Some(Compiler::resolve(&[Candidate::tcc_library(library)]).unwrap_or_else(|e| panic!("{e}")))
}

#[test]
fn tcc_compiles_in_memory_and_finds_symbols() {
    let Some(tcc) = tcc() else { return };
    assert_eq!(tcc.kind(), CompilerKind::Tcc);
    let a = tcc.compile("#include <stddef.h>\nint f(void){return 7;}").unwrap();
    let b = tcc.compile("int f(void){return 2;}").unwrap();
    assert_eq!(call_f(&a), 7);
    assert_eq!(call_f(&b), 2);
    assert!(unsafe { a.get::<extern "C" fn()>(c"nope") }.is_none());
    drop(tcc); // a library keeps what it needs alive
    assert_eq!(call_f(&a), 7);
}

#[test]
fn tcc_errors_are_reported_not_fatal() {
    let Some(tcc) = tcc() else { return };
    match tcc.compile("int f(void){ syntax error }") {
        Err(Error::Tcc(text)) => assert!(text.contains("error"), "{text}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn tcc_resolution_rejects_what_is_not_libtcc() {
    if tcc_library().is_none() {
        return;
    }
    // loads, but isn't libtcc
    let not_tcc = if cfg!(windows) { "kernel32.dll" } else if cfg!(target_os = "macos") { "libSystem.dylib" } else { "libm.so.6" };
    let err = Compiler::resolve(&[Candidate::tcc_library(not_tcc)]).unwrap_err();
    assert!(err.to_string().contains("not a usable libtcc"), "{err}");
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn tcc_bundle_works_after_being_copied_elsewhere() {
    let Some(library) = tcc_library() else { return };
    // the library and its support files are copied together to another folder:
    // the files next to the library are found there, wherever it is
    let moved = std::env::temp_dir().join(format!("c_aot_tcc_moved_{}", std::process::id()));
    copy_dir(library.parent().unwrap(), &moved);
    let tcc = Compiler::resolve(&[Candidate::tcc_library(moved.join(library.file_name().unwrap()))]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(call_f(&tcc.compile("#include <stddef.h>\nint f(void){return 5;}").unwrap()), 5);
    drop(tcc);
    let _ = std::fs::remove_dir_all(&moved);
}

#[test]
fn tcc_works_from_many_threads() {
    let Some(tcc) = tcc() else { return };
    let threads: Vec<_> = (0..8)
        .map(|i| {
            let tcc = tcc.clone();
            std::thread::spawn(move || call_f(&tcc.compile(&format!("int f(void){{return {i};}}")).unwrap()))
        })
        .collect();
    for (i, t) in threads.into_iter().enumerate() {
        assert_eq!(t.join().unwrap(), i as i32);
    }
}

#[cfg(all(target_os = "linux", not(feature = "no_memory_files")))]
#[test]
fn reused_fd_number_does_not_alias() {
    // -z nodelete: dropping the first library leaves it mapped, still known to
    // the loader under the name it was opened with. The next library gets the
    // same fd number, and must not be mistaken for it.
    let keep = ["-Wl,-z,nodelete"];
    let a = compile_with_args(&f_source("1"), &keep).unwrap();
    assert_eq!(call_f(&a), 1);
    drop(a);
    let b = compile_with_args(&f_source("2"), &keep).unwrap();
    assert_eq!(call_f(&b), 2);
}

#[test]
fn memory_first_candidates_order() {
    use std::path::Path;
    let tcc_program = Candidate::executable("tcc");
    let cc = Candidate::env("CC");
    let tcc = Candidate::tcc_library("/some/libtcc.so");
    let on_linux = cfg!(target_os = "linux");

    let system = Candidate::tcc_library(if cfg!(windows) {
        "libtcc.dll"
    } else if cfg!(target_vendor = "apple") {
        "libtcc.dylib"
    } else {
        "libtcc.so"
    });

    // without your libtcc, the system's is the only one
    let none = memory_first_candidates(None);
    let libtccs: Vec<usize> = (0..none.len()).filter(|&i| matches!(none[i], Candidate::TccLibrary { .. })).collect();
    assert_eq!(libtccs.len(), 1);
    let at = libtccs[0];
    assert_eq!(none[at], system);
    // yours, then the system's right after it, wherever they go
    let with = memory_first_candidates(Some(Path::new("/some/libtcc.so")));
    assert_eq!(with.len(), none.len() + 1);
    assert_eq!((&with[at], &with[at + 1]), (&tcc, &system));

    if cfg!(all(target_os = "linux", not(feature = "no_memory_files"))) {
        // memory files: the system compilers keep nothing on disk, so $CC and
        // they come first, then the libtccs, then tcc as a program, last
        assert_eq!(none[0], cc);
        assert_eq!(with[0], cc);
        assert_eq!(at + 2, with.len() - 1);
        assert_eq!(with.last(), Some(&tcc_program));
    } else {
        // no memory files: libtcc keeps nothing on disk, so they come first, before $CC
        assert_eq!(at, 0);
        if on_linux {
            // tcc as a program stays last on Linux (its libraries may not load there)
            assert_eq!(with[2], cc);
            assert_eq!(none[1], cc);
            assert_eq!(with.last(), Some(&tcc_program));
        } else {
            // elsewhere: tcc as a program right after the libtccs (it compiles fastest), then $CC
            assert_eq!(with[2], tcc_program);
            assert_eq!(with[3], cc);
            assert_eq!((&none[1], &none[2]), (&tcc_program, &cc));
        }
    }
    // tcc as a program is in the list exactly once, wherever it is
    assert_eq!(with.iter().filter(|c| **c == tcc_program).count(), 1);
}

#[test]
fn fast_candidates_try_fast_args_then_plain_and_put_tcc_last() {
    use c_aot_compile::{fast_candidates, FAST_ARGS};
    use std::path::Path;
    let list = fast_candidates(None);
    assert_eq!(list.len(), 9); // $CC and three programs, each with the fast args and then without, then tcc
    assert_eq!(list.last(), Some(&Candidate::executable("tcc")), "last, everywhere: it doesn't optimize");
    for pair in list[..list.len() - 1].chunks(2) {
        match (&pair[0], &pair[1]) {
            (Candidate::Executable { program: a, args: fast }, Candidate::Executable { program: b, args: plain }) => {
                assert_eq!(a, b);
                assert_eq!(fast, FAST_ARGS);
                assert!(plain.is_empty());
            }
            (Candidate::Env { variable: a, args: fast }, Candidate::Env { variable: b, args: plain }) => {
                assert_eq!((a, b), (&"CC".to_owned(), &"CC".to_owned()));
                assert_eq!(fast, FAST_ARGS);
                assert!(plain.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(FAST_ARGS[0], "-O2");

    // libtcc, if given, comes just before it
    let with = fast_candidates(Some(Path::new("/some/libtcc.so")));
    assert_eq!(with.len(), list.len() + 1);
    assert_eq!(with[with.len() - 2], Candidate::tcc_library("/some/libtcc.so"));
    assert_eq!(with.last(), Some(&Candidate::executable("tcc")));

    // on this machine it resolves, with the fast args if the compiler takes them
    let compiler = Compiler::resolve_fast(None).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(compiler.kind(), CompilerKind::Executable);
}

#[cfg(unix)]
mod candidate_args {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh directory with an executable shell script in it.
    fn script(name: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("c_aot_args_{name}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cc.sh");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, path)
    }

    #[test]
    fn a_candidates_args_come_after_the_fixed_ones() {
        let dir = std::env::temp_dir().join(format!("c_aot_args_order_{}", std::process::id()));
        let record = dir.join("record");
        let (dir, cc) = script("order", &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexec cc \"$@\"\n", record.display()));
        let compiler = Compiler::resolve(&[Candidate::executable_with_args(&cc, ["-DFROM_CANDIDATE=1"])]).unwrap_or_else(|e| panic!("{e}"));
        let lib = compiler.compile(&format!("{EXPORT}int f(void){{return FROM_CANDIDATE;}}")).unwrap();
        assert_eq!(call_f(&lib), 1);
        let seen = std::fs::read_to_string(&record).unwrap();
        // the fixed core ends with "-" (stdin): then the candidate's
        assert!(seen.ends_with("\n-\n-DFROM_CANDIDATE=1\n"), "{seen}");
        assert!(seen.contains("-O1\n"), "the default optimization is still there, before them: {seen}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_compiler_that_rejects_the_candidates_args_falls_through_to_the_next_candidate() {
        let (dir, picky) = script(
            "picky",
            "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -march=native ] && { echo 'unknown option' >&2; exit 1; }; done\nexec cc \"$@\"\n",
        );
        let list = [
            Candidate::executable_with_args(&picky, ["-O2", "-march=native"]),
            Candidate::executable(&picky),
        ];
        let compiler = Compiler::resolve(&list).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(compiler.candidate(), 1, "the first was tried, and failed the test program");

        // and if nothing is left, the report says what the first one said
        let err = Compiler::resolve(&list[..1]).unwrap_err();
        assert!(err.to_string().contains("unknown option"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[test]
fn tcc_configure_sets_options_on_the_state_directly() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let Some(library) = tcc_library() else { return };
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    let candidate = Candidate::tcc_library_with(library, move |tcc| {
        counted.fetch_add(1, Ordering::SeqCst);
        let state = tcc.state.as_ptr();
        // SAFETY: the state is live, the strings are NUL terminated.
        unsafe {
            (tcc.api.define_symbol)(state, c"FROM_DEFINE".as_ptr(), c"4".as_ptr());
            if let Some(set_options) = tcc.api.set_options {
                set_options(state, c"-DFROM_OPTIONS=5".as_ptr());
            }
        }
        Ok(())
    });
    let compiler = Compiler::resolve(&[candidate]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the test program");
    let lib = compiler
        .compile("int f(void){return FROM_DEFINE * 10 + FROM_OPTIONS;}")
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(call_f(&lib), 45);
}

#[test]
fn tcc_configure_can_fail_the_compile_and_a_panic_is_an_error() {
    let Some(library) = tcc_library() else { return };
    let err = Compiler::resolve(&[Candidate::tcc_library_with(library.clone(), |_| Err("nope".to_owned()))]).unwrap_err();
    assert!(err.to_string().contains("the configure function stopped the compile: nope"), "{err}");

    let err = Compiler::resolve(&[Candidate::tcc_library_with(library, |_| panic!("oh no"))]).unwrap_err();
    assert!(err.to_string().contains("the configure function panicked"), "{err}");
}

#[test]
fn candidates_compare_and_clone() {
    assert_eq!(Candidate::tcc_library("/x/libtcc.so"), Candidate::tcc_library("/x/libtcc.so"));
    let with = Candidate::tcc_library_with("/x/libtcc.so", |_| Ok(()));
    assert_eq!(with, with.clone(), "a clone has the same configure function");
    assert_ne!(with, Candidate::tcc_library("/x/libtcc.so"));
    assert_ne!(with, Candidate::tcc_library_with("/x/libtcc.so", |_| Ok(())), "another function is another candidate");
    assert_eq!(
        Candidate::executable_with_args("gcc", ["-O2"]),
        Candidate::Executable { program: "gcc".into(), args: vec!["-O2".to_owned()] }
    );
}

#[cfg(unix)]
#[test]
fn a_nul_in_a_tcc_library_path_is_an_error_not_a_panic() {
    use std::os::unix::ffi::OsStringExt;
    let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"lib\0tcc.so".to_vec()));
    let err = Compiler::resolve(&[Candidate::tcc_library(path)]).unwrap_err();
    assert!(err.to_string().contains("NUL"), "{err}");
}

#[test]
fn tcc_compiled_code_calls_a_host_function_and_sees_settings_change() {
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;
    let Some(library) = tcc_library() else { return };

    // a function of this program, for the compiled code to call
    extern "C" fn host_double(x: i32) -> i32 {
        2 * x
    }
    // read on every compile, so a change between compiles is seen
    let value = Arc::new(AtomicI32::new(5));
    let read = Arc::clone(&value);
    let candidate = Candidate::tcc_library_with(library, move |tcc| {
        let add_symbol = tcc.api.add_symbol.ok_or_else(|| "this libtcc has no tcc_add_symbol".to_owned())?;
        let defined = std::ffi::CString::new(read.load(Ordering::SeqCst).to_string()).unwrap();
        let state = tcc.state.as_ptr();
        // SAFETY: the state is live, the strings are NUL terminated, and
        // host_double has the C signature the source declares.
        unsafe {
            add_symbol(state, c"host_double".as_ptr(), host_double as *const std::ffi::c_void);
            (tcc.api.define_symbol)(state, c"VALUE".as_ptr(), defined.as_ptr());
        }
        Ok(())
    });
    let compiler = Compiler::resolve(&[candidate]).unwrap_or_else(|e| panic!("{e}"));
    let source = "int host_double(int);\nint f(void){return host_double(VALUE);}";
    let first = compiler.compile(source).unwrap();
    assert_eq!(call_f(&first), 10);
    value.store(7, Ordering::SeqCst);
    let second = compiler.compile(source).unwrap();
    assert_eq!(call_f(&second), 14);
    assert_eq!(call_f(&first), 10, "the first is its own code");
}

/// tcc as a compiler program (`C_AOT_TEST_TCC_PROGRAM`: an installed tcc). On
/// glibc 2.41 and later it needs a tcc from `mob@772dc70d` on (see
/// [`memory_first_candidates`]), such as the bundled example's.
#[cfg(target_os = "linux")]
#[test]
fn tcc_as_a_program_works() {
    let Some(program) = std::env::var_os("C_AOT_TEST_TCC_PROGRAM").filter(|p| !p.is_empty()) else { return };
    let compiler = Compiler::resolve(&[Candidate::executable(std::path::PathBuf::from(program))]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(call_f(&compiler.compile(&f_source("3")).unwrap()), 3);
}

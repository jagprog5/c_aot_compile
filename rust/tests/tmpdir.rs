//! Own test binary: it changes environment variables, which would race with
//! other tests in the same process.
#![cfg(unix)]

use c_aot_compile::{Candidate, Compiler};
use std::os::unix::fs::PermissionsExt;

/// The `TMPDIR` the compiler was started with. A compiler that records it and
/// then runs the real one.
#[test]
fn compiler_gets_the_right_tmpdir() {
    let dir = std::env::temp_dir().join(format!("c_aot_tmpdir_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let script = dir.join("cc.sh");
    let record = dir.join("record");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nprintf '%s' \"$TMPDIR\" > {}\nexec cc \"$@\"\n", record.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    let saved = std::env::var_os("TMPDIR");
    let seen = |caller_sets_it: bool| {
        // SAFETY: this is the only test in this process.
        unsafe {
            if caller_sets_it {
                std::env::set_var("TMPDIR", &dir);
            } else {
                std::env::remove_var("TMPDIR");
            }
        }
        // where this crate puts its temp directory with this environment: $TMPDIR,
        // else the system's default (/tmp on Linux, a per-user directory on macOS)
        let base = std::env::temp_dir();
        let compiler = Compiler::resolve(&[Candidate::executable(script.clone())]).unwrap_or_else(|e| panic!("{e}"));
        drop(compiler.compile("int f(void){return 1;}").unwrap());
        (std::fs::read_to_string(&record).unwrap(), base)
    };

    let memory = cfg!(all(target_os = "linux", not(feature = "no_memory_files")));
    let ((unset, unset_base), (set, set_base)) = (seen(false), seen(true));
    if memory {
        // a memory file system, if there is one, whatever the caller set
        let shm = std::path::Path::new("/dev/shm").is_dir();
        assert_eq!(unset, if shm { "/dev/shm" } else { "" });
        assert_eq!(set, if shm { "/dev/shm" } else { dir.to_str().unwrap() });
    } else {
        // the private directory, under the caller's TMPDIR (or the system's default, unset)
        assert!(unset.starts_with(unset_base.join("c_aot_compile.").to_str().unwrap()), "{unset}");
        assert!(set.starts_with(set_base.join("c_aot_compile.").to_str().unwrap()), "{set}");
        assert!(set.starts_with(dir.join("c_aot_compile.").to_str().unwrap()), "{set}");
    }

    // SAFETY: this is the only test in this process.
    unsafe {
        match saved {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

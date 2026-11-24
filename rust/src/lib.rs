//! Compile C source at runtime with the system C compiler, then load it.
//!
//! Linux and macOS (likely other Unix systems too).
//!
//! ```no_run
//! let lib = c_aot_compile::compile("int add(int a, int b) { return a + b; }", None, &[])?;
//! // SAFETY: `add` really is `int add(int, int)`.
//! let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }.unwrap();
//! assert_eq!(add(1, 2), 3); // `add` borrows `lib`, so it can't outlive it
//! # Ok::<(), c_aot_compile::Error>(())
//! ```
//!
//! A [`Symbol`] borrows its [`Library`], so using one after the library is
//! unloaded is a compile error:
//!
//! ```compile_fail,E0597
//! let add = {
//!     let lib = c_aot_compile::compile("int f(void) { return 1; }", None, &[]).unwrap();
//!     unsafe { lib.get::<extern "C" fn() -> i32>(c"f") }.unwrap()
//! }; // error: `lib` dropped here while still borrowed
//! add();
//! ```
//!
//! Design (mirrors the C header):
//! - each compile gets a fresh private (`0700`) directory under
//!   [`std::env::temp_dir`], removed (with everything in it) before
//!   [`compile`] returns, whether it succeeded or not;
//! - the source is written to a file there, unlinked right away and given to
//!   the compiler as stdin (no pipe to feed, so no deadlock or `SIGPIPE`
//!   handling);
//! - the compiler writes the library to a path in that directory. The random
//!   directory name makes the path unique (`dlopen` returns an already loaded
//!   library for a repeated path), and [`Library`] keeps the file open while
//!   loaded, so its inode can't be reused either;
//! - everything is spawned through `std::process::Command`, so there is no
//!   `fork` + custom code in a possibly threaded process.
//!
//! The files do touch disk (unless `TMPDIR` is a memory file system).
//!
//! # Security
//! This is a JIT: an avenue for arbitrary code execution. The source and the
//! compiler must be trusted. Also:
//! - the environment is passed to the compiler unchanged. `GCC_EXEC_PREFIX`,
//!   `COMPILER_PATH`, `CPATH`, `LIBRARY_PATH`, `LD_PRELOAD`, ... change what
//!   it runs or includes;
//! - a compiler name without `/` is looked up in `PATH`; prefer an absolute path;
//! - compiler diagnostics are returned in [`Error`]; with outside-influenced
//!   source, `#include "/secret"` can leak file fragments through them;
//! - between the compiler exiting and `dlopen`, a process running as the same
//!   user could modify the library file.

use std::ffi::{c_void, CStr, CString, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::NonNull;

/// How much of the compiler's stderr is kept for error messages.
const STDERR_CAPACITY: usize = 1024;

/// Why compiling or loading failed.
#[derive(Debug)]
pub enum Error {
    /// A system call or process operation failed.
    Io {
        context: &'static str,
        source: io::Error,
    },
    /// The compiler ran but failed. `stderr` is truncated to 1024 bytes.
    Compiler { status: String, stderr: String },
    /// `dlopen` rejected the compiled library.
    Load(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Compiler { status, stderr } => write!(f, "compiler {status}. stderr:\n{stderr}"),
            Error::Load(reason) => write!(f, "dlopen: {reason}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn io_err(context: &'static str) -> impl FnOnce(io::Error) -> Error {
    move |source| Error::Io { context, source }
}

/// A loaded, compiled library. Unloaded on drop.
pub struct Library {
    handle: NonNull<c_void>,
    // The (already deleted) library file. Closed only after `dlclose` (drop
    // body runs before fields drop), so its inode isn't reused while loaded.
    _code: OwnedFd,
}

// dlsym/dlclose are thread safe, and the handle is never mutated.
unsafe impl Send for Library {}
unsafe impl Sync for Library {}

impl Library {
    /// Looks up a symbol of type `T`. Returns `None` if it doesn't exist.
    ///
    /// The returned [`Symbol`] borrows `self`, so it can't outlive the library.
    ///
    /// `T` must be a function pointer (or other pointer-sized `Copy` type),
    /// e.g. `extern "C" fn(i32) -> i32`. Panics if `T` isn't pointer-sized.
    ///
    /// # Safety
    /// `T` must match the C definition of the symbol (arguments, return type,
    /// calling convention). The compiler can't check this.
    pub unsafe fn get<T: Copy>(&self, name: &CStr) -> Option<Symbol<'_, T>> {
        assert_eq!(
            std::mem::size_of::<T>(),
            std::mem::size_of::<*mut c_void>(),
            "T must be pointer-sized"
        );
        // SAFETY: handle is a live dlopen handle, name is NUL terminated.
        let ptr = NonNull::new(unsafe { libc::dlsym(self.handle.as_ptr(), name.as_ptr()) })?;
        // SAFETY: T is pointer-sized (asserted) and, per the caller, the right type.
        let value = unsafe { std::mem::transmute_copy::<*mut c_void, T>(&ptr.as_ptr()) };
        Some(Symbol {
            value,
            _library: PhantomData,
        })
    }
}

/// A symbol looked up with [`Library::get`]. Derefs to the function pointer
/// (so `symbol(args)` calls it). Borrows the library it came from.
pub struct Symbol<'lib, T> {
    value: T,
    _library: PhantomData<&'lib Library>,
}

impl<T> Deref for Symbol<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: handle came from dlopen and is closed exactly once.
        unsafe { libc::dlclose(self.handle.as_ptr()) };
    }
}

impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Library")
            .field("handle", &self.handle)
            .finish()
    }
}

/// A fresh private (`0700`) directory, removed with its contents on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<TempDir, Error> {
        let mut template = std::env::temp_dir()
            .join("c_aot_compile.XXXXXX")
            .into_os_string()
            .into_vec();
        template.push(0);
        // SAFETY: template is NUL terminated and writable; mkdtemp only
        // replaces the trailing XXXXXX.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(Error::Io {
                context: "creating temp directory",
                source: io::Error::last_os_error(),
            });
        }
        template.pop(); // the NUL
        Ok(TempDir(OsString::from_vec(template).into()))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // best effort. a loaded library stays mapped (and its fd open), so
        // removing its file is fine
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn path_to_cstring(path: &Path) -> CString {
    // the path is the temp dir (mkdtemp took it as a C string) plus a fixed name
    CString::new(path.as_os_str().as_bytes()).expect("no NUL in the temp path")
}

/// Compiles `source` (C) to a shared library and loads it.
///
/// - `compiler`: program to run; `None` means `"cc"`.
/// - `args`: extra compiler arguments, appended to the built-in ones.
///
/// See the crate docs for the security caveats.
pub fn compile(source: &str, compiler: Option<&str>, args: &[&str]) -> Result<Library, Error> {
    let compiler = compiler.unwrap_or("cc");

    // declared first, so it's dropped (removed) last: after the child is
    // waited on and every file in it is closed
    let dir = TempDir::new()?;
    let src_path = dir.0.join("src.c");
    let lib_path = dir.0.join("lib.so");

    // source -> file, unlinked at once, which becomes the compiler's stdin
    let mut src = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&src_path)
        .map_err(io_err("creating source file"))?;
    let _ = fs::remove_file(&src_path); // the directory is removed anyway
    src.write_all(source.as_bytes())
        .map_err(io_err("writing source"))?;
    src.rewind().map_err(io_err("rewinding source"))?;

    let mut child = Command::new(compiler)
        .args(["-pipe", "-fPIC", "-shared", "-O2", "-xc", "-o"])
        .arg(&lib_path)
        .arg("-")
        .args(args)
        .stdin(Stdio::from(src))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(io_err("starting compiler"))?;

    // read stderr to EOF: keep the first bytes (constant space), but keep
    // reading so the compiler never blocks on a full pipe
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let mut kept = Vec::new();
    let read_result = (&mut stderr)
        .take(STDERR_CAPACITY as u64)
        .read_to_end(&mut kept)
        .and_then(|_| io::copy(&mut stderr, &mut io::sink()).map(|rest| rest > 0));
    // drop the pipe before waiting: if reading failed, the compiler gets EPIPE
    // instead of blocking forever
    drop(stderr);
    let status = child.wait().map_err(io_err("waiting for compiler"))?;
    let truncated = read_result.map_err(io_err("reading compiler's stderr"))?;

    if !status.success() {
        let mut stderr = String::from_utf8_lossy(&kept).into_owned();
        if truncated {
            stderr.push_str("\n... (truncated)\n");
        }
        return Err(Error::Compiler {
            status: status.to_string(),
            stderr,
        });
    }

    // hold the library's inode while it's loaded, so it can't be reused for a
    // later library while this one is still loaded
    let code = File::open(&lib_path).map_err(io_err("opening library"))?;

    // random directory, so this path is unique
    let path = path_to_cstring(&lib_path);
    // SAFETY: path is NUL terminated.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    match NonNull::new(handle) {
        Some(handle) => Ok(Library {
            handle,
            _code: code.into(),
        }),
        None => {
            // SAFETY: dlerror returns NULL or a valid C string.
            let reason = unsafe {
                let msg = libc::dlerror();
                if msg.is_null() {
                    "unknown error".to_owned()
                } else {
                    CStr::from_ptr(msg).to_string_lossy().into_owned()
                }
            };
            Err(Error::Load(reason))
        }
    }
}

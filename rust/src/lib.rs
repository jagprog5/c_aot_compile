//! Compile C source at runtime with the system C compiler, then load it.
//!
//! Linux only (`memfd_create`, `/dev/fd`, which needs `/proc` mounted).
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
//! - the source is given to the compiler as a memory file on stdin (no pipe to
//!   feed, so no deadlock or `SIGPIPE` handling);
//! - the compiler writes the library into a sealed memory file that stays open
//!   while the library is loaded: its `/dev/fd/N` path is therefore unique
//!   (`dlopen` returns an already loaded library for a repeated path), and the
//!   code can't be rewritten after loading;
//! - everything is spawned through `std::process::Command`, so there is no
//!   `fork` + custom code in a possibly threaded process.
//!
//! # Security
//! This is a JIT: an avenue for arbitrary code execution. The source and the
//! compiler must be trusted. Also:
//! - the environment is passed to the compiler (except `TMPDIR`, which is
//!   forced to `/dev/shm`). `GCC_EXEC_PREFIX`, `COMPILER_PATH`, `CPATH`,
//!   `LIBRARY_PATH`, `LD_PRELOAD`, ... change what it runs or includes;
//! - a compiler name without `/` is looked up in `PATH`; prefer an absolute path;
//! - compiler diagnostics are returned in [`Error`]; with outside-influenced
//!   source, `#include "/secret"` can leak file fragments through them;
//! - the compiler's stdout is the output file, so don't pass flags that print
//!   to stdout (`-E`, `-print-*`).

use std::ffi::{c_void, CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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
    // Closed only after `dlclose` (drop body runs before fields drop). It must
    // stay open while loaded, see the crate docs.
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

/// Creates a close-on-exec memory file.
fn memfd(name: &CStr, sealable: bool) -> Result<File, Error> {
    let flags = libc::MFD_CLOEXEC | if sealable { libc::MFD_ALLOW_SEALING } else { 0 };
    // SAFETY: name is NUL terminated.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), flags) };
    if fd == -1 {
        return Err(Error::Io {
            context: "memfd_create",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: fd is valid and exclusively ours.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Compiles `source` (C) to a shared library and loads it.
///
/// - `compiler`: program to run; `None` means `"cc"`.
/// - `args`: extra compiler arguments, appended to the built-in ones.
///
/// See the crate docs for the security caveats.
pub fn compile(source: &str, compiler: Option<&str>, args: &[&str]) -> Result<Library, Error> {
    let compiler = compiler.unwrap_or("cc");

    // source -> memory file, which becomes the compiler's stdin
    let mut src = memfd(c"c_aot_source", false)?;
    src.write_all(source.as_bytes())
        .map_err(io_err("writing source"))?;
    src.rewind().map_err(io_err("rewinding source"))?;

    // the compiler writes the library to its stdout, which is this memory
    // file (so "-o/dev/fd/1"). a memory file, not a pipe, is needed, as
    // otherwise gcc fails (ld: final link failed: Illegal seek)
    let out = memfd(c"c_aot_library", true)?;
    let out_for_child = out.try_clone().map_err(io_err("dup library fd"))?;

    let mut child = Command::new(compiler)
        .args([
            "-pipe",
            "-fPIC",
            "-shared",
            "-O2",
            "-xc",
            "-o/dev/fd/1",
            "-",
        ])
        .args(args)
        .env("TMPDIR", "/dev/shm") // best effort: asks the compiler to keep temp files off disk. not a guarantee
        .stdin(Stdio::from(src))
        .stdout(Stdio::from(out_for_child))
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

    // compiler is done: make the code immutable before running it
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: plain fcntl on a valid fd.
    if unsafe { libc::fcntl(out.as_raw_fd(), libc::F_ADD_SEALS, seals) } == -1 {
        return Err(Error::Io {
            context: "sealing library",
            source: io::Error::last_os_error(),
        });
    }

    // the fd stays open as long as the library is loaded, so this path is unique
    let path = CString::new(format!("/dev/fd/{}", out.as_raw_fd())).expect("no NUL in a number");
    // SAFETY: path is NUL terminated.
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    match NonNull::new(handle) {
        Some(handle) => Ok(Library {
            handle,
            _code: out.into(),
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

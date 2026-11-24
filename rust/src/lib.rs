//! Compile C source at runtime with the system C compiler, then load it.
//!
//! Linux, macOS (likely other Unix systems too) and Windows. On Windows the
//! compiler must have a gcc style driver (mingw gcc, clang, tcc), the default
//! is `gcc`, and symbols must be exported to be found: mingw exports every
//! global symbol unless something is marked `__declspec(dllexport)`, other
//! toolchains need it on whatever you look up.
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
//!   [`compile`] returns, whether it succeeded or not (on Windows the
//!   directory inherits its parent's permissions, and is removed when the
//!   [`Library`] drops, because a loaded dll can't be deleted);
//! - the source is written to a file there, unlinked right away and given to
//!   the compiler as stdin (no pipe to feed, so no deadlock or `SIGPIPE`
//!   handling);
//! - the compiler writes the library to a path in that directory. The random
//!   directory name makes the path unique (`dlopen` / `LoadLibrary` return an
//!   already loaded library for a repeated path), and [`Library`] keeps the
//!   file open while loaded, so its inode can't be reused either;
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

use std::ffi::{c_void, CStr};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::PathBuf;
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
    /// The loader (`dlopen` / `LoadLibrary`) rejected the compiled library.
    Load(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Compiler { status, stderr } => write!(f, "compiler {status}. stderr:\n{stderr}"),
            Error::Load(reason) => write!(f, "loading library: {reason}"),
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
    // The (already deleted) library file. Closed only after unloading (drop
    // body runs before fields drop), so its inode isn't reused while loaded.
    // On Windows it's opened delete-on-close, so closing it deletes it.
    _code: File,
    // Windows only: the directory holding the library, removed after the file
    // is closed (so declared after it). Unix removes it before `compile` returns.
    _dir: Option<TempDir>,
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
        // SAFETY: handle is a live library handle, name is NUL terminated.
        let ptr = NonNull::new(unsafe { sys::symbol(self.handle.as_ptr(), name) })?;
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
        // SAFETY: handle came from the loader and is unloaded exactly once.
        unsafe { sys::unload(self.handle.as_ptr()) };
    }
}

impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Library")
            .field("handle", &self.handle)
            .finish()
    }
}

/// A fresh private directory, removed with its contents on drop.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        // best effort. a loaded library stays mapped (and its file open), so
        // removing its file is fine on unix. on windows the file is deleted
        // when its handle closes, which is before this runs
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
mod sys {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub const DEFAULT_COMPILER: &str = "cc";
    pub const LIB_NAME: &str = "lib.so";
    pub const EXTRA_FLAGS: &[&str] = &["-fPIC"];
    pub const KEEP_DIR_WHILE_LOADED: bool = false;

    pub fn temp_dir() -> Result<TempDir, Error> {
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

    /// The source file, read + write, already unlinked.
    pub fn create_source(path: &Path) -> io::Result<File> {
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let _ = fs::remove_file(path); // the directory is removed anyway
        Ok(file)
    }

    /// The library file, held open while it's loaded.
    pub fn open_library_file(path: &Path) -> io::Result<File> {
        File::open(path)
    }

    pub fn load(path: &Path) -> Result<NonNull<c_void>, String> {
        // the path is the temp dir (mkdtemp took it as a C string) plus a fixed name
        let path = CString::new(path.as_os_str().as_bytes()).expect("no NUL in the temp path");
        // SAFETY: path is NUL terminated.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
        NonNull::new(handle).ok_or_else(|| {
            // SAFETY: dlerror returns NULL or a valid C string.
            unsafe {
                let msg = libc::dlerror();
                if msg.is_null() {
                    "unknown error".to_owned()
                } else {
                    CStr::from_ptr(msg).to_string_lossy().into_owned()
                }
            }
        })
    }

    pub unsafe fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
        unsafe { libc::dlsym(handle, name.as_ptr()) }
    }

    pub unsafe fn unload(handle: *mut c_void) {
        unsafe { libc::dlclose(handle) };
    }

    pub fn configure(_command: &mut Command) {}
}

#[cfg(windows)]
mod sys {
    use super::*;
    use std::ffi::c_char;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
        fn FreeLibrary(module: *mut c_void) -> i32;
    }

    const DELETE: u32 = 0x0001_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4; // read, write, delete
    const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub const DEFAULT_COMPILER: &str = "gcc";
    pub const LIB_NAME: &str = "lib.dll";
    pub const EXTRA_FLAGS: &[&str] = &[];
    pub const KEEP_DIR_WHILE_LOADED: bool = true;

    pub fn temp_dir() -> Result<TempDir, Error> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let base = std::env::temp_dir();
        for _ in 0..100 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let name = format!(
                "c_aot_compile.{:x}.{:x}.{:x}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed),
                nanos
            );
            let path = base.join(name);
            match fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(Error::Io {
                        context: "creating temp directory",
                        source,
                    })
                }
            }
        }
        Err(Error::Io {
            context: "creating temp directory",
            source: io::Error::new(io::ErrorKind::AlreadyExists, "names kept colliding"),
        })
    }

    /// The source file, read + write, deleted when its last handle closes
    /// (the compiler's copy of the handle too).
    pub fn create_source(path: &Path) -> io::Result<File> {
        File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(FILE_SHARE_ALL)
            .attributes(FILE_ATTRIBUTE_TEMPORARY)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(path)
    }

    /// The library file, held open (delete-on-close) while it's loaded: a
    /// loaded dll can't be deleted, so it goes away once unloaded and closed.
    pub fn open_library_file(path: &Path) -> io::Result<File> {
        File::options()
            .read(true)
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(path)
    }

    pub fn load(path: &Path) -> Result<NonNull<c_void>, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        // SAFETY: wide is NUL terminated.
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        NonNull::new(handle).ok_or_else(|| io::Error::last_os_error().to_string())
    }

    pub unsafe fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
        unsafe { GetProcAddress(handle, name.as_ptr()) }
    }

    pub unsafe fn unload(handle: *mut c_void) {
        unsafe { FreeLibrary(handle) };
    }

    pub fn configure(command: &mut Command) {
        command.creation_flags(CREATE_NO_WINDOW);
    }
}

/// Compiles `source` (C) to a shared library and loads it.
///
/// - `compiler`: program to run; `None` means `"cc"` (`"gcc"` on Windows).
/// - `args`: extra compiler arguments, appended to the built-in ones.
///
/// See the crate docs for the security caveats.
pub fn compile(source: &str, compiler: Option<&str>, args: &[&str]) -> Result<Library, Error> {
    let compiler = compiler.unwrap_or(sys::DEFAULT_COMPILER);

    // declared first, so it's dropped (removed) last: after the child is
    // waited on and every file in it is closed
    let dir = sys::temp_dir()?;
    let src_path = dir.0.join("src.c");
    let lib_path = dir.0.join(sys::LIB_NAME);

    // source -> file, unlinked at once, which becomes the compiler's stdin
    let mut src = sys::create_source(&src_path).map_err(io_err("creating source file"))?;
    src.write_all(source.as_bytes())
        .map_err(io_err("writing source"))?;
    src.rewind().map_err(io_err("rewinding source"))?;

    let mut command = Command::new(compiler);
    command
        .args(["-pipe", "-shared", "-O2", "-xc"])
        .args(sys::EXTRA_FLAGS)
        .arg("-o")
        .arg(&lib_path)
        .arg("-")
        .args(args)
        .stdin(Stdio::from(src))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    sys::configure(&mut command);
    let mut child = command.spawn().map_err(io_err("starting compiler"))?;
    drop(command); // releases its copy of the source file handle

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

    // hold the library file while it's loaded, so its inode can't be reused
    // for a later library while this one is still loaded
    let code = sys::open_library_file(&lib_path).map_err(io_err("opening library"))?;

    // random directory, so this path is unique
    let handle = sys::load(&lib_path).map_err(Error::Load)?;
    Ok(Library {
        handle,
        _code: code,
        _dir: sys::KEEP_DIR_WHILE_LOADED.then_some(dir),
    })
}

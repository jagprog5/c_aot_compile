//! Compile C source at runtime with a C compiler, then load it.
//!
//! Linux, macOS (likely other Unix systems too) and Windows. On Windows the
//! compiler must have a gcc style driver (mingw gcc, clang, tcc), and symbols
//! must be exported to be found: mingw exports every global symbol unless
//! something is marked `__declspec(dllexport)`, other toolchains need it on
//! whatever you look up.
//!
//! Find a compiler once with [`Compiler::resolve`], from a list of
//! [`Candidate`]s (an executable, given as a path or a name in `PATH`, an
//! environment variable such as `CC`, or a libtcc shared object), then compile with it as often as you like:
//!
//! ```no_run
//! let compiler = c_aot_compile::Compiler::resolve_memory_first(None)?; // $CC, cc, gcc, clang, ...
//! let lib = compiler.compile("int add(int a, int b) { return a + b; }")?;
//! // SAFETY: `add` really is `int add(int, int)`.
//! let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }.unwrap();
//! assert_eq!(add(1, 2), 3); // `add` borrows `lib`, so it can't outlive it
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! If no compiler is found, [`ResolveError`] says what was tried and why each
//! candidate failed. The list is the whole policy: nothing is searched beyond
//! it, so "only this tcc" or "only this path" is a list of one.
//!
//! # Which compiler first
//! You rarely need to write the list yourself. There are two presets:
//! [`fast_candidates`] puts the fastest generated code first (the system
//! compilers with `-O2 -march=native ...`, libtcc after them), and
//! [`memory_first_candidates`] avoids writing to disk first and then speed.
//! Both take the path of an optional libtcc you bundle with your app, or
//! `None`, and put it where it belongs ([`memory_first_candidates`] also tries
//! the system's after it). [`Compiler::resolve_fast`] and
//! [`Compiler::resolve_memory_first`] resolve them.
//! An executable or environment variable candidate can carry its own compiler
//! args ([`Candidate::executable_with_args`]), which come after the fixed ones.
//! A tcc library has no args: it
//! takes a configure function ([`Candidate::tcc_library_with`]) instead, to
//! set options on the tcc state directly. Every compile gets a fresh tcc
//! state, so it runs before every compile, not once.
//!
//! # libtcc
//! A [`Candidate::TccLibrary`] is a libtcc shared object you provide (build it
//! from tcc's source: distro packages often ship only a static one, which can't
//! be loaded at run time). It is loaded at run time
//! with `dlopen` / `LoadLibrary`, never linked, so a program using this crate
//! starts without it. Code is then compiled in this process, to memory: no
//! files, no child process. tcc doesn't optimize, so its code is slower than
//! an optimizing compiler's. Compiles with tcc are serialized, since libtcc
//! has global state.
//!
//! A [`Symbol`] borrows its [`Library`], so using one after the library is
//! unloaded is a compile error:
//!
//! ```compile_fail,E0597
//! let add = {
//!     let compiler = c_aot_compile::Compiler::resolve_memory_first(None).unwrap();
//!     let lib = compiler.compile("int f(void) { return 1; }").unwrap();
//!     unsafe { lib.get::<extern "C" fn() -> i32>(c"f") }.unwrap()
//! }; // error: `lib` dropped here while still borrowed
//! add();
//! ```
//!
//! Design of the executable backend (mirrors the C header):
//! - the source is a file given to the compiler as stdin (no pipe to feed, so
//!   no deadlock or `SIGPIPE` handling);
//! - the compiler writes the library to a file, and [`Library`] keeps that
//!   file open while loaded, so its inode can't be reused;
//! - the name the library is loaded by is always unique (`dlopen` /
//!   `LoadLibrary` return an already loaded library for a repeated name);
//! - where the files are depends on the system, see below. Without memory
//!   files, each compile gets a fresh private (`0700`) directory under
//!   [`std::env::temp_dir`], removed (with everything in it) before
//!   [`Compiler::compile`] returns, whether it succeeded or not (on Windows the
//!   directory inherits its parent's permissions, and is removed when the
//!   [`Library`] drops, because a loaded dll can't be deleted), and the source
//!   is unlinked right away;
//! - everything is spawned through `std::process::Command`, so there is no
//!   `fork` + custom code in a possibly threaded process.
//!
//! The compiler is run as
//! `<compiler> -pipe -fPIC -shared -O1 -xc -o <library> - <args>`
//! (no `-fPIC` on Windows), where `args` are the candidate's. They come last, so
//! a later `-O2` or `-O0` overrides the `-O1`.
//!
//! Where the files are depends on the system:
//! - **Linux:** the source and the library are memory files (`memfd_create`)
//!   and never touch disk. The compiler writes the library to its stdout, a
//!   memory file, by the path `/dev/fd/1`, and it is loaded from
//!   `/proc/self/fd/<fd>`. So a compiler program (or a wrapper around one, such
//!   as a `CC` script) must not write anything to its stdout: that would land
//!   in the library and corrupt it (resolving then fails with "invalid ELF
//!   header"). Compilers don't, and their diagnostics go to stderr. A wrapper
//!   that does can redirect its own output to stderr, or use the
//!   `no_memory_files` feature. Without `memfd_create` or `/dev/fd`, or with the
//!   `no_memory_files` feature, the next case applies.
//! - **macOS, other Unix, Windows:** there is no memory file a compiler can
//!   open by path, so each compile uses the private temp directory described
//!   above. To keep those files in memory anyway, point `TMPDIR` at a memory
//!   file system.
//! - **Everywhere:** what a compiler writes itself while it works (gcc leaves
//!   intermediate files in `TMPDIR` even with `-pipe`) goes where its `TMPDIR`
//!   says, and this crate sets the compiler's `TMPDIR` (Unix; not Windows):
//!   with a temp directory, to that private directory, so those files are
//!   contained and removed with it; with memory files, to `/dev/shm` if it is
//!   a writable directory, even if your `TMPDIR` is set (if `/dev/shm` isn't
//!   usable, yours is left as it is). This is the only change to the
//!   compiler's environment. (Enable the `no_memory_files` feature to have
//!   everything under your `TMPDIR` instead.)
//!
//! Between the compiler exiting and the load, a process running as the same
//! user could modify a library on disk. A memory file has no path to open by.
//!
//! # Security
//! This is a JIT: an avenue for arbitrary code execution. The source and the
//! compiler must be trusted. Also:
//! - the environment is passed to the compiler as it is, except `TMPDIR` on
//!   Unix (see above). `GCC_EXEC_PREFIX`, `COMPILER_PATH`, `CPATH`,
//!   `LIBRARY_PATH`, `LD_PRELOAD`, ... change what it runs or includes. Resolving reads `PATH` and any [`Candidate::Env`]
//!   you give it (both presets have `CC`);
//! - a [`Candidate::Executable`] without a directory separator is looked up in `PATH`;
//!   prefer a path;
//! - compiler diagnostics are returned in [`Error`]; with outside-influenced
//!   source, `#include "/secret"` can leak file fragments through them;
//! - between the compiler exiting and `dlopen`, a process running as the same
//!   user could modify the library file.

use std::ffi::{c_char, c_int, c_void, CStr, CString, OsStr};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};

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
    /// The tcc backend failed: a compile error (with tcc's diagnostics), or an
    /// argument tcc doesn't support.
    Tcc(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io { context, source } => write!(f, "{context}: {source}"),
            Error::Compiler { status, stderr } => write!(f, "compiler {status}. stderr:\n{stderr}"),
            Error::Load(reason) => write!(f, "loading library: {reason}"),
            Error::Tcc(reason) => write!(f, "tcc: {reason}"),
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

/// Compiled, loaded code. Unloaded on drop.
pub struct Library {
    repr: Repr,
}

enum Repr {
    /// Compiled by an executable: a shared library, loaded.
    Loaded {
        handle: NonNull<c_void>,
        // The (already deleted) library file. Closed only after unloading (drop
        // body runs before fields drop), so its inode isn't reused while loaded.
        // On Windows it's opened delete-on-close, so closing it deletes it.
        _code: File,
        // Windows only: the directory holding the library, removed after the file
        // is closed (so declared after it). Unix removes it before `compile` returns.
        _dir: Option<TempDir>,
    },
    /// Compiled in memory by tcc.
    Tcc(TccCode),
}

// dlsym/dlclose are thread safe, the handle is never mutated, and tcc code is
// only touched under the tcc lock.
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
        let found = match &self.repr {
            // SAFETY: handle is a live library handle, name is NUL terminated.
            Repr::Loaded { handle, .. } => unsafe { sys::symbol(handle.as_ptr(), name) },
            Repr::Tcc(code) => code.symbol(name),
        };
        let ptr = NonNull::new(found)?;
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
        if let Repr::Loaded { handle, .. } = &self.repr {
            // SAFETY: handle came from the loader and is unloaded exactly once.
            unsafe { sys::unload(handle.as_ptr()) };
        }
    }
}

impl fmt::Debug for Library {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Loaded { handle, .. } => f.debug_struct("Library").field("handle", handle).finish(),
            Repr::Tcc(_) => f.debug_struct("Library").field("backend", &"tcc").finish(),
        }
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

    pub const SYSTEM_COMPILERS: &[&str] = &["cc", "gcc", "clang"];
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

    /// Loads a compiled library.
    pub fn load(path: &Path) -> Result<NonNull<c_void>, String> {
        load_with(path, libc::RTLD_NOW)
    }

    /// Loads a libtcc: its symbols stay out of the global namespace (the
    /// default on macOS is the opposite), as the C header does.
    pub fn load_tcc(path: &Path) -> Result<NonNull<c_void>, String> {
        load_with(path, libc::RTLD_NOW | libc::RTLD_LOCAL)
    }

    fn load_with(path: &Path, flags: libc::c_int) -> Result<NonNull<c_void>, String> {
        // a path the caller gave (a libtcc) may contain a NUL: an error, not a panic
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| "the path contains a NUL byte".to_owned())?;
        // SAFETY: path is NUL terminated.
        let handle = unsafe { libc::dlopen(path.as_ptr(), flags) };
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

    pub const SYSTEM_COMPILERS: &[&str] = &["gcc", "clang", "cc"];
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

    /// Loads a libtcc. On Windows there is no global namespace to keep it out of.
    pub fn load_tcc(path: &Path) -> Result<NonNull<c_void>, String> {
        load(path)
    }

    pub fn load(path: &Path) -> Result<NonNull<c_void>, String> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            // it would silently cut the path short
            return Err("the path contains a NUL character".to_owned());
        }
        let wide: Vec<u16> = wide.into_iter().chain([0]).collect();
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


// ============================ candidates ===============================

/// One way to find a compiler. [`Compiler::resolve`] tries a list of these in
/// order, and the first that really works wins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    /// An executable, found like a shell does: with a directory separator it
    /// is a path (a relative one is relative to the current directory), else
    /// it is a name looked up in `PATH`. `program` must be a program only, no
    /// arguments: those are `args`, extra compiler arguments that come after
    /// the fixed ones (`-pipe -fPIC -shared -O1 -xc -o <library> -`), so a
    /// later `-O2` overrides the `-O1`.
    Executable { program: PathBuf, args: Vec<String> },
    /// The name of an environment variable (like `CC`), whose value is an
    /// executable as above, with its own `args`. Not set or empty: skipped.
    Env { variable: String, args: Vec<String> },
    /// A libtcc shared object. Either a path (it has a directory separator:
    /// used as given, and tcc's support files are looked for next to it) or a
    /// bare name (searched for by the system loader, like `dlopen` /
    /// `LoadLibrary`, so no folder is known to look in). tcc also needs its
    /// support files, `libtcc1.a` and `include/`: if they are next to the
    /// library (`libtcc1.a`, or `lib/libtcc1.a` as on Windows), that directory
    /// is used, as in an app that ships them together. Otherwise tcc's own
    /// built-in location is used, as in a tcc that is installed. The compile
    /// then happens in this process, to memory, with no files or child
    /// process.
    ///
    /// A tcc library has no args: `configure` sets options on the tcc state
    /// directly instead. Every compile gets a fresh tcc state, so it runs
    /// before every compile, not once.
    TccLibrary {
        library: PathBuf,
        configure: Option<TccConfigure>,
    },
}

impl Candidate {
    /// An executable (a path, or a name looked up in `PATH`), with no extra
    /// args.
    pub fn executable(program: impl Into<PathBuf>) -> Candidate {
        Candidate::Executable { program: program.into(), args: Vec::new() }
    }

    /// An executable with extra compiler args, which come after the fixed ones.
    pub fn executable_with_args(program: impl Into<PathBuf>, args: impl IntoIterator<Item = impl Into<String>>) -> Candidate {
        Candidate::Executable { program: program.into(), args: args.into_iter().map(Into::into).collect() }
    }

    /// A libtcc shared object (a path, or a bare name for the system loader),
    /// with no configure function.
    pub fn tcc_library(library: impl Into<PathBuf>) -> Candidate {
        Candidate::TccLibrary { library: library.into(), configure: None }
    }

    /// A libtcc shared object with a `configure` function, which sets options
    /// on the tcc state directly. It runs before every single compile (each
    /// gets a fresh tcc state), including the test compile when resolving,
    /// not once. See [`TccConfigure`].
    pub fn tcc_library_with(
        library: impl Into<PathBuf>,
        configure: impl Fn(&TccState<'_>) -> Result<(), String> + Send + Sync + 'static,
    ) -> Candidate {
        Candidate::TccLibrary { library: library.into(), configure: Some(TccConfigure::new(configure)) }
    }

    /// The executable named by an environment variable, with no extra args.
    pub fn env(variable: impl Into<String>) -> Candidate {
        Candidate::Env { variable: variable.into(), args: Vec::new() }
    }

    /// The executable named by an environment variable, with extra compiler
    /// args, which come after the fixed ones.
    pub fn env_with_args(variable: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Candidate {
        Candidate::Env { variable: variable.into(), args: args.into_iter().map(Into::into).collect() }
    }

    fn describe(&self) -> String {
        match self {
            Candidate::Executable { program, .. } => format!("executable \"{}\"", program.display()),
            Candidate::Env { variable, .. } => format!("environment variable \"{variable}\""),
            Candidate::TccLibrary { library, .. } => format!("tcc library \"{}\"", library.display()),
        }
    }
}

/// The memory first preset: the candidates to try when keeping source and
/// compiled code in memory matters most, then speed. It is a priority, not a guarantee: where only
/// a compiler program that writes temporary files exists (macOS or Windows
/// without a libtcc), that program is still used, last. What writes nothing:
/// libtcc, and on Linux the compilers below, whose source and library are
/// memory files and whose own temporary files go to `/dev/shm`. The order:
/// - **Linux:** `$CC`, then `cc`, `gcc`, `clang` (their source and library are
///   memory files: nothing touches disk), then your bundled libtcc and the system's
///   as the fallback, then `tcc` as a program, last.
/// - **Elsewhere** (macOS, Windows, other Unix): your bundled libtcc and the
///   system's first (the only option that never touches disk there), then `tcc` as a program (it
///   compiles fastest), then `$CC`, then `cc`, `gcc`, `clang` (Windows: `gcc`,
///   `clang`, `cc`).
/// - **Linux with the `no_memory_files` feature:** as "elsewhere", except that
///   `tcc` as a program stays last, as on Linux.
///
/// Why `tcc` as a program is last on Linux: a tcc older than `mob@772dc70d`
/// (2026-11-26; that includes 0.9.27, the last release, and so most installed
/// ones) builds libraries with no `PT_GNU_STACK` header, which the loader reads
/// as "needs an executable stack", and glibc 2.41 and later refuse to `dlopen`
/// such a library (older glibc made the stack executable instead). A newer tcc,
/// or an older glibc, works. Where neither is the case, resolving fails it with
/// the loader's own message and moves on, so it costs nothing but a test
/// compile at the end of the list. libtcc, in process, has no such problem.
///
/// `bundled_tcc_library` is optional: a libtcc you bundle with your app (a
/// path, or a bare name for the system loader), or `None` for none. "The
/// system's" libtcc is an installed one, found by the loader; it is skipped if
/// there is none.
pub fn memory_first_candidates(bundled_tcc_library: Option<&Path>) -> Vec<Candidate> {
    const MEMORY_FILES: bool = cfg!(all(target_os = "linux", not(feature = "no_memory_files")));
    let tcc_libraries: Vec<Candidate> = bundled_tcc_library
        .into_iter()
        .chain([Path::new(SYSTEM_TCC_LIBRARY)])
        .map(Candidate::tcc_library)
        .collect();
    let programs = sys::SYSTEM_COMPILERS.iter().map(|n| Candidate::executable(*n));

    let tcc_program = Candidate::executable("tcc");
    let tcc_last = cfg!(target_os = "linux"); // see above

    let mut list = Vec::new();
    if MEMORY_FILES {
        // the system compilers keep nothing on disk: they come first
        list.push(Candidate::env("CC"));
        list.extend(programs);
        list.extend(tcc_libraries);
    } else {
        // only libtcc keeps nothing on disk: it comes first
        list.extend(tcc_libraries);
        if !tcc_last {
            list.push(tcc_program.clone());
        }
        list.push(Candidate::env("CC"));
        list.extend(programs);
    }
    if tcc_last {
        list.push(tcc_program);
    }
    list
}

// the system's libtcc, as a bare name for the loader: an installed tcc's
const SYSTEM_TCC_LIBRARY: &str = if cfg!(windows) {
    "libtcc.dll"
} else if cfg!(target_vendor = "apple") {
    "libtcc.dylib"
} else {
    "libtcc.so"
};

/// The "go fast" compiler args of [`fast_candidates`].
pub const FAST_ARGS: &[&str] = &["-O2", "-march=native", "-fno-semantic-interposition"];

/// The fast preset: the candidates to try when you want the fastest generated
/// code, whatever it costs. The system compilers, each first with "go fast" args ([`FAST_ARGS`]),
/// and then without them if it turns out to reject them: `$CC`, then `cc`,
/// `gcc`, `clang` (Windows: `gcc`, `clang`, `cc`). Then your bundled libtcc, and then
/// `tcc` as a program, last: tcc doesn't optimize (and on Linux, its libraries
/// may not load: see [`memory_first_candidates`]).
///
/// The args are `-O2` (over the default `-O1`), `-march=native` (this
/// machine's instructions: the code is built here and runs here) and
/// `-fno-semantic-interposition` (calls inside the library are direct). Not
/// included, because they change what a program means or remove protection:
/// `-ffast-math`, `-DNDEBUG`, `-fno-stack-protector`. Add them with
/// [`Candidate::executable_with_args`] if you want them. Compiling takes
/// longer.
///
/// `bundled_tcc_library` is optional: a libtcc you bundle with your app, or
/// `None` for none.
pub fn fast_candidates(bundled_tcc_library: Option<&Path>) -> Vec<Candidate> {
    let mut list = vec![Candidate::env_with_args("CC", FAST_ARGS.iter().copied()), Candidate::env("CC")];
    for name in sys::SYSTEM_COMPILERS {
        list.push(Candidate::executable_with_args(*name, FAST_ARGS.iter().copied()));
        list.push(Candidate::executable(*name));
    }
    list.extend(bundled_tcc_library.map(Candidate::tcc_library));
    list.push(Candidate::executable("tcc"));
    list
}

/// No candidate worked. Displays what was tried, and why each failed.
#[derive(Debug)]
pub struct ResolveError {
    /// Each candidate tried, with the reason it didn't work.
    pub attempts: Vec<(Candidate, String)>,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no working compiler. tried:")?;
        if self.attempts.is_empty() {
            write!(f, " nothing (no candidates)")?;
        }
        for (i, (candidate, reason)) in self.attempts.iter().enumerate() {
            write!(f, "\n  {}. {}: {}", i + 1, candidate.describe(), reason.replace('\n', "\n      "))?;
        }
        Ok(())
    }
}

impl std::error::Error for ResolveError {}

// ============================ the compiler =============================

/// What a [`Compiler`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerKind {
    /// A compiler program, run for each compile.
    Executable,
    /// libtcc, loaded into this process.
    Tcc,
}

/// A resolved compiler: it has been found and shown to compile a test program.
/// Cheap to clone and share between threads; compile with it as often as you
/// like. A [`Library`] keeps what it needs alive, so it can outlive this.
#[derive(Clone)]
pub struct Compiler {
    backend: Backend,
    candidate: usize,
}

#[derive(Clone)]
enum Backend {
    /// A compiler program, with the candidate's extra args.
    Executable { path: PathBuf, args: Vec<String> },
    Tcc(Arc<Tcc>),
}

const PROBE: &str = if cfg!(windows) {
    "#include <stddef.h>\n__declspec(dllexport) size_t c_aot_probe(void) { return 1; }\n"
} else {
    "#include <stddef.h>\nsize_t c_aot_probe(void) { return 1; }\n"
};

impl Compiler {
    /// Tries the candidates in order and returns the first that works: an
    /// executable that compiles a test program, or a libtcc that does. Nothing
    /// is searched beyond the candidates, so "only tcc" is a list of one
    /// [`Candidate::TccLibrary`]. Resolving isn't cheap (it compiles a test
    /// program): do it once.
    pub fn resolve(candidates: &[Candidate]) -> Result<Compiler, ResolveError> {
        let mut attempts = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            match try_candidate(candidate, index) {
                Ok(compiler) => return Ok(compiler),
                Err(reason) => attempts.push((candidate.clone(), reason)),
            }
        }
        Err(ResolveError { attempts })
    }

    /// [`Compiler::resolve`] with [`fast_candidates`]: the fastest generated
    /// code. `bundled_tcc_library` is optional: a libtcc you bundle with your
    /// app, or `None`.
    pub fn resolve_fast(bundled_tcc_library: Option<&Path>) -> Result<Compiler, ResolveError> {
        Compiler::resolve(&fast_candidates(bundled_tcc_library))
    }

    /// [`Compiler::resolve`] with [`memory_first_candidates`].
    /// `bundled_tcc_library` is optional: a libtcc you bundle with your app, or
    /// `None`.
    pub fn resolve_memory_first(bundled_tcc_library: Option<&Path>) -> Result<Compiler, ResolveError> {
        Compiler::resolve(&memory_first_candidates(bundled_tcc_library))
    }

    /// The index of the candidate that was chosen.
    pub fn candidate(&self) -> usize {
        self.candidate
    }

    /// Whether this runs a program or is libtcc.
    pub fn kind(&self) -> CompilerKind {
        match self.backend {
            Backend::Executable { .. } => CompilerKind::Executable,
            Backend::Tcc(_) => CompilerKind::Tcc,
        }
    }

    /// The executable (made absolute, symlinks kept), or the libtcc as given.
    pub fn path(&self) -> &Path {
        match &self.backend {
            Backend::Executable { path, .. } => path,
            Backend::Tcc(tcc) => &tcc.library_path,
        }
    }

    /// Compiles `source` (C) and loads it.
    ///
    /// There are no args here: what a compiler is given is part of its
    /// candidate (extra args for a program, a configure function for tcc). To
    /// vary something per compile, put it in the source (a `#define` line).
    ///
    /// See the crate docs for the security caveats.
    pub fn compile(&self, source: &str) -> Result<Library, Error> {
        match &self.backend {
            Backend::Executable { path, args } => compile_executable(path, args, source),
            Backend::Tcc(tcc) => compile_tcc(tcc, source),
        }
    }
}

impl fmt::Debug for Compiler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compiler")
            .field("kind", &self.kind())
            .field("path", &self.path())
            .field("candidate", &self.candidate)
            .finish()
    }
}

/// Resolves one candidate, then proves it works.
fn try_candidate(candidate: &Candidate, index: usize) -> Result<Compiler, String> {
    let backend = match candidate {
        Candidate::Executable { program, args } => Backend::Executable { path: exe_from_value(program.as_os_str())?, args: args.clone() },
        Candidate::Env { variable, args } => {
            let value = match std::env::var_os(variable) {
                Some(v) if !v.is_empty() => v,
                _ => return Err("not set".to_owned()),
            };
            let path = exe_from_value(&value).map_err(|why| format!("set to \"{}\": {why}", value.to_string_lossy()))?;
            Backend::Executable { path, args: args.clone() }
        }
        Candidate::TccLibrary { library, configure } => Backend::Tcc(Arc::new(Tcc::load(library, configure.clone())?)),
    };
    let compiler = Compiler { backend, candidate: index };
    let lib = compiler
        .compile(PROBE)
        .map_err(|e| format!("failed to compile a test program:\n{e}"))?;
    // SAFETY: the probe defines `size_t c_aot_probe(void)`; it's only looked up.
    if unsafe { lib.get::<extern "C" fn() -> usize>(c"c_aot_probe") }.is_none() {
        return Err("the test program compiled, but its symbol wasn't found".to_owned());
    }
    Ok(compiler)
}

#[cfg(windows)]
const DIR_SEPARATORS: &[char] = &['/', '\\', ':'];
#[cfg(not(windows))]
const DIR_SEPARATORS: &[char] = &['/'];

/// Like a shell: a name with a directory separator is a path, not searched.
fn has_dir_separator(s: &OsStr) -> bool {
    s.to_string_lossy().contains(DIR_SEPARATORS)
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// The executable at `path` (Windows: also `path.exe`), made absolute. Symlinks
/// are kept: a compiler may go by the name it was started under (`cc` -> clang).
fn exe_at(path: &Path) -> Result<PathBuf, String> {
    // Windows: `path.exe` first. An extensionless file of the same name next to
    // it (a shell script, as Git Bash and MSYS have) can't be started.
    #[cfg(windows)]
    let found = {
        let mut with_exe = path.as_os_str().to_owned();
        with_exe.push(".exe");
        let with_exe = PathBuf::from(with_exe);
        if is_executable(&with_exe) {
            Some(with_exe)
        } else {
            is_executable(path).then(|| path.to_path_buf())
        }
    };
    #[cfg(not(windows))]
    let found = is_executable(path).then(|| path.to_path_buf());
    let found = found.ok_or("no such executable file")?;
    std::path::absolute(&found).map_err(|e| format!("making the path absolute: {e}"))
}

/// Finds an executable like a shell: a value with a directory separator is a
/// path, any other is searched for in `PATH`.
fn exe_from_value(value: &OsStr) -> Result<PathBuf, String> {
    let found = if has_dir_separator(value) {
        exe_at(Path::new(value))
    } else {
        exe_in_path(value)
    };
    found.map_err(|why| {
        if value.to_string_lossy().contains([' ', '\t']) {
            format!("{why} (note: arguments aren't supported, it must be a program only)")
        } else {
            why
        }
    })
}

/// The first executable called `name` in `PATH`. Empty `PATH` entries (the
/// current directory, in a shell) are skipped on purpose.
fn exe_in_path(name: &OsStr) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or("PATH is not set")?;
    std::env::split_paths(&path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .find_map(|dir| exe_at(&dir.join(name)).ok())
        .ok_or_else(|| "not found in PATH".to_owned())
}

// ================================= tcc =================================

/// libtcc keeps global state, so everything that uses it holds this lock.
static TCC_LOCK: Mutex<()> = Mutex::new(());

fn tcc_lock() -> std::sync::MutexGuard<'static, ()> {
    TCC_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

const TCC_OUTPUT_MEMORY: c_int = 1;


pub type ErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char);

/// The libtcc entry points, resolved by name from the loaded library. The
/// first group is always there; a libtcc without one of the second group (an
/// older one) leaves it `None`. Calling any of them is unsafe: the state must be
/// a live tcc state, the strings NUL terminated.
#[derive(Debug, Clone, Copy)]
pub struct TccApi {
    pub new: unsafe extern "C" fn() -> *mut c_void,
    pub delete: unsafe extern "C" fn(*mut c_void),
    pub set_lib_path: unsafe extern "C" fn(*mut c_void, *const c_char),
    pub set_error_func: unsafe extern "C" fn(*mut c_void, *mut c_void, Option<ErrorFunc>),
    pub set_output_type: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    pub add_include_path: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    pub define_symbol: unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char),
    pub add_library_path: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    pub add_library: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    pub compile_string: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
    // tcc 0.9.27 takes (state, ptr), newer versions (state). it's called with
    // both: the extra argument is harmless to the newer one
    pub relocate: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int,
    pub get_symbol: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,

    /// gcc style options in one string, as on tcc's command line. An option
    /// tcc doesn't know makes tcc 0.9.27 exit the whole process (newer ones
    /// return -1), and that version returns nothing: don't rely on the result.
    pub set_options: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int>,
    pub add_sysinclude_path: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int>,
    pub undefine_symbol: Option<unsafe extern "C" fn(*mut c_void, *const c_char)>,
    /// Makes a symbol of your program visible to the compiled code.
    pub add_symbol: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void) -> c_int>,
    pub add_file: Option<unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int>,
}

/// A new tcc state, as passed to a [`TccConfigure`] function.
#[derive(Debug, Clone, Copy)]
pub struct TccState<'a> {
    /// The non-null result of `tcc_new()`. It has its error function, support
    /// directory and memory output already set.
    pub state: NonNull<c_void>,
    /// libtcc's functions, to call on `state`.
    pub api: &'a TccApi,
}

/// A function called before every single compile, not once: each compile
/// gets a fresh tcc state, and this sets options on it directly (through
/// [`TccState::api`]) before the source is compiled. Return `Ok` to
/// carry on and compile the source, or `Err` to stop before it is compiled
/// (the compile then returns an error saying so). It runs for the test program
/// when resolving too, and
/// under libtcc's global lock: don't compile from inside it. A panic in it is
/// turned into an error. Build one with [`TccConfigure::new`], or use
/// [`Candidate::tcc_library_with`].
#[derive(Clone)]
pub struct TccConfigure(Arc<ConfigureFn>);

type ConfigureFn = dyn Fn(&TccState<'_>) -> Result<(), String> + Send + Sync;

impl TccConfigure {
    pub fn new(configure: impl Fn(&TccState<'_>) -> Result<(), String> + Send + Sync + 'static) -> TccConfigure {
        TccConfigure(Arc::new(configure))
    }
}

impl fmt::Debug for TccConfigure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TccConfigure(..)")
    }
}

/// Two are equal if they are the same function (the same `Arc`).
impl PartialEq for TccConfigure {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for TccConfigure {}

/// A loaded libtcc.
struct Tcc {
    library: NonNull<c_void>,
    library_path: PathBuf,
    api: TccApi,
    support_dir: Option<PathBuf>,
    configure: Option<TccConfigure>,
}

// The library handle is never mutated, and the api is only called under the lock.
unsafe impl Send for Tcc {}
unsafe impl Sync for Tcc {}

impl Drop for Tcc {
    fn drop(&mut self) {
        // SAFETY: the handle came from the loader and is unloaded exactly once.
        unsafe { sys::unload(self.library.as_ptr()) };
    }
}

impl Tcc {
    fn load(library_path: &Path, configure: Option<TccConfigure>) -> Result<Tcc, String> {
        let library = sys::load_tcc(library_path)?;
        let handle = library.as_ptr();
        /// # Safety
        /// `T` must be the type of the libtcc function called `name`.
        unsafe fn function<T: Copy>(handle: *mut c_void, name: &'static CStr) -> Result<T, String> {
            // SAFETY: handle is a live library handle.
            let ptr = unsafe { sys::symbol(handle, name) };
            if ptr.is_null() {
                return Err(format!("not a usable libtcc: no {}", name.to_string_lossy()));
            }
            // SAFETY: T is a function pointer, the same size as a data pointer.
            Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&ptr) })
        }
        /// # Safety
        /// `T` must be the type of the libtcc function called `name`.
        unsafe fn optional<T: Copy>(handle: *mut c_void, name: &'static CStr) -> Option<T> {
            // SAFETY: as for `function`.
            unsafe { function(handle, name) }.ok()
        }
        // SAFETY: the types are libtcc's (see libtcc.h).
        let api = unsafe {
            (|| {
                Ok(TccApi {
                    new: function(handle, c"tcc_new")?,
                    delete: function(handle, c"tcc_delete")?,
                    set_lib_path: function(handle, c"tcc_set_lib_path")?,
                    set_error_func: function(handle, c"tcc_set_error_func")?,
                    set_output_type: function(handle, c"tcc_set_output_type")?,
                    add_include_path: function(handle, c"tcc_add_include_path")?,
                    define_symbol: function(handle, c"tcc_define_symbol")?,
                    add_library_path: function(handle, c"tcc_add_library_path")?,
                    add_library: function(handle, c"tcc_add_library")?,
                    compile_string: function(handle, c"tcc_compile_string")?,
                    relocate: function(handle, c"tcc_relocate")?,
                    get_symbol: function(handle, c"tcc_get_symbol")?,
                    set_options: optional(handle, c"tcc_set_options"),
                    add_sysinclude_path: optional(handle, c"tcc_add_sysinclude_path"),
                    undefine_symbol: optional(handle, c"tcc_undefine_symbol"),
                    add_symbol: optional(handle, c"tcc_add_symbol"),
                    add_file: optional(handle, c"tcc_add_file"),
                })
            })()
        };
        let api = match api {
            Ok(api) => api,
            Err(reason) => {
                // SAFETY: just loaded, nothing else uses it.
                unsafe { sys::unload(handle) };
                return Err(reason);
            }
        };
        let support_dir = support_files_next_to(library_path);
        Ok(Tcc {
            library,
            library_path: library_path.to_path_buf(),
            api,
            support_dir,
            configure,
        })
    }
}

/// The directory of the libtcc at `library_path`, if tcc's support files are
/// in it (`libtcc1.a`, or `lib/libtcc1.a` as on Windows). Otherwise (also for a
/// bare name, whose directory isn't known) `None`: tcc then uses its own
/// built-in location, which is right for an installed tcc.
fn support_files_next_to(library_path: &Path) -> Option<PathBuf> {
    let dir = library_path.parent().filter(|d| !d.as_os_str().is_empty())?;
    (dir.join("libtcc1.a").is_file() || dir.join("lib").join("libtcc1.a").is_file()).then(|| dir.to_path_buf())
}

/// Code compiled in memory by tcc. The state owns the code.
struct TccCode {
    state: NonNull<c_void>,
    tcc: Arc<Tcc>,
}

impl TccCode {
    fn symbol(&self, name: &CStr) -> *mut c_void {
        let _guard = tcc_lock();
        // SAFETY: the state is live, name is NUL terminated.
        unsafe { (self.tcc.api.get_symbol)(self.state.as_ptr(), name.as_ptr()) }
    }
}

impl Drop for TccCode {
    fn drop(&mut self) {
        let _guard = tcc_lock();
        // SAFETY: the state is deleted exactly once; `tcc` (the library) is
        // dropped after this body.
        unsafe { (self.tcc.api.delete)(self.state.as_ptr()) };
    }
}

/// libtcc's error callback: keeps the first bytes of what it reports.
unsafe extern "C" fn on_tcc_error(opaque: *mut c_void, message: *const c_char) {
    // SAFETY: opaque is the `Vec` passed to set_error_func, message a C string.
    let (errors, message) = unsafe { (&mut *opaque.cast::<Vec<u8>>(), CStr::from_ptr(message)) };
    let room = STDERR_CAPACITY.saturating_sub(errors.len());
    errors.extend(message.to_bytes().iter().take(room));
    if errors.len() < STDERR_CAPACITY {
        errors.push(b'\n');
    }
}

fn compile_tcc(tcc: &Arc<Tcc>, source: &str) -> Result<Library, Error> {
    let text = CString::new(source).map_err(|_| Error::Tcc("source contains a NUL byte".to_owned()))?; // tcc wants a C string
    let api = &tcc.api;
    let mut errors: Vec<u8> = Vec::new();

    let guard = tcc_lock();
    // SAFETY: tcc_new has no preconditions.
    let state = NonNull::new(unsafe { (api.new)() }).ok_or_else(|| Error::Tcc("tcc_new failed".to_owned()))?;
    let state_ptr = state.as_ptr();
    let compiled = (|| {
        // SAFETY: the state is live and the lock is held. `errors` outlives
        // every call that can report to it (the state is deleted or handed to
        // the result, which replaces the callback's target below, before it
        // is dropped).
        unsafe {
            (api.set_error_func)(state_ptr, (&mut errors as *mut Vec<u8>).cast(), Some(on_tcc_error));
            if let Some(dir) = &tcc.support_dir {
                let dir = CString::new(dir.as_os_str().to_string_lossy().as_bytes())
                    .map_err(|_| Error::Tcc("the support directory contains a NUL byte".to_owned()))?;
                (api.set_lib_path)(state_ptr, dir.as_ptr());
            }
            if (api.set_output_type)(state_ptr, TCC_OUTPUT_MEMORY) < 0 {
                return Err(Error::Tcc("tcc_set_output_type failed".to_owned()));
            }
            // the candidate's configure function sets options on the state, as
            // a compiler program gets the candidate's args
            if let Some(configure) = &tcc.configure {
                let state = TccState { state, api };
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (configure.0)(&state))) {
                    Ok(Ok(())) => {}
                    Ok(Err(why)) => {
                        return Err(Error::Tcc(format!("the configure function stopped the compile: {why}. diagnostics:\n{}", String::from_utf8_lossy(&errors))))
                    }
                    Err(_) => return Err(Error::Tcc("the configure function panicked".to_owned())),
                }
            }
            if (api.compile_string)(state_ptr, text.as_ptr()) < 0 || (api.relocate)(state_ptr, std::ptr::without_provenance_mut(1) /* TCC_RELOCATE_AUTO */) < 0 {
                return Err(Error::Tcc(format!("failed. diagnostics:\n{}", String::from_utf8_lossy(&errors))));
            }
            // no more errors to report: don't leave the callback pointing at `errors`
            (api.set_error_func)(state_ptr, std::ptr::null_mut(), None);
        }
        Ok(())
    })();
    match compiled {
        Ok(()) => {
            drop(guard);
            Ok(Library {
                repr: Repr::Tcc(TccCode { state, tcc: Arc::clone(tcc) }),
            })
        }
        Err(e) => {
            // SAFETY: the state is live, deleted exactly once, under the lock.
            unsafe { (api.delete)(state_ptr) };
            Err(e)
        }
    }
}

// ============================= executables =============================

/// Runs `compiler` (a path) without resolving it first. Only for this crate's
/// tests, which need a compiler that dies mid-compile.
#[doc(hidden)]
pub fn __compile_with_executable(compiler: &Path, args: &[&str], source: &str) -> Result<Library, Error> {
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    compile_executable(compiler, &args, source)
}

/// Linux: the source and the library of a compiler program live in memory
/// files (`memfd_create`), so neither touches disk. Everywhere else, or with
/// the `no_memory_files` feature, `files` is `None` and a private temp
/// directory holds them.
#[cfg(all(target_os = "linux", not(feature = "no_memory_files")))]
mod memory {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};

    fn memfd(name: &CStr) -> io::Result<File> {
        // SAFETY: name is a C string; the new fd is owned by the File.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    /// The source's and the library's memory files, if the system has them
    /// (and `/dev/fd`, which the compiler writes its output through).
    pub fn files() -> Option<(File, File)> {
        if !Path::new("/dev/fd/0").exists() {
            return None;
        }
        Some((memfd(c"c_aot_source").ok()?, memfd(c"c_aot_library").ok()?))
    }

    /// The `TMPDIR` for the compiler, when its source and library are in
    /// memory files: `/dev/shm`, a memory file system, if it is a writable
    /// directory, even if the caller set `TMPDIR`: the point of memory files
    /// is to stay off disk.
    pub fn child_tmpdir() -> Option<PathBuf> {
        let shm = Path::new("/dev/shm");
        let c_path = CString::new("/dev/shm").expect("no NUL");
        // SAFETY: c_path is NUL terminated.
        let writable = unsafe { libc::access(c_path.as_ptr(), libc::W_OK | libc::X_OK) } == 0;
        (shm.is_dir() && writable).then(|| shm.to_path_buf())
    }

    /// Loads the library in a memory file. The loader names a library by the
    /// path it was opened with and hands back the library already loaded under
    /// that name, so a name used before (an fd number reused while an earlier
    /// library is still mapped, because `dlclose` doesn't always unload) can't
    /// be used again: `./` components make a new name for the same file.
    pub fn load(file: &File) -> Result<NonNull<c_void>, String> {
        for extra in 0..64 {
            let path = format!("/proc/self/fd/{}{}", "./".repeat(extra), file.as_raw_fd());
            let c_path = CString::new(path.as_str()).expect("no NUL in the path");
            // SAFETY: c_path is NUL terminated.
            let taken = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
            if !taken.is_null() {
                // SAFETY: taken is a handle we were just given.
                unsafe { libc::dlclose(taken) };
                continue;
            }
            return sys::load(Path::new(&path));
        }
        Err("no unused name for the library".to_owned())
    }
}

#[cfg(not(all(target_os = "linux", not(feature = "no_memory_files"))))]
mod memory {
    use super::*;

    pub fn files() -> Option<(File, File)> {
        None
    }

    #[allow(dead_code)]
    pub fn child_tmpdir() -> Option<PathBuf> {
        None
    }

    #[allow(dead_code)]
    pub fn load(_file: &File) -> Result<NonNull<c_void>, String> {
        unreachable!("no memory files on this system")
    }
}

fn compile_executable(compiler: &Path, candidate_args: &[String], source: &str) -> Result<Library, Error> {
    // declared first, so it's dropped (removed) last: after the child is
    // waited on and every file in it is closed
    let dir: Option<TempDir>;
    let mut src: File;
    let lib_arg: PathBuf; // what the compiler is told to write to
    let stdout: Stdio;
    let memory_library: Option<File>;
    // the compiler's own temporary files go where its TMPDIR says: with a temp
    // directory, that private directory (contained, and removed with it); with
    // memory files, a memory file system. unix only: Windows compilers look at
    // TMP / TEMP, which this doesn't change
    let child_tmpdir: Option<PathBuf>;
    match memory::files() {
        Some((memory_source, library)) => {
            // the compiler writes the library to its stdout, a memory file
            dir = None;
            src = memory_source;
            lib_arg = PathBuf::from("/dev/fd/1");
            stdout = Stdio::from(library.try_clone().map_err(io_err("duplicating the library file"))?);
            memory_library = Some(library);
            child_tmpdir = memory::child_tmpdir();
        }
        None => {
            let temp = sys::temp_dir()?;
            // source -> file, unlinked at once, which becomes the compiler's stdin
            src = sys::create_source(&temp.0.join("src.c")).map_err(io_err("creating source file"))?;
            lib_arg = temp.0.join(sys::LIB_NAME);
            stdout = Stdio::null();
            memory_library = None;
            child_tmpdir = cfg!(unix).then(|| temp.0.clone());
            dir = Some(temp);
        }
    }
    src.write_all(source.as_bytes())
        .map_err(io_err("writing source"))?;
    src.rewind().map_err(io_err("rewinding source"))?;

    let mut command = Command::new(compiler);
    command
        .args(["-pipe", "-shared", "-O1", "-xc"])
        .args(sys::EXTRA_FLAGS)
        .arg("-o")
        .arg(&lib_arg)
        .arg("-")
        .args(candidate_args)
        .stdin(Stdio::from(src))
        .stdout(stdout)
        .stderr(Stdio::piped());
    if let Some(tmpdir) = &child_tmpdir {
        command.env("TMPDIR", tmpdir);
    }
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
    let (code, handle, kept_dir) = match memory_library {
        Some(library) => {
            let handle = memory::load(&library).map_err(Error::Load)?;
            (library, handle, None)
        }
        None => {
            let code = sys::open_library_file(&lib_arg).map_err(io_err("opening library"))?;
            // random directory, so this path is unique
            let handle = sys::load(&lib_arg).map_err(Error::Load)?;
            (code, handle, if sys::KEEP_DIR_WHILE_LOADED { dir } else { None })
        }
    };
    Ok(Library {
        repr: Repr::Loaded {
            handle,
            _code: code,
            _dir: kept_dir,
        },
    })
}

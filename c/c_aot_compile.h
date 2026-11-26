#pragma once

/**
 * ahead of time compilation using a c compiler. c source is compiled, then loaded.
 *
 * linux and macos (posix_spawn, mkdtemp, dlopen; likely other posix systems
 * too) and windows (CreateProcess, LoadLibrary; needs a gcc style compiler
 * driver such as mingw gcc, clang or tcc, see the windows notes below). link
 * with -ldl -lpthread on linux with glibc < 2.34 (nothing extra newer, or on
 * macos or windows). _GNU_SOURCE is defined here if
 * missing, but only works if this header comes before any system header;
 * otherwise define it yourself.
 *
 * usage: resolve a compiler once (a preset: c_aot_compiler_resolve_fast or
 * c_aot_compiler_resolve_memory_first, or your own list of candidates), then
 * c_aot_compile(&compiler, source, size) any
 * number of times. a candidate is a path, a program name looked up in PATH, an
 * environment variable (like CC), or a libtcc shared object. libtcc is not
 * part of this header and is loaded at run time with dlopen / LoadLibrary, so
 * a program using this header runs (and says what is missing) without it.
 * with a libtcc, code is compiled in this process, to memory.
 *
 * design of the executable backend (each point removes a class of bugs).
 * the compiler is run as:
 *   <compiler> -pipe -fPIC -shared -O1 -DC_AOT_EXPORT=... -xc -o <library> - <candidate's args>
 * (no -fPIC on windows). the candidate's args come last, so a later -O2 or -O0
 * overrides the -O1. C_AOT_EXPORT is defined in every compile (libtcc too):
 * mark what your code must export with it, as in
 *   C_AOT_EXPORT int f(void) { return 1; }
 * it is __declspec(dllexport) on windows (which toolchains other than mingw
 * gcc need), and nothing elsewhere.
 * - the source is a file, which is the compiler's stdin: no pipe to feed, so
 *   no deadlock, short write or SIGPIPE handling.
 * - the compiler writes the library to a file, and the library's fd is kept
 *   open while it is loaded, so its inode can't be reused.
 * - where those files are depends on the system (see "files" below). the
 *   name the library is loaded by is always unique (dlopen would otherwise
 *   return an already loaded library of the same name).
 * - the compiler is started with posix_spawn, so no code runs in a forked
 *   child of this (possibly threaded) process.
 * - every fd is close-on-exec and numbered >= 10, so nothing leaks into our
 *   child and nothing collides with the standard fds. (the stderr pipe is
 *   made close-on-exec just after it's created, so another thread spawning a
 *   program at that very instant could inherit it.)
 *
 * files:
 * - linux: the source and the library are memory files (memfd_create), and
 *   never touch disk. the compiler writes the library to its stdout, a memory
 *   file, by the path /dev/fd/1, and the library is loaded from
 *   /proc/self/fd/<fd>. so a compiler program (or a wrapper around one, such as
 *   a CC script) must not write anything to its stdout: that would land in the
 *   library and corrupt it (resolving then fails with "invalid ELF header").
 *   compilers don't, and their diagnostics go to stderr. a wrapper that does
 *   can redirect its own output to stderr, or use C_AOT_NO_MEMORY_FILES. if the kernel has no memfd_create, or no /dev/fd, the
 *   next case applies. define C_AOT_NO_MEMORY_FILES to use it anyway.
 * - everywhere else (macos, other unix, windows): each compile gets a fresh
 *   private (0700) directory from mkdtemp, under TMPDIR (or /tmp), holding the
 *   source (unlinked right away) and the library. it is removed before
 *   returning, whether the compile succeeded or not. these systems have no
 *   memory file a compiler can open by path. to keep the files in memory
 *   anyway, point TMPDIR at a memory file system.
 * - either way, what a compiler writes itself while it works (gcc leaves
 *   intermediate files in TMPDIR even with -pipe) goes where its TMPDIR says,
 *   and the compiler's TMPDIR is set by this header (unix; not windows):
 *   with a temp directory, to that private directory, so those files are
 *   contained and removed with it. with memory files, to /dev/shm if it is a
 *   writable directory, even if your TMPDIR is set (if /dev/shm isn't usable,
 *   yours is left as it is). this is the only change to the compiler's
 *   environment. (define C_AOT_NO_MEMORY_FILES to have everything under your
 *   TMPDIR instead.)
 * between the compiler exiting and dlopen, a process running as the same user
 * could modify a library on disk. a memory file has no path to open by.
 *
 * windows notes: the same design, with these differences.
 * - the directory is created under GetTempPath (TMP / TEMP) and inherits that
 *   directory's permissions (a user's default temp directory is private).
 * - the source file is deleted when its last handle closes. the compiler
 *   inherits exactly three handles (stdin, stdout, stderr), listed explicitly,
 *   so nothing else leaks into it.
 * - a loaded dll can't be deleted, so the library file is opened with
 *   delete-on-close and kept open while loaded; the directory is removed by
 *   c_aot_compile_result_destroy.
 * - the presets try gcc, clang, cc in that order (not cc, gcc, clang), and
 *   the library is named lib.dll. -fPIC isn't passed.
 * - symbols must be exported to be found: mingw gcc exports every global
 *   symbol unless something is marked dllexport; clang (msvc target) and
 *   others need __declspec(dllexport) on what you look up. C_AOT_EXPORT (see
 *   above) is that on windows, and nothing elsewhere: use it and the same
 *   source works everywhere.
 * - paths are handled in the ANSI code page, limited to MAX_PATH.
 * - use c_aot_compile_symbol instead of dlsym.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// linux: the source and the library of a compiler program live in memory files
// (memfd_create) and never touch disk. define C_AOT_NO_MEMORY_FILES to use a
// private temp directory there too, as every other system does
#if defined(__linux__) && !defined(C_AOT_NO_MEMORY_FILES)
#define C_AOT_MEMORY_FILES 1
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // vista: PROC_THREAD_ATTRIBUTE_HANDLE_LIST
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <spawn.h>
#ifdef C_AOT_MEMORY_FILES
#include <sys/mman.h>
#include <sys/syscall.h>
#endif
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h> // _NSGetEnviron: environ isn't declared, nor usable from a dylib
#endif
#endif

// ============================ compilers ================================

// the libtcc entry points (resolved by name from the loaded library). the
// first group is always there; a libtcc without one of the second group (an
// older one) leaves it NULL, so check before calling
struct c_aot_tcc_api {
  void* (*tcc_new)(void);
  void (*tcc_delete)(void*);
  void (*tcc_set_lib_path)(void*, const char*);
  void (*tcc_set_error_func)(void*, void*, void (*)(void*, const char*));
  int (*tcc_set_output_type)(void*, int);
  int (*tcc_add_include_path)(void*, const char*);
  void (*tcc_define_symbol)(void*, const char*, const char*);
  int (*tcc_add_library_path)(void*, const char*);
  int (*tcc_add_library)(void*, const char*);
  int (*tcc_compile_string)(void*, const char*);
  // tcc 0.9.27 takes (state, ptr), newer versions (state). it's called with
  // both: the extra argument is harmless to the newer one
  int (*tcc_relocate)(void*, void*);
  void* (*tcc_get_symbol)(void*, const char*);

  // may be NULL:
  // gcc style options in one string, as on tcc's command line. an option tcc
  // doesn't know makes tcc 0.9.27 exit the whole process (newer ones return
  // -1), and that version returns nothing: don't rely on the result
  int (*tcc_set_options)(void*, const char*);
  int (*tcc_add_sysinclude_path)(void*, const char*);
  void (*tcc_undefine_symbol)(void*, const char*);
  // makes a symbol of your program visible to the compiled code
  int (*tcc_add_symbol)(void*, const char*, const void*);
  int (*tcc_add_file)(void*, const char*);
};

// called before every single compile, not once: each compile gets a fresh
// tcc state, and this sets options on it directly, before the source is
// compiled (analogous to CLI args for the executable candidates,
// but for the lib instead). tcc_state is the non-NULL result of tcc_new(). it
// has its error function, support directory and memory output already set.
// return 0 to carry on and compile the source, or nonzero to stop before it is
// compiled (the compile then returns an error saying so). runs under libtcc's
// global lock: don't compile from inside it. it also runs for the test program
// when resolving
typedef int (*c_aot_tcc_configure)(void* tcc_state, const struct c_aot_tcc_api* api, void* user_data);

// a compiler is found by trying candidates in order (c_aot_compiler_resolve);
// the first that really works wins. each candidate is one of these, and has
// only what that kind can use:
enum c_aot_candidate_type {
  C_AOT_CANDIDATE_EXECUTABLE,
  C_AOT_CANDIDATE_ENV,
  C_AOT_CANDIDATE_TCC_LIBRARY,
};

// an executable, found like a shell does: with a directory separator it is a
// path (a relative one is relative to the current directory), else it is a name
// looked up in PATH. a program only: its args are separate
struct c_aot_candidate_executable {
  const char* compiler_exe_path_or_name;
  // extra compiler args: a NULL terminated list, or NULL for none. they come
  // after the fixed ones (-pipe -fPIC -shared -O1 -DC_AOT_EXPORT=... -xc -o
  // <library> -), so a
  // later -O2 overrides the -O1. copied when resolving, so the list need not
  // outlive it
  const char* const* args;
};

// the name of an environment variable, whose value is an executable as above.
// not set or empty: skipped
struct c_aot_candidate_env {
  const char* variable;
  const char* const* args; // as for an executable
};

// a libtcc shared object, found the same way (a path, or a bare name the system
// loader searches for). tcc also needs its support files, libtcc1.a and
// include/: if they are next to the library (libtcc1.a, or lib/libtcc1.a as on
// windows), that directory is used, as in an app that ships them together.
// otherwise tcc's own built-in location is used, as in a tcc that is
// installed. tcc then compiles in this process: no files, no child process
struct c_aot_candidate_tcc_library {
  const char* library_path_or_name;
  // sets options on each new tcc state, however you like. NULL: none
  c_aot_tcc_configure configure;
  // passed to configure, on every compile. only the pointer is copied, not what
  // it points to (and it is never freed here): that must stay valid until the
  // c_aot_resolve_result that holds the compiler is destroyed, not only until
  // resolving returns. the candidate list itself need not outlive resolving
  void* user_data;
};

union c_aot_candidate_value {
  struct c_aot_candidate_executable executable;
  struct c_aot_candidate_env env;
  struct c_aot_candidate_tcc_library tcc_library;
};

struct c_aot_candidate {
  enum c_aot_candidate_type type;
  union c_aot_candidate_value value;
  // the test program that proves this candidate works, or NULL for the
  // built-in one. C source (NUL terminated) that defines
  //   C_AOT_EXPORT int c_aot_test(void)
  // resolving compiles it with the candidate, loads it and calls c_aot_test:
  // it must return 0 (ok) to be accepted; anything else fails the candidate,
  // and the value is reported. C_AOT_EXPORT, which every compile defines,
  // exports it on windows too. only used while resolving: it need not outlive
  // it. the constructors below set NULL: set it on the result afterwards
  const char* test_source;
};

// args: NULL terminated, or NULL for none
static inline struct c_aot_candidate c_aot_candidate_executable(const char* compiler_exe_path_or_name, const char* const* args) {
  struct c_aot_candidate c;
  c.type = C_AOT_CANDIDATE_EXECUTABLE;
  c.value.executable.compiler_exe_path_or_name = compiler_exe_path_or_name;
  c.value.executable.args = args;
  c.test_source = NULL;
  return c;
}
static inline struct c_aot_candidate c_aot_candidate_env(const char* variable, const char* const* args) {
  struct c_aot_candidate c;
  c.type = C_AOT_CANDIDATE_ENV;
  c.value.env.variable = variable;
  c.value.env.args = args;
  c.test_source = NULL;
  return c;
}
// configure: may be NULL
static inline struct c_aot_candidate c_aot_candidate_tcc_library(const char* library_path_or_name, c_aot_tcc_configure configure, void* user_data) {
  struct c_aot_candidate c;
  c.type = C_AOT_CANDIDATE_TCC_LIBRARY;
  c.value.tcc_library.library_path_or_name = library_path_or_name;
  c.value.tcc_library.configure = configure;
  c.value.tcc_library.user_data = user_data;
  c.test_source = NULL;
  return c;
}

enum c_aot_compiler_type {
  C_AOT_COMPILER_EXECUTABLE, // a compiler program: see value.executable
  C_AOT_COMPILER_TCC,        // libtcc, in this process: see value.tcc
};

struct c_aot_compiler_executable {
  // the program: a path, made absolute (symlinks are kept). malloc'd
  char* path;
  // the candidate's extra args: a NULL terminated list, or NULL for none. malloc'd
  char** args;
};

struct c_aot_compiler_tcc {
  void* library;            // the loaded libtcc
  struct c_aot_tcc_api api; // the functions looked up in it
  c_aot_tcc_configure configure; // the candidate's, or NULL
  void* configure_user_data;
  // where tcc's support files (libtcc1.a, include/) are, applied on every
  // compile: the directory next to the library (see C_AOT_CANDIDATE_TCC_LIBRARY).
  // NULL: tcc's own built-in location. malloc'd
  char* support_dir;
};

union c_aot_compiler_value {
  // only if C_AOT_COMPILER_EXECUTABLE
  struct c_aot_compiler_executable executable;
  // only if C_AOT_COMPILER_TCC
  struct c_aot_compiler_tcc tcc;
};

// a working compiler. it can be used from several threads at once, and must
// outlive every c_aot_compile_result made with it (and must not be moved
// while one lives: tcc results point into it). it is owned by the
// c_aot_resolve_result that holds it
struct c_aot_compiler {
  enum c_aot_compiler_type type;
  // the index of the candidate that worked
  size_t candidate;
  union c_aot_compiler_value value;
};

enum c_aot_resolve_result_type {
  C_AOT_RESOLVE_OK,
  C_AOT_RESOLVE_ERR,
};

union c_aot_resolve_result_value {
  // only if C_AOT_RESOLVE_OK
  struct c_aot_compiler compiler;
  // only if C_AOT_RESOLVE_ERR: why no candidate worked, one line per
  // candidate. malloc'd. NULL only on alloc failure
  char* error_msg;
};

// an error message, or a compiler. free with c_aot_resolve_result_destroy, in
// both cases.
struct c_aot_resolve_result {
  enum c_aot_resolve_result_type type;
  union c_aot_resolve_result_value value;
};

// the code that was compiled, and what keeps it alive. it is one of these:
enum c_aot_code_type {
  C_AOT_CODE_LIBRARY, // a shared library, loaded (a compiler program made it)
  C_AOT_CODE_TCC,     // code in memory, owned by a tcc state (libtcc made it)
};

struct c_aot_code_library {
  void* handle; // dlopen / LoadLibrary
#ifdef _WIN32
  // the library file (a HANDLE, opened delete-on-close), kept open as long as
  // the library is loaded
  void* file;
  // the directory holding the library file. malloc'd. removed by destroy
  char* tmp_dir;
#else
  // the (already deleted) library file, kept open as long as the library is loaded
  int fd;
#endif
};

struct c_aot_code_tcc {
  // the compiler's libtcc functions: they live in the compiler, which
  // must outlive this
  const struct c_aot_tcc_api* api;
  // the tcc state that owns the code
  void* state;
};

union c_aot_code_value {
  // only if C_AOT_CODE_LIBRARY
  struct c_aot_code_library library;
  // only if C_AOT_CODE_TCC
  struct c_aot_code_tcc tcc;
};

struct c_aot_code {
  enum c_aot_code_type type;
  union c_aot_code_value value;
};

enum c_aot_compile_result_type {
  C_AOT_COMPILE_OK,
  C_AOT_COMPILE_ERR,
};

union c_aot_compile_result_value {
  // only if C_AOT_COMPILE_OK
  struct c_aot_code code;
  // only if C_AOT_COMPILE_ERR. malloc'd. NULL only on alloc failure
  char* error_msg;
};

// an error message, or the compiled code. free with c_aot_compile_result_destroy,
// in both cases.
struct c_aot_compile_result {
  enum c_aot_compile_result_type type;
  union c_aot_compile_result_value value;
};

static inline void c_aot_result_init(struct c_aot_compile_result* result) {
  result->type = C_AOT_COMPILE_ERR;
  result->value.error_msg = NULL;
}

static void c_aot_remove_dir(const char* dir);

// libtcc keeps global state, so everything that uses it holds this lock. (one
// per translation unit that includes this header; use the header from one
// translation unit if tcc is used from several threads)
static void c_aot_tcc_lock(void);
static void c_aot_tcc_unlock(void);

// ok: unload the library, then close the library file (or free the tcc
// state). err: free the message. the result must not be used afterwards.
static void c_aot_compile_result_destroy(struct c_aot_compile_result* result) {
  if (result->type == C_AOT_COMPILE_OK) {
    struct c_aot_code* code = &result->value.code;
    switch (code->type) {
    case C_AOT_CODE_LIBRARY: {
      struct c_aot_code_library* library = &code->value.library;
#ifdef _WIN32
      FreeLibrary((HMODULE)library->handle);
      CloseHandle((HANDLE)library->file); // deletes the library file
      c_aot_remove_dir(library->tmp_dir);
      free(library->tmp_dir);
#else
      dlclose(library->handle);
      close(library->fd);
#endif
      break;
    }
    case C_AOT_CODE_TCC:
      c_aot_tcc_lock();
      code->value.tcc.api->tcc_delete(code->value.tcc.state);
      c_aot_tcc_unlock();
      break;
    }
  } else {
    free(result->value.error_msg);
  }
  c_aot_result_init(result);
}

// looks up a symbol in the compiled code (dlsym / GetProcAddress / tcc_get_symbol).
// NULL if it's not found, or result isn't ok. the pointer is valid until
// c_aot_compile_result_destroy is called on this result. for tcc code it also
// needs the c_aot_resolve_result whose compiler made it: that must not be
// destroyed or moved yet (this result points into it).
static inline void* c_aot_compile_symbol(const struct c_aot_compile_result* result, const char* name) {
  if (result->type != C_AOT_COMPILE_OK) {
    return NULL;
  }
  const struct c_aot_code* code = &result->value.code;
  switch (code->type) {
  case C_AOT_CODE_LIBRARY: {
#ifdef _WIN32
    FARPROC proc = GetProcAddress((HMODULE)code->value.library.handle, name);
    void* symbol = NULL;
    memcpy(&symbol, &proc, sizeof(symbol)); // function pointer -> void*
    return symbol;
#else
    return dlsym(code->value.library.handle, name);
#endif
  }
  case C_AOT_CODE_TCC: {
    c_aot_tcc_lock();
    void* symbol = code->value.tcc.api->tcc_get_symbol(code->value.tcc.state, name);
    c_aot_tcc_unlock();
    return symbol;
  }
  }
  return NULL;
}

// ============================== internals ==============================

// getenv, without the deprecation warning msvc's headers give for it (an error
// under -Werror, which would make every user define _CRT_SECURE_NO_WARNINGS)
static const char* c_aot_getenv(const char* name) {
#if defined(_MSC_VER) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
  const char* value = getenv(name);
#if defined(_MSC_VER) && defined(__clang__)
#pragma clang diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif
  return value;
}

// errno / GetLastError as text. passed as an argument to c_aot_set_err (macos
// printf has no %m), so it's evaluated before anything in there could change
// the error. on windows it needs a char c_aot_errbuf[C_AOT_ERRBUF_SIZE] local
#ifdef _WIN32
enum { C_AOT_ERRBUF_SIZE = 256 };
static const char* c_aot_win_strerror(char* buf, size_t size, DWORD code) {
  DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0, buf, (DWORD)size, NULL);
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '.')) {
    buf[--n] = '\0';
  }
  if (n == 0) {
    snprintf(buf, size, "error %lu", (unsigned long)code);
  }
  return buf;
}
#define C_AOT_ERRNO c_aot_win_strerror(c_aot_errbuf, sizeof(c_aot_errbuf), GetLastError())
#else
#define C_AOT_ERRNO strerror(errno)
#endif

// sets result to err with a printf-style message
static void c_aot_set_err(struct c_aot_compile_result* result, const char* format, ...) {
  va_list args, args_again;
  va_start(args, format);
  va_copy(args_again, args);
  int needed = vsnprintf(NULL, 0, format, args);
  va_end(args);
  char* msg = NULL;
  if (needed >= 0 && (msg = malloc((size_t)needed + 1)) != NULL) {
    vsnprintf(msg, (size_t)needed + 1, format, args_again);
  }
  va_end(args_again);
  result->type = C_AOT_COMPILE_ERR;
  result->value.error_msg = msg;
}

enum { C_AOT_STDERR_CAPACITY = 1024 };

#ifndef _WIN32

// moves fd to a number >= 10 with close-on-exec (the standard fds can then
// never collide). consumes fd, returns -1 on failure
static int c_aot_fd_high(int fd) {
  if (fd == -1) {
    return -1;
  }
  int moved = fcntl(fd, F_DUPFD_CLOEXEC, 10);
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return moved;
}

static bool c_aot_write_all(int fd, const char* data, size_t size) {
  while (size > 0) {
    ssize_t n = write(fd, data, size);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    data += n;
    size -= (size_t)n;
  }
  return true;
}

static char** c_aot_environ(void) {
#ifdef __APPLE__
  return *_NSGetEnviron();
#else
  return environ;
#endif
}

// a copy of the environment with name set to value, for a child. one
// allocation: free it with free(). NULL if out of memory
static char** c_aot_environ_with(const char* name, const char* value) {
  char** env = c_aot_environ();
  size_t count = 0;
  while (env[count]) {
    ++count;
  }
  size_t name_len = strlen(name);
  size_t entry_size = name_len + 1 + strlen(value) + 1;
  char** copy = malloc((count + 2) * sizeof(*copy) + entry_size);
  if (!copy) {
    return NULL;
  }
  char* entry = (char*)(copy + count + 2); // the new entry lives after the pointers
  snprintf(entry, entry_size, "%s=%s", name, value);
  size_t n = 0;
  for (size_t i = 0; i < count; ++i) {
    if (strncmp(env[i], name, name_len) != 0 || env[i][name_len] != '=') {
      copy[n++] = env[i];
    }
  }
  copy[n++] = entry;
  copy[n] = NULL;
  return copy;
}

static bool c_aot_is_writable_dir(const char* path) {
  struct stat st;
  return stat(path, &st) == 0 && S_ISDIR(st.st_mode) && access(path, W_OK | X_OK) == 0;
}

// removes dir and the files in it (the compiler may leave some behind on
// failure; it makes no subdirectories). errors are ignored: best effort
static void c_aot_remove_dir(const char* dir) {
  DIR* d = opendir(dir);
  if (d) {
    struct dirent* entry;
    while ((entry = readdir(d)) != NULL) {
      if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
        unlinkat(dirfd(d), entry->d_name, 0);
      }
    }
    closedir(d);
  }
  rmdir(dir);
}
#endif // !_WIN32

// ============================ executables ==============================

// compiles with the executable at c_compiler (a path; already resolved). see
// c_aot_compile for the rest. the platform specific part:
#ifdef _WIN32

enum { C_AOT_PATH_MAX = 1024 };

// removes dir and the files in it. errors are ignored: best effort
static void c_aot_remove_dir(const char* dir) {
  char pattern[C_AOT_PATH_MAX + 4];
  if (snprintf(pattern, sizeof(pattern), "%s\\*", dir) < (int)sizeof(pattern)) {
    WIN32_FIND_DATAA entry;
    HANDLE find = FindFirstFileA(pattern, &entry);
    if (find != INVALID_HANDLE_VALUE) {
      do {
        if (strcmp(entry.cFileName, ".") != 0 && strcmp(entry.cFileName, "..") != 0) {
          char path[C_AOT_PATH_MAX + MAX_PATH + 2];
          if (snprintf(path, sizeof(path), "%s\\%s", dir, entry.cFileName) < (int)sizeof(path)) {
            DeleteFileA(path);
          }
        }
      } while (FindNextFileA(find, &entry));
      FindClose(find);
    }
  }
  RemoveDirectoryA(dir);
}

// appends arg to out, quoted so that CommandLineToArgvW / the msvc crt parse
// it back to exactly arg. out needs 2 * strlen(arg) + 3 bytes. returns the end
static char* c_aot_win_append_arg(char* out, const char* arg) {
  bool plain = arg[0] != '\0' && strpbrk(arg, " \t\n\v\"") == NULL;
  if (plain) {
    size_t len = strlen(arg);
    memcpy(out, arg, len);
    return out + len;
  }
  *out++ = '"';
  while (true) {
    size_t backslashes = 0;
    while (*arg == '\\') {
      ++arg;
      ++backslashes;
    }
    if (*arg == '\0') {
      // the closing quote follows: double the backslashes before it
      for (size_t i = 0; i < backslashes * 2; ++i) *out++ = '\\';
      break;
    } else if (*arg == '"') {
      // double them, and escape the quote
      for (size_t i = 0; i < backslashes * 2 + 1; ++i) *out++ = '\\';
      *out++ = '"';
    } else {
      for (size_t i = 0; i < backslashes; ++i) *out++ = '\\';
      *out++ = *arg;
    }
    ++arg;
  }
  *out++ = '"';
  return out;
}

static struct c_aot_compile_result c_aot_compile_exec(const char* source, size_t source_size, const char* c_compiler, const char* const* compiler_args) {
  struct c_aot_compile_result result;
  c_aot_result_init(&result);

  static const char* const no_args[] = {NULL};
  if (!compiler_args) {
    compiler_args = no_args;
  }

  char c_aot_errbuf[C_AOT_ERRBUF_SIZE];
  HANDLE src = INVALID_HANDLE_VALUE;      // compiler's stdin
  HANDLE nul = INVALID_HANDLE_VALUE;      // compiler's stdout
  HANDLE err_read = INVALID_HANDLE_VALUE; // compiler's stderr
  HANDLE err_write = INVALID_HANDLE_VALUE;
  HANDLE lib_file = INVALID_HANDLE_VALUE; // the library, once compiled
  PROCESS_INFORMATION process;
  memset(&process, 0, sizeof(process));
  bool started = false; // process.hProcess is valid and unwaited
  LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
  bool attrs_init = false;
  char* command_line = NULL;
  char tmp_dir[C_AOT_PATH_MAX]; // private temp directory
  bool tmp_dir_made = false;
  bool keep_tmp_dir = false; // the loaded library still lives in it
  char src_path[C_AOT_PATH_MAX + 16];
  char lib_path[C_AOT_PATH_MAX + 16];

  {
    char base[C_AOT_PATH_MAX]; // ends with a backslash
    DWORD n = GetTempPathA((DWORD)sizeof(base), base);
    if (n == 0 || n >= sizeof(base)) {
      c_aot_set_err(&result, "getting temp path: %s\n", C_AOT_ERRNO);
      goto end;
    }
    static volatile LONG counter = 0;
    for (int attempt = 0; attempt < 100 && !tmp_dir_made; ++attempt) {
      LARGE_INTEGER ticks;
      QueryPerformanceCounter(&ticks);
      unsigned long unique = (unsigned long)InterlockedIncrement(&counter);
      int len = snprintf(tmp_dir, sizeof(tmp_dir), "%sc_aot_compile.%lx.%lx.%llx", base, (unsigned long)GetCurrentProcessId(), unique, (unsigned long long)ticks.QuadPart);
      if (len < 0 || len >= (int)sizeof(tmp_dir)) {
        c_aot_set_err(&result, "temp directory path too long (%s)\n", base);
        goto end;
      }
      if (CreateDirectoryA(tmp_dir, NULL)) {
        tmp_dir_made = true;
      } else if (GetLastError() != ERROR_ALREADY_EXISTS) {
        c_aot_set_err(&result, "creating temp directory in \"%s\": %s\n", base, C_AOT_ERRNO);
        goto end;
      }
    }
    if (!tmp_dir_made) {
      c_aot_set_err(&result, "creating temp directory in \"%s\": names kept colliding\n", base);
      goto end;
    }
    snprintf(src_path, sizeof(src_path), "%s\\src.c", tmp_dir);
    snprintf(lib_path, sizeof(lib_path), "%s\\lib.dll", tmp_dir);
  }

  // command line: 9 fixed + extras
  {
    size_t num_extra = 0;
    while (compiler_args[num_extra]) {
      ++num_extra;
    }
    const char* fixed[] = {c_compiler, "-pipe", "-shared", "-O1", "-DC_AOT_EXPORT=__declspec(dllexport)", "-xc", "-o", lib_path, "-"};
    const size_t num_fixed = sizeof(fixed) / sizeof(fixed[0]);
    size_t capacity = 1;
    for (size_t i = 0; i < num_fixed + num_extra; ++i) {
      capacity += 2 * strlen(i < num_fixed ? fixed[i] : compiler_args[i - num_fixed]) + 3;
    }
    command_line = malloc(capacity);
    if (!command_line) {
      c_aot_set_err(&result, "out of memory\n");
      goto end;
    }
    char* out = command_line;
    for (size_t i = 0; i < num_fixed + num_extra; ++i) {
      if (i != 0) *out++ = ' ';
      out = c_aot_win_append_arg(out, i < num_fixed ? fixed[i] : compiler_args[i - num_fixed]);
    }
    *out = '\0';
    if ((size_t)(out - command_line) >= 32767) { // CreateProcess limit
      c_aot_set_err(&result, "compiler command line too long\n");
      goto end;
    }
  }

  // inheritable, but only the handles in the attribute list below are inherited
  SECURITY_ATTRIBUTES inheritable;
  inheritable.nLength = sizeof(inheritable);
  inheritable.lpSecurityDescriptor = NULL;
  inheritable.bInheritHandle = TRUE;

  // source -> file, deleted when closed (the child's copy of the handle too),
  // which becomes the compiler's stdin
  src = CreateFileA(src_path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, &inheritable, CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (src == INVALID_HANDLE_VALUE) {
    c_aot_set_err(&result, "creating source file: %s\n", C_AOT_ERRNO);
    goto end;
  }
  {
    const char* data = source;
    size_t size = source_size;
    while (size > 0) {
      DWORD chunk = size > (1u << 30) ? (1u << 30) : (DWORD)size;
      DWORD written = 0;
      if (!WriteFile(src, data, chunk, &written, NULL)) {
        c_aot_set_err(&result, "writing source: %s\n", C_AOT_ERRNO);
        goto end;
      }
      data += written;
      size -= written;
    }
    if (SetFilePointer(src, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
      c_aot_set_err(&result, "rewinding source: %s\n", C_AOT_ERRNO);
      goto end;
    }
  }

  nul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (nul == INVALID_HANDLE_VALUE) {
    c_aot_set_err(&result, "opening NUL: %s\n", C_AOT_ERRNO);
    goto end;
  }
  if (!CreatePipe(&err_read, &err_write, &inheritable, 0)) {
    err_read = err_write = INVALID_HANDLE_VALUE;
    c_aot_set_err(&result, "pipe: %s\n", C_AOT_ERRNO);
    goto end;
  }
  if (!SetHandleInformation(err_read, HANDLE_FLAG_INHERIT, 0)) { // our end
    c_aot_set_err(&result, "SetHandleInformation: %s\n", C_AOT_ERRNO);
    goto end;
  }

  // the child inherits exactly: stdin = source, stdout = NUL, stderr = pipe
  {
    HANDLE inherited[3] = {src, nul, err_write};
    SIZE_T attrs_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrs_size); // fails, sets the size
    attrs = malloc(attrs_size);
    if (!attrs) {
      c_aot_set_err(&result, "out of memory\n");
      goto end;
    }
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_size)) {
      c_aot_set_err(&result, "InitializeProcThreadAttributeList: %s\n", C_AOT_ERRNO);
      goto end;
    }
    attrs_init = true;
    if (!UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), NULL, NULL)) {
      c_aot_set_err(&result, "UpdateProcThreadAttribute: %s\n", C_AOT_ERRNO);
      goto end;
    }

    STARTUPINFOEXA info;
    memset(&info, 0, sizeof(info));
    info.StartupInfo.cb = sizeof(info);
    info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    info.StartupInfo.hStdInput = src;
    info.StartupInfo.hStdOutput = nul;
    info.StartupInfo.hStdError = err_write;
    info.lpAttributeList = attrs;
    // the program is searched in PATH (and the application / current directory
    // first: prefer an absolute path)
    if (!CreateProcessA(NULL, command_line, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &info.StartupInfo, &process)) {
      c_aot_set_err(&result, "starting compiler \"%s\": %s\n", c_compiler, C_AOT_ERRNO);
      goto end;
    }
    started = true;
    CloseHandle(process.hThread);
    process.hThread = NULL;
  }

  // our copy of the write end must go, or the read below never sees EOF
  CloseHandle(err_write);
  err_write = INVALID_HANDLE_VALUE;

  // read the compiler's stderr until EOF. keep only the first bytes (constant
  // space), but keep reading so the compiler never blocks on a full pipe
  char stderr_buf[C_AOT_STDERR_CAPACITY];
  size_t stderr_size = 0;
  bool stderr_truncated = false;
  while (true) {
    char chunk[C_AOT_STDERR_CAPACITY];
    DWORD n = 0;
    if (!ReadFile(err_read, chunk, (DWORD)sizeof(chunk), &n, NULL)) {
      if (GetLastError() == ERROR_BROKEN_PIPE) { // write end closed: EOF
        break;
      }
      c_aot_set_err(&result, "reading compiler's stderr: %s\n", C_AOT_ERRNO);
      goto end;
    }
    if (n == 0) {
      break;
    }
    size_t room = sizeof(stderr_buf) - stderr_size;
    size_t take = (size_t)n < room ? (size_t)n : room;
    memcpy(stderr_buf + stderr_size, chunk, take);
    stderr_size += take;
    if (take < (size_t)n) {
      stderr_truncated = true;
    }
  }

  DWORD exit_code = 0;
  if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exit_code)) {
    c_aot_set_err(&result, "waiting for compiler: %s\n", C_AOT_ERRNO);
    goto end;
  }
  CloseHandle(process.hProcess);
  process.hProcess = NULL;
  started = false;

  if (exit_code != 0) {
    c_aot_set_err(&result, "compiler \"%s\" exited with code %lu. stderr:\n%.*s%s", c_compiler, (unsigned long)exit_code, (int)stderr_size, stderr_buf,
                  stderr_truncated ? "\n... (truncated)\n" : "");
    goto end;
  }

  // a loaded dll can't be deleted: hold it open delete-on-close instead, so
  // it goes away once it's unloaded and this handle is closed
  lib_file = CreateFileA(lib_path, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE,
                         NULL);
  if (lib_file == INVALID_HANDLE_VALUE) {
    c_aot_set_err(&result, "opening library: %s\n", C_AOT_ERRNO);
    goto end;
  }

  {
    HMODULE handle = LoadLibraryA(lib_path); // random directory, so unique
    if (!handle) {
      c_aot_set_err(&result, "LoadLibrary: %s\n", C_AOT_ERRNO);
      goto end;
    }
    size_t dir_size = strlen(tmp_dir) + 1;
    char* dir_copy = malloc(dir_size);
    if (!dir_copy) {
      FreeLibrary(handle);
      c_aot_set_err(&result, "out of memory\n");
      goto end;
    }
    memcpy(dir_copy, tmp_dir, dir_size);
    result.type = C_AOT_COMPILE_OK;
    result.value.code.type = C_AOT_CODE_LIBRARY;
    result.value.code.value.library.handle = (void*)handle;
    result.value.code.value.library.file = (void*)lib_file; // ownership moves to the result
    result.value.code.value.library.tmp_dir = dir_copy;
    lib_file = INVALID_HANDLE_VALUE;
    keep_tmp_dir = true;
  }

end:
  // pipe first: an unreaped child (error paths) then gets a broken pipe
  // instead of blocking on stderr, so the wait below can't hang on it
  if (err_read != INVALID_HANDLE_VALUE) CloseHandle(err_read);
  if (err_write != INVALID_HANDLE_VALUE) CloseHandle(err_write);
  if (src != INVALID_HANDLE_VALUE) CloseHandle(src);
  if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
  if (lib_file != INVALID_HANDLE_VALUE) CloseHandle(lib_file);
  if (started) {
    WaitForSingleObject(process.hProcess, INFINITE);
    CloseHandle(process.hProcess);
  }
  if (process.hThread) {
    CloseHandle(process.hThread);
  }
  if (attrs_init) {
    DeleteProcThreadAttributeList(attrs);
  }
  free(attrs);
  free(command_line);
  // after the wait, so the compiler can't still be writing into it
  if (tmp_dir_made && !keep_tmp_dir) {
    c_aot_remove_dir(tmp_dir);
  }
  return result;
}

#else // !_WIN32

#ifdef C_AOT_MEMORY_FILES
// an anonymous file in memory (close-on-exec), or -1 if the kernel has none
static int c_aot_memfd(const char* name) {
#if defined(__GLIBC__) && !__GLIBC_PREREQ(2, 27)
  return (int)syscall(SYS_memfd_create, name, 1u); // MFD_CLOEXEC
#else
  return memfd_create(name, 1u); // MFD_CLOEXEC
#endif
}

// dlopen the file behind fd (a memory file). the loader names a library by
// the path it was opened with and hands back the library already loaded under
// that name, so a name used before (an fd number reused while an earlier
// library is still mapped, because dlclose doesn't always unload) can't be
// used again: "./" components make a new name for the same file
static void* c_aot_dlopen_fd(int fd, char* reason, size_t reason_size) {
  for (int extra = 0; extra < 64; ++extra) {
    char path[256];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/");
    for (int i = 0; i < extra; ++i) {
      n += snprintf(path + n, sizeof(path) - (size_t)n, "./");
    }
    snprintf(path + n, sizeof(path) - (size_t)n, "%d", fd);
    void* taken = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (taken) {
      dlclose(taken);
      continue;
    }
    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
      const char* why = dlerror();
      snprintf(reason, reason_size, "dlopen: %s", why ? why : "unknown error");
    }
    return handle;
  }
  snprintf(reason, reason_size, "dlopen: no unused name for the library");
  return NULL;
}
#endif // C_AOT_MEMORY_FILES

static struct c_aot_compile_result c_aot_compile_exec(const char* source, size_t source_size, const char* c_compiler, const char* const* compiler_args) {
  struct c_aot_compile_result result;
  c_aot_result_init(&result);

  static const char* const no_args[] = {NULL};
  if (!compiler_args) {
    compiler_args = no_args;
  }

  int src_fd = -1;            // compiler's stdin
  int lib_fd = -1;            // the library, once compiled
  int err_pipe[2] = {-1, -1}; // compiler's stderr
  char** argv = NULL;
  char** envp = NULL; // the child's environment, if it isn't ours
  pid_t pid = 0; // nonzero while the child is unreaped
  posix_spawn_file_actions_t actions;
  bool actions_init = false;
  int rc;
  char tmp_dir[PATH_MAX]; // private temp directory, removed at the end
  bool tmp_dir_made = false;
  char src_path[PATH_MAX]; // inside tmp_dir
  char lib_path[PATH_MAX]; // inside tmp_dir, or what the compiler is told to write to

  // linux: the source and the library are memory files, so neither touches
  // disk. the compiler writes the library to its stdout, a memory file, by
  // the path /dev/fd/1. (what a compiler itself writes to TMPDIR is its own
  // business.) elsewhere, or if the kernel has no memory files, a private
  // temp directory holds them
  bool in_memory = false;
  int mem_lib_fd = -1; // the library's memory file, the compiler's stdout
#ifdef C_AOT_MEMORY_FILES
  src_fd = c_aot_fd_high(c_aot_memfd("c_aot_source"));
  mem_lib_fd = c_aot_fd_high(c_aot_memfd("c_aot_library"));
  in_memory = src_fd != -1 && mem_lib_fd != -1 && access("/dev/fd/0", F_OK) == 0;
  if (!in_memory) {
    if (src_fd != -1) close(src_fd);
    if (mem_lib_fd != -1) close(mem_lib_fd);
    src_fd = mem_lib_fd = -1;
  }
#endif

  if (in_memory) {
    snprintf(lib_path, sizeof(lib_path), "/dev/fd/1");
  } else {
    const char* base = c_aot_getenv("TMPDIR");
    if (!base || !base[0]) {
      base = "/tmp";
    }
    size_t len = strlen(base);
    const char* sep = base[len - 1] == '/' ? "" : "/";
    // the XXXXXX is replaced by mkdtemp, same length. lib_path is the longest
    if (snprintf(lib_path, sizeof(lib_path), "%s%sc_aot_compile.XXXXXX/lib.so", base, sep) >= (int)sizeof(lib_path)) {
      c_aot_set_err(&result, "temp directory path too long (TMPDIR=%s)\n", base);
      goto end;
    }
    snprintf(tmp_dir, sizeof(tmp_dir), "%s%sc_aot_compile.XXXXXX", base, sep);
    if (!mkdtemp(tmp_dir)) { // creates it 0700
      c_aot_set_err(&result, "creating temp directory in \"%s\": %s\n", base, C_AOT_ERRNO);
      goto end;
    }
    tmp_dir_made = true;
    // the length check above guarantees tmp_dir + "/lib.so" (the longest) fits
    size_t dir_len = strlen(tmp_dir);
    memcpy(src_path, tmp_dir, dir_len);
    memcpy(src_path + dir_len, "/src.c", sizeof("/src.c"));
    memcpy(lib_path, tmp_dir, dir_len);
    memcpy(lib_path + dir_len, "/lib.so", sizeof("/lib.so"));
  }

  // argv: 10 fixed + extras + NULL
  size_t num_extra = 0;
  while (compiler_args[num_extra]) {
    ++num_extra;
  }
  argv = malloc((11 + num_extra) * sizeof(*argv));
  if (!argv) {
    c_aot_set_err(&result, "out of memory\n");
    goto end;
  }
  argv[0] = (char*)c_compiler;
  argv[1] = (char*)"-pipe"; // fewer intermediate files
  argv[2] = (char*)"-fPIC";
  argv[3] = (char*)"-shared";
  argv[4] = (char*)"-O1"; // modest. later args win, so -O2 or -O0 in the candidate's args overrides it
  argv[5] = (char*)"-DC_AOT_EXPORT="; // see the top of this header
  argv[6] = (char*)"-xc"; // stdin is c
  argv[7] = (char*)"-o";
  argv[8] = lib_path;
  argv[9] = (char*)"-"; // source is stdin only
  for (size_t i = 0; i < num_extra; ++i) {
    argv[10 + i] = (char*)compiler_args[i];
  }
  argv[10 + num_extra] = NULL;

  // source -> a file (in memory, or unlinked at once), which becomes the
  // compiler's stdin
  if (!in_memory) {
    src_fd = c_aot_fd_high(open(src_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    if (src_fd == -1) {
      c_aot_set_err(&result, "creating source file: %s\n", C_AOT_ERRNO);
      goto end;
    }
    unlink(src_path);
  }
  if (!c_aot_write_all(src_fd, source, source_size) || lseek(src_fd, 0, SEEK_SET) == -1) {
    c_aot_set_err(&result, "writing source: %s\n", C_AOT_ERRNO);
    goto end;
  }

  // plain pipe (pipe2 isn't on macos): c_aot_fd_high below makes both ends
  // close-on-exec before our child is spawned. another thread's fork/exec in
  // that instant could still inherit them
  if (pipe(err_pipe) == -1) {
    err_pipe[0] = err_pipe[1] = -1;
    c_aot_set_err(&result, "pipe: %s\n", C_AOT_ERRNO);
    goto end;
  }
  err_pipe[0] = c_aot_fd_high(err_pipe[0]);
  err_pipe[1] = c_aot_fd_high(err_pipe[1]);
  if (err_pipe[0] == -1 || err_pipe[1] == -1) {
    c_aot_set_err(&result, "fcntl: %s\n", C_AOT_ERRNO);
    goto end;
  }

  // wire up the child: stdin = source, stdout = the library's memory file or
  // /dev/null, stderr = pipe.
  // (all our fds are close-on-exec; dup2 clears it on the new numbers)
  if ((rc = posix_spawn_file_actions_init(&actions)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions_init: %s\n", C_AOT_ERRNO);
    goto end;
  }
  actions_init = true;
  if ((rc = posix_spawn_file_actions_adddup2(&actions, src_fd, STDIN_FILENO)) != 0 ||       //
      (rc = posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO)) != 0 || //
      (rc = in_memory ? posix_spawn_file_actions_adddup2(&actions, mem_lib_fd, STDOUT_FILENO)
                      : posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions: %s\n", C_AOT_ERRNO);
    goto end;
  }

  // the compiler's own temporary files (gcc leaves intermediate files even with
  // -pipe) go where TMPDIR says. with a temp directory, that is the private
  // directory, so they are contained and removed with it. with memory files
  // (linux), it is /dev/shm, a memory file system, even if the caller set
  // TMPDIR: the point of memory files is to stay off disk
  const char* child_tmpdir = NULL;
  if (in_memory) {
    if (c_aot_is_writable_dir("/dev/shm")) {
      child_tmpdir = "/dev/shm";
    }
  } else {
    child_tmpdir = tmp_dir;
  }
  if (child_tmpdir) {
    envp = c_aot_environ_with("TMPDIR", child_tmpdir);
    if (!envp) {
      c_aot_set_err(&result, "out of memory\n");
      goto end;
    }
  }

  if ((rc = posix_spawnp(&pid, c_compiler, &actions, NULL, argv, envp ? envp : c_aot_environ())) != 0) {
    pid = 0; // not started
    errno = rc;
    c_aot_set_err(&result, "starting compiler \"%s\": %s\n", c_compiler, C_AOT_ERRNO);
    goto end;
  }

  // our copy of the write end must go, or the read below never sees EOF
  close(err_pipe[1]);
  err_pipe[1] = -1;

  // read the compiler's stderr until EOF. keep only the first bytes (constant
  // space), but keep reading so the compiler never blocks on a full pipe
  char stderr_buf[C_AOT_STDERR_CAPACITY];
  size_t stderr_size = 0;
  bool stderr_truncated = false;
  while (true) {
    char chunk[C_AOT_STDERR_CAPACITY];
    ssize_t n = read(err_pipe[0], chunk, sizeof(chunk));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      c_aot_set_err(&result, "reading compiler's stderr: %s\n", C_AOT_ERRNO);
      goto end;
    }
    if (n == 0) {
      break;
    }
    size_t room = sizeof(stderr_buf) - stderr_size;
    size_t take = (size_t)n < room ? (size_t)n : room;
    memcpy(stderr_buf + stderr_size, chunk, take);
    stderr_size += take;
    if (take < (size_t)n) {
      stderr_truncated = true;
    }
  }

  int status;
  pid_t waited;
  do {
    waited = waitpid(pid, &status, 0);
  } while (waited == -1 && errno == EINTR);
  pid = 0; // reaped (or can't be, e.g. ECHILD)
  if (waited == -1) {
    c_aot_set_err(&result, "waitpid: %s\n", C_AOT_ERRNO);
    goto end;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    char how[64];
    if (WIFSIGNALED(status)) {
      snprintf(how, sizeof(how), "killed by signal %d", WTERMSIG(status));
    } else {
      snprintf(how, sizeof(how), "exited with code %d", WEXITSTATUS(status));
    }
    c_aot_set_err(&result, "compiler \"%s\" %s. stderr:\n%.*s%s", c_compiler, how, (int)stderr_size, stderr_buf,
                  stderr_truncated ? "\n... (truncated)\n" : "");
    goto end;
  }

  // hold the library's inode while it's loaded, so it can't be reused for a
  // later library while this one is still loaded
  if (in_memory) {
    lib_fd = mem_lib_fd;
    mem_lib_fd = -1;
  } else {
    lib_fd = c_aot_fd_high(open(lib_path, O_RDONLY | O_CLOEXEC));
    if (lib_fd == -1) {
      c_aot_set_err(&result, "opening library: %s\n", C_AOT_ERRNO);
      goto end;
    }
  }

  {
    void* handle;
#ifdef C_AOT_MEMORY_FILES
    if (in_memory) {
      char reason[256];
      handle = c_aot_dlopen_fd(lib_fd, reason, sizeof(reason));
      if (!handle) {
        c_aot_set_err(&result, "%s\n", reason);
        goto end;
      }
    } else
#endif
    {
      handle = dlopen(lib_path, RTLD_NOW); // random directory, so unique
      if (!handle) {
        const char* reason = dlerror();
        c_aot_set_err(&result, "dlopen: %s\n", reason ? reason : "unknown error");
        goto end;
      }
    }
    result.type = C_AOT_COMPILE_OK;
    result.value.code.type = C_AOT_CODE_LIBRARY;
    result.value.code.value.library.handle = handle;
    result.value.code.value.library.fd = lib_fd; // ownership moves to the result
    lib_fd = -1;
  }

end:
  // close failures are ignored on purpose: the fd is released regardless, and
  // they must not turn a loaded library into an error.
  // pipe first: an unreaped child (error paths) then gets EPIPE instead of
  // blocking on stderr, so waitpid can't hang on it
  if (err_pipe[0] != -1) close(err_pipe[0]);
  if (err_pipe[1] != -1) close(err_pipe[1]);
  if (src_fd != -1) close(src_fd);
  if (lib_fd != -1) close(lib_fd);
  if (mem_lib_fd != -1) close(mem_lib_fd);
  if (pid != 0) {
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR) {}
  }
  if (actions_init) {
    posix_spawn_file_actions_destroy(&actions);
  }
  // after waitpid, so the compiler can't still be writing into it. a loaded
  // library stays mapped (and code_fd open), so removing its file is fine
  if (tmp_dir_made) {
    c_aot_remove_dir(tmp_dir);
  }
  free(argv);
  free(envp);
  return result;
}

#endif // _WIN32

// ================================ tcc ==================================

#ifdef _WIN32
static SRWLOCK c_aot_tcc_mutex = SRWLOCK_INIT;
static void c_aot_tcc_lock(void) { AcquireSRWLockExclusive(&c_aot_tcc_mutex); }
static void c_aot_tcc_unlock(void) { ReleaseSRWLockExclusive(&c_aot_tcc_mutex); }
#else
static pthread_mutex_t c_aot_tcc_mutex = PTHREAD_MUTEX_INITIALIZER;
static void c_aot_tcc_lock(void) { pthread_mutex_lock(&c_aot_tcc_mutex); }
static void c_aot_tcc_unlock(void) { pthread_mutex_unlock(&c_aot_tcc_mutex); }
#endif

enum { C_AOT_TCC_OUTPUT_MEMORY = 1 };
enum { C_AOT_EXE_PATH_MAX = 1024 };

struct c_aot_tcc_errors {
  char text[C_AOT_STDERR_CAPACITY];
  size_t size;
};

// libtcc's error callback: keeps the first bytes of what it reports
static void c_aot_tcc_on_error(void* opaque, const char* message) {
  struct c_aot_tcc_errors* errors = opaque;
  size_t room = sizeof(errors->text) - errors->size - 1;
  size_t take = strlen(message);
  if (take > room) take = room;
  memcpy(errors->text + errors->size, message, take);
  errors->size += take;
  if (errors->size < sizeof(errors->text) - 1) {
    errors->text[errors->size++] = '\n';
  }
  errors->text[errors->size] = '\0';
}

static struct c_aot_compile_result c_aot_compile_tcc(const struct c_aot_compiler* compiler, const char* source, size_t source_size) {
  struct c_aot_compile_result result;
  c_aot_result_init(&result);
  if (memchr(source, '\0', source_size)) {
    c_aot_set_err(&result, "source contains a NUL byte\n");
    return result;
  }
  char* text = malloc(source_size + 1); // tcc wants a C string
  if (!text) {
    c_aot_set_err(&result, "out of memory\n");
    return result;
  }
  memcpy(text, source, source_size);
  text[source_size] = '\0';

  const struct c_aot_tcc_api* tcc = &compiler->value.tcc.api;
  struct c_aot_tcc_errors errors;
  errors.size = 0;
  errors.text[0] = '\0';
  bool ok = false;

  c_aot_tcc_lock();
  void* state = tcc->tcc_new();
  if (!state) {
    c_aot_set_err(&result, "tcc_new failed\n");
  } else {
    tcc->tcc_set_error_func(state, &errors, c_aot_tcc_on_error);
    if (compiler->value.tcc.support_dir) {
      tcc->tcc_set_lib_path(state, compiler->value.tcc.support_dir);
    }
    bool output_set = tcc->tcc_set_output_type(state, C_AOT_TCC_OUTPUT_MEMORY) >= 0;
    // as for a compiler program (see the top of this header)
#ifdef _WIN32
    tcc->tcc_define_symbol(state, "C_AOT_EXPORT", "__declspec(dllexport)");
#else
    tcc->tcc_define_symbol(state, "C_AOT_EXPORT", "");
#endif
    // the candidate's configure function sets options on the state, as a
    // compiler program gets the candidate's args
    int configured = 0;
    if (output_set && compiler->value.tcc.configure) {
      configured = compiler->value.tcc.configure(state, tcc, compiler->value.tcc.configure_user_data);
    }
    if (!output_set) {
      c_aot_set_err(&result, "tcc: tcc_set_output_type failed\n");
    } else if (configured != 0) {
      c_aot_set_err(&result, "tcc: the configure function stopped the compile (returned %d). diagnostics:\n%s", configured, errors.text);
    } else if (tcc->tcc_compile_string(state, text) < 0 || tcc->tcc_relocate(state, (void*)1 /* TCC_RELOCATE_AUTO */) < 0) {
      c_aot_set_err(&result, "tcc failed. diagnostics:\n%s", errors.text);
    } else {
      ok = true;
    }
    if (ok) {
      // the state lives on in the result, `errors` doesn't: nothing may report to it
      tcc->tcc_set_error_func(state, NULL, NULL);
    } else {
      tcc->tcc_delete(state);
    }
  }
  c_aot_tcc_unlock();
  free(text);

  if (ok) {
    result.type = C_AOT_COMPILE_OK;
    result.value.code.type = C_AOT_CODE_TCC;
    result.value.code.value.tcc.api = tcc;
    result.value.code.value.tcc.state = state;
  }
  return result;
}

// ============================= resolution ==============================

// a growing string
struct c_aot_text {
  char* data; // NULL until something is added
  size_t size;
  bool failed; // out of memory
};

static void c_aot_text_add(struct c_aot_text* text, const char* format, ...) {
  va_list args, args_again;
  va_start(args, format);
  va_copy(args_again, args);
  int needed = vsnprintf(NULL, 0, format, args);
  va_end(args);
  if (needed >= 0 && !text->failed) {
    char* grown = realloc(text->data, text->size + (size_t)needed + 1);
    if (grown) {
      vsnprintf(grown + text->size, (size_t)needed + 1, format, args_again);
      text->data = grown;
      text->size += (size_t)needed;
    } else {
      text->failed = true;
    }
  }
  va_end(args_again);
}

static char* c_aot_copy(const char* s) {
  size_t n = strlen(s) + 1;
  char* copy = malloc(n);
  if (copy) memcpy(copy, s, n);
  return copy;
}

#ifdef _WIN32
#define C_AOT_DIR_SEPARATORS "/\\:"
#define C_AOT_PATH_LIST_SEPARATOR ';'
#else
#define C_AOT_DIR_SEPARATORS "/"
#define C_AOT_PATH_LIST_SEPARATOR ':'
#endif

// like a shell: a name with a directory separator is a path, not searched
static bool c_aot_has_dir_separator(const char* s) { return strpbrk(s, C_AOT_DIR_SEPARATORS) != NULL; }

static bool c_aot_is_file(const char* path) {
#ifdef _WIN32
  DWORD attributes = GetFileAttributesA(path);
  return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
#endif
}

// out = path made absolute (symlinks are kept: a compiler may go by the name
// it was started under, like cc -> clang)
static bool c_aot_make_absolute(const char* path, char* out, size_t out_size) {
#ifdef _WIN32
  DWORD n = GetFullPathNameA(path, (DWORD)out_size, out, NULL);
  return n > 0 && n < out_size;
#else
  if (path[0] == '/') {
    return snprintf(out, out_size, "%s", path) < (int)out_size;
  }
  char cwd[PATH_MAX];
  return getcwd(cwd, sizeof(cwd)) && snprintf(out, out_size, "%s/%s", cwd, path) < (int)out_size;
#endif
}

// out = the executable at path (windows: also path + ".exe"). NULL if found,
// else why not
static const char* c_aot_exe_at(const char* path, char* out, size_t out_size) {
  char candidate[C_AOT_EXE_PATH_MAX];
#ifdef _WIN32
  // path.exe first: an extensionless file of the same name next to it (a shell
  // script, as git bash and msys have) can't be started by CreateProcess
  if (snprintf(candidate, sizeof(candidate), "%s.exe", path) < (int)sizeof(candidate) && c_aot_is_file(candidate)) {
    return c_aot_make_absolute(candidate, out, out_size) ? NULL : "path too long";
  }
#endif
  if (snprintf(candidate, sizeof(candidate), "%s", path) >= (int)sizeof(candidate)) {
    return "path too long";
  }
  if (!c_aot_is_file(candidate)) {
    return "no such executable file";
  }
  return c_aot_make_absolute(candidate, out, out_size) ? NULL : "path too long";
}

// out = the first executable called name in PATH. empty PATH entries (the
// current directory, in a shell) are skipped on purpose. NULL if found, else why not
static const char* c_aot_exe_in_path(const char* name, char* out, size_t out_size) {
  const char* path = c_aot_getenv("PATH");
  if (!path) {
    return "PATH is not set";
  }
  const char* dir = path;
  while (*dir) {
    const char* end = strchr(dir, C_AOT_PATH_LIST_SEPARATOR);
    size_t len = end ? (size_t)(end - dir) : strlen(dir);
    const char* entry = dir;
    size_t entry_len = len;
#ifdef _WIN32
    // an entry may be in double quotes ("C:\Program Files\LLVM\bin"): without them
    if (entry_len >= 2 && entry[0] == '"' && entry[entry_len - 1] == '"') {
      ++entry;
      entry_len -= 2;
    }
#endif
    char candidate[C_AOT_EXE_PATH_MAX];
    if (entry_len && snprintf(candidate, sizeof(candidate), "%.*s/%s", (int)entry_len, entry, name) < (int)sizeof(candidate) &&
        c_aot_exe_at(candidate, out, out_size) == NULL) {
      return NULL;
    }
    dir = end ? end + 1 : dir + len;
  }
  return "not found in PATH";
}

static const char* c_aot_exe_from_value(const char* value, char* out, size_t out_size) {
  return c_aot_has_dir_separator(value) ? c_aot_exe_at(value, out, out_size) : c_aot_exe_in_path(value, out, out_size);
}

static void* c_aot_load_library(const char* name, char* reason, size_t reason_size) {
#ifdef _WIN32
  char c_aot_errbuf[C_AOT_ERRBUF_SIZE];
  void* handle = (void*)LoadLibraryA(name);
  if (!handle) snprintf(reason, reason_size, "LoadLibrary: %s", C_AOT_ERRNO);
  return handle;
#else
  void* handle = dlopen(name, RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    const char* why = dlerror();
    snprintf(reason, reason_size, "dlopen: %s", why ? why : "unknown error");
  }
  return handle;
#endif
}

static void c_aot_unload_library(void* handle) {
#ifdef _WIN32
  FreeLibrary((HMODULE)handle);
#else
  dlclose(handle);
#endif
}

static void* c_aot_library_symbol(void* handle, const char* name) {
#ifdef _WIN32
  FARPROC proc = GetProcAddress((HMODULE)handle, name);
  void* symbol = NULL;
  memcpy(&symbol, &proc, sizeof(symbol));
  return symbol;
#else
  return dlsym(handle, name);
#endif
}

// fills api from the library. returns the name of the first function it's
// missing, or NULL
static const char* c_aot_tcc_bind(void* library, struct c_aot_tcc_api* api) {
  struct slot {
    const char* name;
    void* slot; // the address of the function pointer to fill
  };
  const struct slot slots[] = {
      {"tcc_new", &api->tcc_new},
      {"tcc_delete", &api->tcc_delete},
      {"tcc_set_lib_path", &api->tcc_set_lib_path},
      {"tcc_set_error_func", &api->tcc_set_error_func},
      {"tcc_set_output_type", &api->tcc_set_output_type},
      {"tcc_add_include_path", &api->tcc_add_include_path},
      {"tcc_define_symbol", &api->tcc_define_symbol},
      {"tcc_add_library_path", &api->tcc_add_library_path},
      {"tcc_add_library", &api->tcc_add_library},
      {"tcc_compile_string", &api->tcc_compile_string},
      {"tcc_relocate", &api->tcc_relocate},
      {"tcc_get_symbol", &api->tcc_get_symbol},
  };
  for (size_t i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i) {
    void* symbol = c_aot_library_symbol(library, slots[i].name);
    if (!symbol) {
      return slots[i].name;
    }
    memcpy(slots[i].slot, &symbol, sizeof(symbol)); // void* -> function pointer
  }
  // the ones an older libtcc may lack stay NULL
  const struct slot optional[] = {
      {"tcc_set_options", &api->tcc_set_options},
      {"tcc_add_sysinclude_path", &api->tcc_add_sysinclude_path},
      {"tcc_undefine_symbol", &api->tcc_undefine_symbol},
      {"tcc_add_symbol", &api->tcc_add_symbol},
      {"tcc_add_file", &api->tcc_add_file},
  };
  for (size_t i = 0; i < sizeof(optional) / sizeof(optional[0]); ++i) {
    void* symbol = c_aot_library_symbol(library, optional[i].name);
    memcpy(optional[i].slot, &symbol, sizeof(symbol));
  }
  return NULL;
}

// a copy of a NULL terminated list of strings: NULL for an empty or NULL list.
// false if out of memory
static bool c_aot_copy_args(const char* const* args, char*** out) {
  *out = NULL;
  size_t count = 0;
  while (args && args[count]) {
    ++count;
  }
  if (count == 0) {
    return true;
  }
  char** copy = calloc(count + 1, sizeof(*copy));
  if (!copy) {
    return false;
  }
  for (size_t i = 0; i < count; ++i) {
    copy[i] = c_aot_copy(args[i]);
    if (!copy[i]) {
      for (size_t j = 0; j < i; ++j) free(copy[j]);
      free(copy);
      return false;
    }
  }
  *out = copy;
  return true;
}

static void c_aot_free_args(char** args) {
  for (size_t i = 0; args && args[i]; ++i) {
    free(args[i]);
  }
  free(args);
}

// true if path is a regular file (c_aot_is_file also wants it executable)
static bool c_aot_file_exists(const char* path) {
#ifdef _WIN32
  DWORD attributes = GetFileAttributesA(path);
  return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
#else
  struct stat st;
  return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#endif
}

// the directory of the libtcc at library_path, if tcc's support files are in
// it (libtcc1.a, or lib/libtcc1.a as on windows): malloc'd. else NULL (also
// for a bare name, whose directory isn't known): tcc then uses its own
// built-in location, which is right for an installed tcc
static char* c_aot_tcc_neighbors(const char* library_path) {
  if (!c_aot_has_dir_separator(library_path)) {
    return NULL;
  }
  size_t dir_len = strlen(library_path);
  while (dir_len > 0 && !strchr(C_AOT_DIR_SEPARATORS, library_path[dir_len - 1])) --dir_len;
  // drop the trailing separator, except where that changes what the directory
  // is: the root "/", a drive root "C:\" ("C:" alone is that drive's current
  // directory), or a drive prefix "C:" itself
  bool drive_root = dir_len == 3 && library_path[1] == ':';
  if (dir_len > 1 && library_path[dir_len - 1] != ':' && !drive_root) --dir_len;
  char probe[C_AOT_EXE_PATH_MAX];
  static const char* const names[] = {"%.*s/libtcc1.a", "%.*s/lib/libtcc1.a"};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    if (snprintf(probe, sizeof(probe), names[i], (int)dir_len, library_path) < (int)sizeof(probe) && c_aot_file_exists(probe)) {
      char* dir = malloc(dir_len + 1);
      if (dir) {
        memcpy(dir, library_path, dir_len);
        dir[dir_len] = '\0';
      }
      return dir;
    }
  }
  return NULL;
}

// runs the test program (test_source, or the built-in one if NULL) with
// compiler, to know it works: compiles and loads it, then calls c_aot_test,
// which must return 0. appends why not to text (indented) and returns false if
// it doesn't
static bool c_aot_probe(const struct c_aot_compiler* compiler, const char* test_source, struct c_aot_text* text) {
  // stddef.h: tcc needs its support files (include/) for it
  static const char builtin[] = "#include <stddef.h>\nC_AOT_EXPORT int c_aot_test(void) { return 0; }\n";
  const char* source = test_source ? test_source : builtin;
  size_t source_size = strlen(source);
  struct c_aot_compile_result result;
  if (compiler->type == C_AOT_COMPILER_TCC) {
    result = c_aot_compile_tcc(compiler, source, source_size);
  } else {
    result = c_aot_compile_exec(source, source_size, compiler->value.executable.path, (const char* const*)compiler->value.executable.args);
  }
  bool ok = false;
  if (result.type != C_AOT_COMPILE_OK) {
    const char* message = result.value.error_msg ? result.value.error_msg : "out of memory\n";
    c_aot_text_add(text, "failed to compile the test program: ");
    // indent the lines of the message
    for (const char* line = message; *line;) {
      const char* nl = strchr(line, '\n');
      size_t n = nl ? (size_t)(nl - line) : strlen(line);
      if (n) c_aot_text_add(text, "\n      %.*s", (int)n, line);
      line += n + (nl ? 1 : 0);
    }
  } else {
    void* symbol = c_aot_compile_symbol(&result, "c_aot_test");
    if (!symbol) {
      c_aot_text_add(text, "the test program compiled, but has no c_aot_test function");
    } else {
      int (*test)(void);
      memcpy(&test, &symbol, sizeof(test)); // object to function pointer, without a cast warning
      int returned = test();
      ok = returned == 0;
      if (!ok) c_aot_text_add(text, "the test program's c_aot_test returned %d, not 0", returned);
    }
  }
  c_aot_compile_result_destroy(&result);
  return ok;
}

enum { C_AOT_PRESET_CANDIDATES_MAX = 12 };

// the memory first preset: the candidates to try when keeping source and
// compiled code in memory matters most, then speed. writes them to out (room for
// C_AOT_PRESET_CANDIDATES_MAX) and returns how many. it is a priority, not a
// guarantee: where only a compiler program that writes temporary files exists
// (macos or windows without a libtcc) that program is still used, last. what
// writes nothing: libtcc, and on linux the compilers below, whose source and
// library are memory files and whose own temporary files go to /dev/shm. the
// order:
// - linux: $CC, then cc, gcc, clang (their source and library are memory
//   files: nothing touches disk), then your bundled libtcc and the system's as the
//   fallback, then tcc as a program, last.
// - elsewhere (macos, windows, other unix): your bundled libtcc and the system's first
//   (the only option that never touches disk there), then tcc as a program (it compiles
//   fastest), then $CC, then cc, gcc, clang (windows: gcc, clang, cc).
// - with C_AOT_NO_MEMORY_FILES on linux: as "elsewhere", except that tcc as a
//   program stays last, as on linux.
// why tcc as a program is last on linux: a tcc older than mob@772dc70d
// (2026-11-26; that includes 0.9.27, the last release, and so most installed
// ones) builds libraries with no PT_GNU_STACK header, which the loader reads as
// "needs an executable stack", and glibc 2.41 and later refuse to dlopen such a
// library (older glibc made the stack executable instead). a newer tcc, or an
// older glibc, works. where neither is the case, resolving fails it with the
// loader's own message and moves on, so it costs nothing but a test compile at
// the end of the list. libtcc, in process, has no such problem
// bundled_tcc_library: optional, a libtcc you bundle with your app (a path, or
// a bare name for the loader), or NULL for none. "the system's" libtcc is an
// installed one, found by the loader; it is skipped if there is none. to give a
// libtcc a configure function, set value.tcc_library.configure of the
// candidates of type C_AOT_CANDIDATE_TCC_LIBRARY in out afterwards
static inline size_t c_aot_memory_first_candidates(struct c_aot_candidate* out, const char* bundled_tcc_library) {
#ifdef _WIN32
  static const char* const names[] = {"gcc", "clang", "cc"};
  static const char system_tcc[] = "libtcc.dll";
#elif defined(__APPLE__)
  static const char* const names[] = {"cc", "gcc", "clang"};
  static const char system_tcc[] = "libtcc.dylib";
#else
  static const char* const names[] = {"cc", "gcc", "clang"};
  static const char system_tcc[] = "libtcc.so";
#endif
  size_t n = 0;
#ifdef C_AOT_MEMORY_FILES
  // the system compilers keep nothing on disk: they come first
  out[n++] = c_aot_candidate_env("CC", NULL);
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    out[n++] = c_aot_candidate_executable(names[i], NULL);
  }
  if (bundled_tcc_library) {
    out[n++] = c_aot_candidate_tcc_library(bundled_tcc_library, NULL, NULL);
  }
  out[n++] = c_aot_candidate_tcc_library(system_tcc, NULL, NULL);
#else
  // only libtcc keeps nothing on disk: it comes first
  if (bundled_tcc_library) {
    out[n++] = c_aot_candidate_tcc_library(bundled_tcc_library, NULL, NULL);
  }
  out[n++] = c_aot_candidate_tcc_library(system_tcc, NULL, NULL);
#ifndef __linux__
  out[n++] = c_aot_candidate_executable("tcc", NULL);
#endif
  out[n++] = c_aot_candidate_env("CC", NULL);
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    out[n++] = c_aot_candidate_executable(names[i], NULL);
  }
#endif
#ifdef __linux__
  out[n++] = c_aot_candidate_executable("tcc", NULL); // last, see above
#endif
  return n;
}

// frees what a compiler owns. users free it through its c_aot_resolve_result
static void c_aot_compiler_free(struct c_aot_compiler* compiler) {
  switch (compiler->type) {
  case C_AOT_COMPILER_EXECUTABLE:
    free(compiler->value.executable.path);
    c_aot_free_args(compiler->value.executable.args);
    break;
  case C_AOT_COMPILER_TCC:
    free(compiler->value.tcc.support_dir);
    c_aot_unload_library(compiler->value.tcc.library);
    break;
  }
}

// ok: frees the compiler (and unloads libtcc, if that's what it is), after
// which every result made with it must already be destroyed. err: frees the
// message. the result must not be used afterwards.
static inline void c_aot_resolve_result_destroy(struct c_aot_resolve_result* result) {
  if (result->type == C_AOT_RESOLVE_OK) {
    c_aot_compiler_free(&result->value.compiler);
  } else {
    free(result->value.error_msg);
  }
  result->type = C_AOT_RESOLVE_ERR;
  result->value.error_msg = NULL;
}

// tries the candidates in order and returns the first that works: one whose
// test program (its test_source, or the built-in one) compiles, loads and
// returns 0. nothing is
// searched beyond the candidates (so "only tcc" is a list of one tcc library).
// if none works, the result is an error that says why, for each.
// resolving is not cheap (it compiles a test program), so do it once
static inline struct c_aot_resolve_result c_aot_compiler_resolve(const struct c_aot_candidate* candidates, size_t count) {
  struct c_aot_compiler compiler;
  memset(&compiler, 0, sizeof(compiler)); // only read once found
  bool found = false;
  struct c_aot_text report = {NULL, 0, false};
  c_aot_text_add(&report, "no working compiler. tried:");

  for (size_t i = 0; i < count && !found; ++i) {
    const struct c_aot_candidate* c = &candidates[i];
    // what the candidate names, and its args (an executable or an environment variable)
    const char* named = NULL;
    const char* const* args = NULL;
    const char* kind = NULL;
    switch (c->type) {
    case C_AOT_CANDIDATE_EXECUTABLE:
      kind = "executable";
      named = c->value.executable.compiler_exe_path_or_name;
      args = c->value.executable.args;
      break;
    case C_AOT_CANDIDATE_ENV:
      kind = "environment variable";
      named = c->value.env.variable;
      args = c->value.env.args;
      break;
    case C_AOT_CANDIDATE_TCC_LIBRARY:
      kind = "tcc library";
      named = c->value.tcc_library.library_path_or_name;
      break;
    }
    c_aot_text_add(&report, "\n  %lu. %s \"%s\": ", (unsigned long)(i + 1), kind, named);

    if (c->type == C_AOT_CANDIDATE_TCC_LIBRARY) {
      char reason[512];
      void* library = c_aot_load_library(named, reason, sizeof(reason));
      if (!library) {
        c_aot_text_add(&report, "%s", reason);
        continue;
      }
      struct c_aot_compiler attempt;
      memset(&attempt, 0, sizeof(attempt));
      attempt.type = C_AOT_COMPILER_TCC;
      struct c_aot_compiler_tcc* tcc = &attempt.value.tcc;
      tcc->library = library;
      tcc->configure = c->value.tcc_library.configure;
      tcc->configure_user_data = c->value.tcc_library.user_data;
      const char* missing = c_aot_tcc_bind(library, &tcc->api);
      if (missing) {
        c_aot_text_add(&report, "not a usable libtcc: no %s", missing);
      } else {
        tcc->support_dir = c_aot_tcc_neighbors(named);
        attempt.candidate = i;
        if (c_aot_probe(&attempt, c->test_source, &report)) {
          compiler = attempt;
          found = true;
          continue;
        }
        free(tcc->support_dir);
      }
      c_aot_unload_library(library);
      continue;
    }

    // an executable: named directly, or by an environment variable
    const char* value = named;
    char exe[C_AOT_EXE_PATH_MAX];
    const char* why = NULL;
    if (c->type == C_AOT_CANDIDATE_ENV) {
      value = c_aot_getenv(named);
      if (!value || !value[0]) {
        c_aot_text_add(&report, "not set");
        continue;
      }
      c_aot_text_add(&report, "set to \"%s\": ", value);
    }
    why = c_aot_exe_from_value(value, exe, sizeof(exe));
    if (why) {
      c_aot_text_add(&report, "%s", why);
      if (strpbrk(value, " \t")) {
        c_aot_text_add(&report, " (note: arguments aren't supported, it must be a program only)");
      }
      continue;
    }
    struct c_aot_compiler attempt;
    memset(&attempt, 0, sizeof(attempt));
    attempt.type = C_AOT_COMPILER_EXECUTABLE;
    attempt.value.executable.path = c_aot_copy(exe);
    attempt.candidate = i;
    if (!attempt.value.executable.path || !c_aot_copy_args(args, &attempt.value.executable.args)) {
      c_aot_text_add(&report, "out of memory");
    } else if (c_aot_probe(&attempt, c->test_source, &report)) {
      compiler = attempt;
      found = true;
      continue;
    }
    free(attempt.value.executable.path);
    c_aot_free_args(attempt.value.executable.args);
  }

  struct c_aot_resolve_result result;
  if (found) {
    free(report.data);
    result.type = C_AOT_RESOLVE_OK;
    result.value.compiler = compiler;
  } else {
    if (count == 0) {
      c_aot_text_add(&report, " nothing (no candidates)");
    }
    c_aot_text_add(&report, "\n");
    result.type = C_AOT_RESOLVE_ERR;
    result.value.error_msg = report.failed ? NULL : report.data;
    if (report.failed) free(report.data);
  }
  return result;
}

// the fast preset: the candidates to try when you want the fastest generated
// code, whatever it costs. writes them to out (room for C_AOT_PRESET_CANDIDATES_MAX) and returns
// how many. the system compilers, each first with "go fast" args, and then
// without them if it turns out to reject them: $CC, then cc, gcc, clang
// (windows: gcc, clang, cc). then your bundled libtcc, and then tcc as a program, last:
// tcc doesn't optimize (and on linux, its libraries may not load: see
// c_aot_memory_first_candidates). the args are -O2 (over the default -O1),
// -march=native (this machine's instructions; the code is built here and runs
// here) and -fno-semantic-interposition (calls inside the library are direct).
// not included, because they change what a program means or remove protection:
// -ffast-math, -DNDEBUG, -fno-stack-protector. add them with
// a candidate's args if you want them. compiling takes longer.
// bundled_tcc_library: optional, a libtcc you bundle with your app, or NULL for none
static inline size_t c_aot_fast_candidates(struct c_aot_candidate* out, const char* bundled_tcc_library) {
  static const char* const fast[] = {"-O2", "-march=native", "-fno-semantic-interposition", NULL};
#ifdef _WIN32
  static const char* const names[] = {"gcc", "clang", "cc"};
#else
  static const char* const names[] = {"cc", "gcc", "clang"};
#endif
  size_t n = 0;
  out[n++] = c_aot_candidate_env("CC", fast);
  out[n++] = c_aot_candidate_env("CC", NULL);
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
    out[n++] = c_aot_candidate_executable(names[i], fast);
    out[n++] = c_aot_candidate_executable(names[i], NULL);
  }
  if (bundled_tcc_library) {
    out[n++] = c_aot_candidate_tcc_library(bundled_tcc_library, NULL, NULL);
  }
  out[n++] = c_aot_candidate_executable("tcc", NULL);
  return n;
}

// c_aot_compiler_resolve with c_aot_fast_candidates. bundled_tcc_library:
// optional, a libtcc you bundle with your app, or NULL
static inline struct c_aot_resolve_result c_aot_compiler_resolve_fast(const char* bundled_tcc_library) {
  struct c_aot_candidate candidates[C_AOT_PRESET_CANDIDATES_MAX];
  size_t count = c_aot_fast_candidates(candidates, bundled_tcc_library);
  return c_aot_compiler_resolve(candidates, count);
}

// c_aot_compiler_resolve with c_aot_memory_first_candidates.
// bundled_tcc_library: optional, a libtcc you bundle with your app, or NULL
static inline struct c_aot_resolve_result c_aot_compiler_resolve_memory_first(const char* bundled_tcc_library) {
  struct c_aot_candidate candidates[C_AOT_PRESET_CANDIDATES_MAX];
  size_t count = c_aot_memory_first_candidates(candidates, bundled_tcc_library);
  return c_aot_compiler_resolve(candidates, count);
}

// ================================ api ==================================

// compiles the c source in source[0, source_size) and loads it. the source
// need not be NUL terminated.
//
// compiler: the compiler of an ok c_aot_resolve_result. it must outlive the
//   result. an executable compiles to a shared library in a private
//   temporary directory; tcc compiles in this process, to memory.
//
// there are no args here: what a compiler is given is part of its candidate
// (extra args for a program, a configure function for tcc). to vary something
// per compile, put it in the source (a #define line).
//
// warning! this is a JIT: an avenue for arbitrary code execution. the source
// and the compiler must be trusted/constant. also:
// - the environment is passed to the compiler as it is, except TMPDIR on unix
//   (see the top of this file). variables such as
//   GCC_EXEC_PREFIX, COMPILER_PATH, CPATH, LIBRARY_PATH, LD_PRELOAD change
//   what it runs or includes. resolving reads PATH, and any environment
//   variable candidate you give it (both presets: CC).
// - compiler diagnostics are returned in the error message; with outside
//   influenced source, #include "/secret" can leak file fragments through it.
// - SIGCHLD must not be ignored / children not reaped elsewhere (waitpid would
//   fail with ECHILD).
static struct c_aot_compile_result c_aot_compile(const struct c_aot_compiler* compiler, const char* source, size_t source_size) {
  switch (compiler->type) {
  case C_AOT_COMPILER_EXECUTABLE:
    return c_aot_compile_exec(source, source_size, compiler->value.executable.path, (const char* const*)compiler->value.executable.args);
  case C_AOT_COMPILER_TCC:
    return c_aot_compile_tcc(compiler, source, source_size);
  }
  struct c_aot_compile_result result; // every type is handled above
  c_aot_result_init(&result);
  c_aot_set_err(&result, "invalid compiler type\n");
  return result;
}

#pragma once

/**
 * ahead of time compilation using a c compiler. c source is compiled, then loaded.
 *
 * linux and macos (posix_spawn, mkdtemp, dlopen; likely other posix systems
 * too) and windows (CreateProcess, LoadLibrary; needs a gcc style compiler
 * driver such as mingw gcc, clang or tcc, see the windows notes below). link
 * with -ldl on linux with glibc < 2.34. _GNU_SOURCE is defined here if
 * missing, but only works if this header comes before any system header;
 * otherwise define it yourself.
 *
 * design (each point removes a class of bugs):
 * - each compile gets a fresh private (0700) directory from mkdtemp, under
 *   TMPDIR (or /tmp). it and everything in it is removed before returning,
 *   whether the compile succeeded or not.
 * - the source is written to a file there, which is unlinked right away and
 *   given to the compiler as stdin. no pipe to feed, so no deadlock, short
 *   write or SIGPIPE handling.
 * - the compiler writes the library to a path in that directory. the random
 *   directory name makes the path unique (dlopen would otherwise return an
 *   already loaded library of the same path), and the library's fd is kept
 *   open while it is loaded, so its inode can't be reused either.
 * - the compiler is started with posix_spawn, so no code runs in a forked
 *   child of this (possibly threaded) process.
 * - every fd is close-on-exec and numbered >= 10, so nothing leaks into our
 *   child and nothing collides with the standard fds. (the stderr pipe is
 *   made close-on-exec just after it's created, so another thread spawning a
 *   program at that very instant could inherit it.)
 *
 * the files do touch disk (unless TMPDIR is a memory file system), and
 * between the compiler exiting and dlopen, a process running as the same user
 * could modify the library.
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
 * - the default compiler is "gcc" (there is no "cc"), and the library is
 *   named lib.dll. -fPIC isn't passed.
 * - symbols must be exported to be found: mingw gcc exports every global
 *   symbol unless something is marked dllexport; clang (msvc target) and
 *   others need __declspec(dllexport) on what you look up.
 * - paths are handled in the ANSI code page, limited to MAX_PATH.
 * - use c_aot_compile_symbol instead of dlsym.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
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
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h> // _NSGetEnviron: environ isn't declared, nor usable from a dylib
#endif
#endif

enum c_aot_compile_result_type {
  C_AOT_COMPILE_OK,
  C_AOT_COMPILE_ERR,
};

union c_aot_compile_result_value {
  // only if C_AOT_COMPILE_OK. never NULL
  void* dl_handle;
  // only if C_AOT_COMPILE_ERR. malloc'd. NULL only on alloc failure
  char* error_msg;
};

// either err with error message, or ok with handle.
// free with c_aot_compile_result_destroy, in both cases.
struct c_aot_compile_result {
  enum c_aot_compile_result_type type;
  union c_aot_compile_result_value value;
#ifdef _WIN32
  // only if C_AOT_COMPILE_OK (else NULL): the library file (a HANDLE, opened
  // delete-on-close), kept open as long as the library is loaded
  void* code_file;
  // only if C_AOT_COMPILE_OK (else NULL): malloc'd, the directory holding the
  // library file. removed by c_aot_compile_result_destroy
  char* tmp_dir;
#else
  // only if C_AOT_COMPILE_OK (else -1): the (already deleted) library file.
  // kept open as long as the library is loaded
  int code_fd;
#endif
};

static void c_aot_remove_dir(const char* dir);

// ok: unload the library, then close the library file. err: free the message.
// the result must not be used afterwards.
static void c_aot_compile_result_destroy(struct c_aot_compile_result* result) {
  if (result->type == C_AOT_COMPILE_OK) {
#ifdef _WIN32
    if (result->value.dl_handle) {
      FreeLibrary((HMODULE)result->value.dl_handle);
    }
    if (result->code_file) {
      CloseHandle((HANDLE)result->code_file); // deletes the library file
    }
    if (result->tmp_dir) {
      c_aot_remove_dir(result->tmp_dir);
      free(result->tmp_dir);
    }
#else
    if (result->value.dl_handle) {
      dlclose(result->value.dl_handle);
    }
    if (result->code_fd != -1) {
      close(result->code_fd);
    }
#endif
  } else {
    free(result->value.error_msg);
  }
  result->type = C_AOT_COMPILE_ERR;
  result->value.error_msg = NULL;
#ifdef _WIN32
  result->code_file = NULL;
  result->tmp_dir = NULL;
#else
  result->code_fd = -1;
#endif
}

// looks up a symbol in a loaded library (dlsym / GetProcAddress). NULL if
// it's not found, or result isn't ok. the pointer is valid until destroy.
static inline void* c_aot_compile_symbol(const struct c_aot_compile_result* result, const char* name) {
  if (result->type != C_AOT_COMPILE_OK || !result->value.dl_handle) {
    return NULL;
  }
#ifdef _WIN32
  FARPROC proc = GetProcAddress((HMODULE)result->value.dl_handle, name);
  void* symbol = NULL;
  memcpy(&symbol, &proc, sizeof(symbol)); // function pointer -> void*
  return symbol;
#else
  return dlsym(result->value.dl_handle, name);
#endif
}

// ============================== internals ==============================

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

// ================================ api ==================================

// compiles the c source in source[0, source_size) to a shared library and
// loads it. the source need not be NUL terminated.
//
// c_compiler: program to run. NULL means "cc" ("gcc" on windows). if it has no
//   '/', it is looked up in PATH (prefer an absolute path).
// compiler_args: NULL terminated list of extra compiler args (may be NULL).
//
// warning! this is a JIT: an avenue for arbitrary code execution. the source
// and c_compiler must be trusted/constant. also:
// - the environment is passed to the compiler unchanged. variables such as
//   GCC_EXEC_PREFIX, COMPILER_PATH, CPATH, LIBRARY_PATH, LD_PRELOAD change
//   what it runs or includes.
// - compiler diagnostics are returned in the error message; with outside
//   influenced source, #include "/secret" can leak file fragments through it.
// - SIGCHLD must not be ignored / children not reaped elsewhere (waitpid would
//   fail with ECHILD).
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

static struct c_aot_compile_result c_aot_compile(const char* source, size_t source_size, const char* c_compiler, const char* const* compiler_args) {
  struct c_aot_compile_result result;
  result.type = C_AOT_COMPILE_ERR;
  result.value.error_msg = NULL;
  result.code_file = NULL;
  result.tmp_dir = NULL;

  if (!c_compiler) {
    c_compiler = "gcc";
  }
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

  // command line: 8 fixed + extras
  {
    size_t num_extra = 0;
    while (compiler_args[num_extra]) {
      ++num_extra;
    }
    const char* fixed[] = {c_compiler, "-pipe", "-shared", "-O2", "-xc", "-o", lib_path, "-"};
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
    char* dir_copy = malloc(strlen(tmp_dir) + 1);
    if (!dir_copy) {
      FreeLibrary(handle);
      c_aot_set_err(&result, "out of memory\n");
      goto end;
    }
    strcpy(dir_copy, tmp_dir);
    result.type = C_AOT_COMPILE_OK;
    result.value.dl_handle = (void*)handle;
    result.code_file = (void*)lib_file; // ownership moves to the result
    result.tmp_dir = dir_copy;
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

static struct c_aot_compile_result c_aot_compile(const char* source, size_t source_size, const char* c_compiler, const char* const* compiler_args) {
  struct c_aot_compile_result result;
  result.type = C_AOT_COMPILE_ERR;
  result.value.error_msg = NULL;
  result.code_fd = -1;

  if (!c_compiler) {
    c_compiler = "cc";
  }
  static const char* const no_args[] = {NULL};
  if (!compiler_args) {
    compiler_args = no_args;
  }

  int src_fd = -1;            // compiler's stdin
  int lib_fd = -1;            // the library, once compiled
  int err_pipe[2] = {-1, -1}; // compiler's stderr
  char** argv = NULL;
  pid_t pid = 0; // nonzero while the child is unreaped
  posix_spawn_file_actions_t actions;
  bool actions_init = false;
  int rc;
  char tmp_dir[PATH_MAX]; // private temp directory, removed at the end
  bool tmp_dir_made = false;
  char src_path[PATH_MAX]; // inside tmp_dir
  char lib_path[PATH_MAX]; // inside tmp_dir

  {
    const char* base = getenv("TMPDIR");
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

  // argv: 9 fixed + extras + NULL
  size_t num_extra = 0;
  while (compiler_args[num_extra]) {
    ++num_extra;
  }
  argv = malloc((10 + num_extra) * sizeof(*argv));
  if (!argv) {
    c_aot_set_err(&result, "out of memory\n");
    goto end;
  }
  argv[0] = (char*)c_compiler;
  argv[1] = (char*)"-pipe"; // fewer intermediate files
  argv[2] = (char*)"-fPIC";
  argv[3] = (char*)"-shared";
  argv[4] = (char*)"-O2";
  argv[5] = (char*)"-xc"; // stdin is c
  argv[6] = (char*)"-o";
  argv[7] = lib_path;
  argv[8] = (char*)"-"; // source is stdin only
  for (size_t i = 0; i < num_extra; ++i) {
    argv[9 + i] = (char*)compiler_args[i];
  }
  argv[9 + num_extra] = NULL;

  // source -> file, unlinked at once, which becomes the compiler's stdin
  src_fd = c_aot_fd_high(open(src_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
  if (src_fd == -1) {
    c_aot_set_err(&result, "creating source file: %s\n", C_AOT_ERRNO);
    goto end;
  }
  unlink(src_path);
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

  // wire up the child: stdin = source, stdout = /dev/null, stderr = pipe.
  // (all our fds are close-on-exec; dup2 clears it on the new numbers)
  if ((rc = posix_spawn_file_actions_init(&actions)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions_init: %s\n", C_AOT_ERRNO);
    goto end;
  }
  actions_init = true;
  if ((rc = posix_spawn_file_actions_adddup2(&actions, src_fd, STDIN_FILENO)) != 0 ||       //
      (rc = posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO)) != 0 || //
      (rc = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions: %s\n", C_AOT_ERRNO);
    goto end;
  }

  if ((rc = posix_spawnp(&pid, c_compiler, &actions, NULL, argv, c_aot_environ())) != 0) {
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
  lib_fd = c_aot_fd_high(open(lib_path, O_RDONLY | O_CLOEXEC));
  if (lib_fd == -1) {
    c_aot_set_err(&result, "opening library: %s\n", C_AOT_ERRNO);
    goto end;
  }

  {
    void* handle = dlopen(lib_path, RTLD_NOW); // random directory, so unique
    if (!handle) {
      const char* reason = dlerror();
      c_aot_set_err(&result, "dlopen: %s\n", reason ? reason : "unknown error");
      goto end;
    }
    result.type = C_AOT_COMPILE_OK;
    result.value.dl_handle = handle;
    result.code_fd = lib_fd; // ownership moves to the result
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
  return result;
}

#endif // _WIN32

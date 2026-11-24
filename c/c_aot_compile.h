#pragma once

/**
 * ahead of time compilation using a c compiler. c source is compiled, then loaded.
 *
 * linux and macos (posix_spawn, mkdtemp, dlopen; likely other posix systems
 * too). link with -ldl on linux with glibc < 2.34. _GNU_SOURCE is defined here
 * if missing, but only works if this header comes before any system header;
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
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <crt_externs.h> // _NSGetEnviron: environ isn't declared, nor usable from a dylib
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
  // only if C_AOT_COMPILE_OK (else -1): the (already deleted) library file.
  // kept open as long as the library is loaded
  int code_fd;
};

// ok: dlclose, then close the library file. err: free the message.
// the result must not be used afterwards.
static void c_aot_compile_result_destroy(struct c_aot_compile_result* result) {
  if (result->type == C_AOT_COMPILE_OK) {
    if (result->value.dl_handle) {
      dlclose(result->value.dl_handle);
    }
    if (result->code_fd != -1) {
      close(result->code_fd);
    }
  } else {
    free(result->value.error_msg);
  }
  result->type = C_AOT_COMPILE_ERR;
  result->value.error_msg = NULL;
  result->code_fd = -1;
}

// ============================== internals ==============================

// errno as text. passed as an argument to c_aot_set_err (macos printf has no
// %m), so it's evaluated before anything in there could change errno
#define C_AOT_ERRNO strerror(errno)

// sets result to err with a printf-style message
static void c_aot_set_err(struct c_aot_compile_result* result, const char* format, ...) {
  va_list args;
  va_start(args, format);
  char* msg = NULL;
  if (vasprintf(&msg, format, args) < 0) {
    msg = NULL;
  }
  va_end(args);
  result->type = C_AOT_COMPILE_ERR;
  result->value.error_msg = msg;
}

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

enum { C_AOT_STDERR_CAPACITY = 1024 };

// ================================ api ==================================

// compiles the c source in [program_begin, program_end) to a shared library
// and loads it.
//
// c_compiler: program to run. NULL means "cc". if it has no '/', it is looked
//   up in PATH (prefer an absolute path).
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
static struct c_aot_compile_result c_aot_compile(const char* program_begin, const char* program_end, const char* c_compiler, const char* const* compiler_args) {
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

  if (program_end < program_begin) {
    errno = EINVAL;
    c_aot_set_err(&result, "program_end is before program_begin\n");
    goto end;
  }

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
  if (!c_aot_write_all(src_fd, program_begin, (size_t)(program_end - program_begin)) || lseek(src_fd, 0, SEEK_SET) == -1) {
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

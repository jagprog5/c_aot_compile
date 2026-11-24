#pragma once

/**
 * ahead of time compilation using a c compiler. c source is compiled, then loaded.
 *
 * linux only (memfd_create, /dev/fd -> needs /proc mounted). link with -ldl.
 * _GNU_SOURCE is defined here if missing, but only works if this header comes
 * before any system header; otherwise define it yourself.
 *
 * design (each point removes a class of bugs):
 * - the source goes to the compiler as a memory file on stdin. no pipe to
 *   feed, so no deadlock, short write or SIGPIPE handling.
 * - the compiler is started with posix_spawn, so no code runs in a forked
 *   child of this (possibly threaded) process.
 * - the output library is a sealed memory file that stays open while the
 *   library is loaded. its /dev/fd/N path is therefore unique (dlopen would
 *   otherwise return an already loaded library of the same path), and the
 *   code can't be rewritten after loading.
 * - every fd is close-on-exec and numbered >= 10, so nothing leaks into other
 *   children and nothing collides with the standard fds.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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
  // only if C_AOT_COMPILE_OK (else -1): the memory file the library is loaded
  // from. must stay open as long as the library is loaded
  int code_fd;
};

// ok: dlclose, then close the memory file. err: free the message.
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

// sets result to err with a printf-style message. %m prints errno, so call
// this before anything that could change errno
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

// moves fd to a number >= 10 with close-on-exec (the standard fds and the
// child's fixed fds can then never collide). consumes fd, returns -1 on failure
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

// the compiler sees the output memory file as this fd (see "-o/dev/fd/3" below)
#define C_AOT_CHILD_OUT_FD 3

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
// - the environment is passed to the compiler (except TMPDIR, which is forced
//   to /dev/shm). variables such as GCC_EXEC_PREFIX, COMPILER_PATH, CPATH,
//   LIBRARY_PATH, LD_PRELOAD change what it runs or includes.
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
  int out_fd = -1;            // compiler's output (the library)
  int err_pipe[2] = {-1, -1}; // compiler's stderr
  char** argv = NULL;
  char** envp = NULL;
  pid_t pid = 0; // nonzero while the child is unreaped
  posix_spawn_file_actions_t actions;
  bool actions_init = false;
  int rc;

  if (program_end < program_begin) {
    errno = EINVAL;
    c_aot_set_err(&result, "program_end is before program_begin\n");
    goto end;
  }

  // argv: 8 fixed + extras + NULL
  size_t num_extra = 0;
  while (compiler_args[num_extra]) {
    ++num_extra;
  }
  argv = malloc((9 + num_extra) * sizeof(*argv));
  if (!argv) {
    c_aot_set_err(&result, "out of memory\n");
    goto end;
  }
  argv[0] = (char*)c_compiler;
  argv[1] = (char*)"-pipe"; // no temp files
  argv[2] = (char*)"-fPIC";
  argv[3] = (char*)"-shared";
  argv[4] = (char*)"-O2";
  argv[5] = (char*)"-xc";         // stdin is c
  argv[6] = (char*)"-o/dev/fd/3"; // = C_AOT_CHILD_OUT_FD
  argv[7] = (char*)"-";           // source is stdin only
  for (size_t i = 0; i < num_extra; ++i) {
    argv[8 + i] = (char*)compiler_args[i];
  }
  argv[8 + num_extra] = NULL;

  // env: ours, with TMPDIR forced to memory (any existing TMPDIR must go,
  // since getenv uses the first match)
  size_t env_count = 0;
  while (environ[env_count]) {
    ++env_count;
  }
  envp = malloc((env_count + 2) * sizeof(*envp));
  if (!envp) {
    c_aot_set_err(&result, "out of memory\n");
    goto end;
  }
  {
    size_t used = 0;
    envp[used++] = (char*)"TMPDIR=/dev/shm";
    for (size_t i = 0; i < env_count; ++i) {
      if (strncmp(environ[i], "TMPDIR=", 7) != 0) {
        envp[used++] = environ[i];
      }
    }
    envp[used] = NULL;
  }

  // source -> memory file, which becomes the compiler's stdin
  src_fd = c_aot_fd_high(memfd_create("c_aot_source", MFD_CLOEXEC));
  if (src_fd == -1) {
    c_aot_set_err(&result, "memfd_create (source): %m\n");
    goto end;
  }
  if (!c_aot_write_all(src_fd, program_begin, (size_t)(program_end - program_begin)) || lseek(src_fd, 0, SEEK_SET) == -1) {
    c_aot_set_err(&result, "writing source: %m\n");
    goto end;
  }

  // output memory file. a memory file (not a pipe) is needed, as otherwise
  // gcc fails (ld: final link failed: Illegal seek)
  out_fd = c_aot_fd_high(memfd_create("c_aot_library", MFD_CLOEXEC | MFD_ALLOW_SEALING));
  if (out_fd == -1) {
    c_aot_set_err(&result, "memfd_create (library): %m\n");
    goto end;
  }

  if (pipe2(err_pipe, O_CLOEXEC) == -1) {
    err_pipe[0] = err_pipe[1] = -1;
    c_aot_set_err(&result, "pipe: %m\n");
    goto end;
  }
  err_pipe[0] = c_aot_fd_high(err_pipe[0]);
  err_pipe[1] = c_aot_fd_high(err_pipe[1]);
  if (err_pipe[0] == -1 || err_pipe[1] == -1) {
    c_aot_set_err(&result, "fcntl: %m\n");
    goto end;
  }

  // wire up the child: stdin = source, stdout = /dev/null, stderr = pipe,
  // fd 3 = library file. (all our fds are close-on-exec; dup2 clears it on
  // the new numbers)
  if ((rc = posix_spawn_file_actions_init(&actions)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions_init: %m\n");
    goto end;
  }
  actions_init = true;
  if ((rc = posix_spawn_file_actions_adddup2(&actions, src_fd, STDIN_FILENO)) != 0 ||                    //
      (rc = posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO)) != 0 ||              //
      (rc = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0)) != 0 || //
      (rc = posix_spawn_file_actions_adddup2(&actions, out_fd, C_AOT_CHILD_OUT_FD)) != 0) {
    errno = rc;
    c_aot_set_err(&result, "posix_spawn_file_actions: %m\n");
    goto end;
  }

  if ((rc = posix_spawnp(&pid, c_compiler, &actions, NULL, argv, envp)) != 0) {
    pid = 0; // not started
    errno = rc;
    c_aot_set_err(&result, "starting compiler \"%s\": %m\n", c_compiler);
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
      c_aot_set_err(&result, "reading compiler's stderr: %m\n");
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
    c_aot_set_err(&result, "waitpid: %m\n");
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

  // compiler is done: make the code immutable before running it
  if (fcntl(out_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == -1) {
    c_aot_set_err(&result, "sealing library: %m\n");
    goto end;
  }

  {
    // out_fd stays open until the library is closed, so this path is unique
    char path[32]; // "/dev/fd/" + int + NUL always fits
    snprintf(path, sizeof(path), "/dev/fd/%d", out_fd);
    void* handle = dlopen(path, RTLD_NOW);
    if (!handle) {
      const char* reason = dlerror();
      c_aot_set_err(&result, "dlopen: %s\n", reason ? reason : "unknown error");
      goto end;
    }
    result.type = C_AOT_COMPILE_OK;
    result.value.dl_handle = handle;
    result.code_fd = out_fd; // ownership moves to the result
    out_fd = -1;
  }

end:
  // close failures are ignored on purpose: the fd is released regardless, and
  // they must not turn a loaded library into an error.
  // pipe first: an unreaped child (error paths) then gets EPIPE instead of
  // blocking on stderr, so waitpid can't hang on it
  if (err_pipe[0] != -1) close(err_pipe[0]);
  if (err_pipe[1] != -1) close(err_pipe[1]);
  if (src_fd != -1) close(src_fd);
  if (out_fd != -1) close(out_fd);
  if (pid != 0) {
    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR) {}
  }
  if (actions_init) {
    posix_spawn_file_actions_destroy(&actions);
  }
  free(argv);
  free(envp);
  return result;
}

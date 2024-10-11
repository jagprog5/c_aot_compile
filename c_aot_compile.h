#pragma once
#define _GNU_SOURCE

/**
 * ahead of time compilation using c compiler. c source is compiled, then loaded
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

// returns NULL on error - an appropriate error will have been printed to stderr
// returns the dlopen handle for the compiled shared object.
//
// compiler_args is a null terminating list of cstr args which are passed to the
// compiler. some args are already specified; compiler_args is appended to args.
void* c_aot_compile(const char* c_compiler, const char* program_begin, const char* program_end, const char* const* compiler_args) {
  int stdin_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  // a memory file must be used here instead of a pipe, as otherwise this causes
  // gcc output to fail (/usr/bin/ld: final link failed: Illegal seek)
  int code_fd = -1;

  void* ret = NULL;
  pid_t pid;

  if (pipe(stdin_pipe) == -1) {
    perror("pipe");
    goto end;
  }

  if (pipe(stderr_pipe) == -1) {
    perror("pipe");
    goto end;
  }

  code_fd = memfd_create("dynamic_compiled_shared_library", 0);
  if (code_fd == -1) {
    perror("memfd_create");
    goto end;
  }

  char compile_output_file[32];
  {
    int printf_result = snprintf(compile_output_file, //
                                 sizeof(compile_output_file), "/dev/fd/%d", code_fd);
    if (printf_result < 0 || (unsigned long)printf_result >= sizeof(compile_output_file)) {
      fputs("format error", stderr);
      goto end;
    }
  }

  pid = fork();

  if (pid < 0) {
    perror("fork");
    goto end;
  }

  if (pid == 0) {
    // child process
    if (dup2(stdin_pipe[0], STDIN_FILENO) == -1 || //
                 dup2(stderr_pipe[1], STDERR_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null == -1) {
      perror("open");
      exit(EXIT_FAILURE); // in child process - exit now
    }
    if (dup2(dev_null, STDOUT_FILENO) == -1) {
      perror("dup2");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    if (close(stdin_pipe[1]) == -1) {
      // must close stdin writer or else it will keep child process alive
      // as it waits for input
      perror("close");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    char compile_output_file_arg[34];
    {
      int printf_result = snprintf(compile_output_file_arg, //
                                   sizeof(compile_output_file_arg), "-o%s", compile_output_file);
      if (printf_result < 0 || (unsigned long)printf_result >= sizeof(compile_output_file_arg)) {
        fputs("format error", stderr);
        exit(EXIT_FAILURE); // in child process - exit now
      }
    }

    size_t num_extra_args = 0;
    while (compiler_args[num_extra_args] != 0) {
      ++num_extra_args;
    }

    // copy required since args are non const
    char* args[9 + num_extra_args];

    // first arg always is self
    const char* arg0_const = c_compiler;
    size_t arg0_size = strlen(arg0_const) + 1;
    char arg0[arg0_size];
    memcpy(arg0, arg0_const, arg0_size);
    args[0] = arg0;

    // don't use temp files during compilation; pipes instead
    const char* arg1_const = "-pipe";
    size_t arg1_size = strlen(arg1_const) + 1;
    char arg1[arg1_size];
    memcpy(arg1, arg1_const, arg1_size);
    args[1] = arg1;

    // shouldn't be needed, but just to be safe. the code shouldn't be
    // moved from the memory file after it is written.
    const char* arg2_const = "-fPIC";
    size_t arg2_size = strlen(arg2_const) + 1;
    char arg2[arg2_size];
    memcpy(arg2, arg2_const, arg2_size);
    args[2] = arg2;

    const char* arg3_const = "-shared"; // shared object (resolve symbols)
    size_t arg3_size = strlen(arg3_const) + 1;
    char arg3[arg3_size];
    memcpy(arg3, arg3_const, arg3_size);
    args[3] = arg3;

    const char* arg4_const = "-O2"; // optimize a good amount (priority is for fast runtime)
    size_t arg4_size = strlen(arg4_const) + 1;
    char arg4[arg4_size];
    memcpy(arg4, arg4_const, arg4_size);
    args[4] = arg4;

    const char* arg5_const = "-xc"; // stdin contains c language
    size_t arg5_size = strlen(arg5_const) + 1;
    char arg5[arg5_size];
    memcpy(arg5, arg5_const, arg5_size);
    args[5] = arg5;

    args[6] = compile_output_file_arg; // write compiled shared object to memory file

    const char* arg7_const = "-"; // no further files to compile will be specified. only stdin
    size_t arg7_size = strlen(arg7_const) + 1;
    char arg7[arg7_size];
    memcpy(arg7, arg7_const, arg7_size);
    args[7] = arg7;

    size_t extra_args_arena_size = 0;

    for (size_t i = 0; i < num_extra_args; ++i) {
      extra_args_arena_size += strlen(compiler_args[i]) + 1;
    }

    char extra_args_arena[extra_args_arena_size];

    {
      char* extra_args_arena_walk = extra_args_arena;
      for (size_t i = 0; i < num_extra_args; ++i) {
        const char* the_arg = compiler_args[i];
        args[8 + i] = extra_args_arena_walk;
        while (1) {
          char ch = *the_arg++;
          bool complete = ch == '\0';
          *extra_args_arena_walk++ = ch; // includes null
          if (complete) break;
        }
      }
    }

    args[sizeof(args) / sizeof(*args) - 1] = (char*)NULL; // execl args are null terminating

    execvp(c_compiler, args);
    perror("execl");    // only reached on error
    exit(EXIT_FAILURE); // in child process - exit now
    // all other fds will be closed by OS on child process exit.
    // this is required by the code_pipe (can't be closed before execl)
  }

  // parent process

  // write then close the input
  if (write(stdin_pipe[1], program_begin, program_end - program_begin) == -1) {
    perror("write");
    goto end;
  }

  // must close stdin writer or else it will keep child process alive as it
  // waits for input
  {
    int close_result = close(stdin_pipe[1]);
    stdin_pipe[1] = -1;
    if (close_result == -1) {
      perror("close");
      goto end;
    }
  }

  // must close output streams here, or else it will keep the parent
  // blocking on read as it waits for the input from child to end
  {
    int close_result = close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    if (close_result == -1) {
      perror("close");
      goto end;
    }
  }

  {
    int child_return_status;
    if (waitpid(pid, &child_return_status, 0) == -1) {
      perror("waitpid");
      goto end;
    }

    if (WIFEXITED(child_return_status)) {
      child_return_status = WEXITSTATUS(child_return_status);
    }

    if (child_return_status != 0) {
      fprintf(stderr, "child process containing %s exited with code %d, stderr:\n", c_compiler, child_return_status);
      char buffer[1024];
      ssize_t count;
      size_t while_loop_limit = 1000; // make bounded in time for safety
      while (1) {
        if (while_loop_limit == 0) {
          fputs("\n... stderr was truncated\n", stderr);
          break;
        }
        --while_loop_limit;
        count = read(stderr_pipe[0], buffer, sizeof(buffer));
        if (count < 0) {
          perror("read");
          goto end;
        }
        if (count == 0) {
          break;
        }
        fwrite(buffer, sizeof(char), count, stderr);
      }
      goto end;
    }
  }

  {
    void* handle = dlopen(compile_output_file, RTLD_NOW);
    if (handle == NULL) {
      char* reason = dlerror();
      if (reason) {
        fprintf(stderr, "dlopen: %s\n", reason);
      } else {
        fputs("dlopen failed for an unknown reason", stderr);
      }
      goto end;
    }
    ret = handle;
  }

end:
  int close_errored = 0;
  if (stdin_pipe[0] != -1) close_errored |= close(stdin_pipe[0]);
  if (stdin_pipe[1] != -1) close_errored |= close(stdin_pipe[1]);
  if (stderr_pipe[0] != -1) close_errored |= close(stderr_pipe[0]);
  if (stderr_pipe[1] != -1) close_errored |= close(stderr_pipe[1]);
  if (code_fd != -1) close_errored |= close(code_fd);

  if (close_errored) {
    perror("close");
    if (ret != NULL) {
      // yoink. no longer returning the handle since there were errors while cleaning up
      if (dlclose(ret) != 0) {
        char* reason = dlerror();
        if (reason) {
          fprintf(stderr, "dlclose: %s\n", reason);
        } else {
          fputs("dlclose failed for an unknown reason", stderr);
        }
      }
      ret = NULL;
      // end of yoink
    }
  }

  return ret;
}

// overload for compile
void* c_aot_compile_no_args(const char* c_compiler, const char* program_begin, const char* program_end) {
  const char* compiler_args = NULL;
  return c_aot_compile(c_compiler, program_begin, program_end, &compiler_args);
}
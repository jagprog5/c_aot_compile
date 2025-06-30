#pragma once

/**
 * ahead of time compilation using c compiler. c source is compiled, then loaded
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

// ================================= error handling =====================================

// this is a super basic and dead simple string manipulation lib, for use by the aot lib's error messages

// malloc formatted string
static char* c_aot_err_printf_owned(const char* format, ...) {
  va_list args;
  va_start(args, format);
  int size = vsnprintf(NULL, 0, format, args);
  va_end(args);

  if (size < 0) {
    return NULL;
  }
  size += 1; // for null char
  char* ret = malloc(size * sizeof(char));
  if (!ret) {
    return NULL;
  }

  va_start(args, format);
  vsnprintf(ret, size, format, args);
  va_end(args);

  return ret;
}

// concatenate two strings.
// args:
// - are owned (malloc)
// - can be NULL (treated as empty)
// - will be freed by this function  
//
// return value:
// - can be NULL
// - is owned (malloc)
static char* c_aot_err_strcat(char* first, char* second) {
  const char* first_used = first ? first : "";
  const char* second_used = second ? second : "";

  size_t next_size = strlen(first_used) + strlen(second_used) + 1; // +1 for terminator
  char* ret = malloc(next_size * sizeof(char));
  if (ret) {
    char* ret_walk = ret;
    while (*first_used != '\0') {
      *ret_walk++ = *first_used++;
    }
    while (*second_used != '\0') {
      *ret_walk++ = *second_used++;
    }
    *ret_walk++ = '\0';
  }

  free(first);
  free(second);
  return ret;
}

// perror_arg is a string literal, just like the arg to perror
//
// error_msg_so_far arg: 
// - is owned (malloc)
// - can be NULL (treated as empty)
// - will be freed by this function
static char* c_aot_err_strcat_perror(char* error_msg_so_far, const char* perror_arg) {
  char* formatted = c_aot_err_printf_owned("%s: %s\n", perror_arg, strerror(errno));
  char* ret = c_aot_err_strcat(error_msg_so_far, formatted);
  return ret;
}

// appends data with length to the error message. if null bytes are
// contained in the data, then it will appear to terminate early
//
// error_msg_so_far arg: 
// - is owned (malloc)
// - can be NULL (treated as empty)
// - will be freed by this function  
//
// data is NOT owned and will point to num_elements bytes
static char* c_aot_err_strcat_len(char* error_msg_so_far, const char* data, size_t num_elements) {
  char* msg_used = error_msg_so_far ? error_msg_so_far : "";

  char* ret = malloc((strlen(msg_used) + num_elements + 1) * sizeof(char));
  if (ret) {
    char* ret_walk = ret;
    while (*msg_used != '\0') {
      *ret_walk++ = *msg_used++;
    }
    for (size_t i = 0; i < num_elements; ++i) {
      *ret_walk++ = data[i];
    }
    *ret_walk++ = '\0';
  }

  free(error_msg_so_far);
  return ret;
}

// ================================== c aot result type ==========================

enum c_aot_compile_result_type {
  C_AOT_COMPILE_OK,
  C_AOT_COMPILE_ERR,
};

union c_aot_compile_result_value {
  // only if C_AOT_COMPILE_OK.
  // OWNED, must be freed with dlclose
  // never NULL
  void* dl_handle;
  // only if C_AOT_COMPILE_ERR.
  // OWNED, must be freed with free.
  // might be NULL only on alloc failure
  char* error_msg;
};

// variant type. either err with error message, or ok with handle
struct c_aot_compile_result {
  enum c_aot_compile_result_type type;
  union c_aot_compile_result_value value;
};

// ================================== c aot result type wrapper of string manipulation functions ==========================

// checks if OK value is contained. destroys it.
//
// returns OWNED error message (NULL on no error)
static char* c_aot_compile_result_convert_to_err(struct c_aot_compile_result* ret) {
  if (ret->type != C_AOT_COMPILE_OK) {
    // already contains error. nothing to do
    return NULL;
  }

  void* dl_handle_to_destroy = ret->value.dl_handle;
  ret->value.dl_handle = NULL;

  ret->type = C_AOT_COMPILE_ERR;
  ret->value.error_msg = NULL; // intentionally redundant (ptr union already set)

  if (dl_handle_to_destroy == NULL) {
    // ok value was contained, but it wasn't set yet. nothing more to do
    return NULL;
  }

  // do destruction of previously contained ok value
  if (dlclose(dl_handle_to_destroy) == 0) {
    return NULL; // no err
  }

  char* reason = dlerror();
  char* reason_msg;
  if (reason) {
    reason_msg = c_aot_err_printf_owned("dlclose: %s\n", reason);
  } else {
    // make owned on either branch
    reason_msg = strdup("dlclose failed for an unknown reason\n");
  }
  return reason_msg;
}

static void c_aot_compile_result_append_error(struct c_aot_compile_result* ret, char* msg) {
  char* destroy_error = c_aot_compile_result_convert_to_err(ret);
  ret->value.error_msg = c_aot_err_strcat(ret->value.error_msg, msg);
  ret->value.error_msg = c_aot_err_strcat(ret->value.error_msg, destroy_error);
}

static void c_aot_compile_result_append_error_perror(struct c_aot_compile_result* ret, const char* perror_arg) {
  char* destroy_error = c_aot_compile_result_convert_to_err(ret);
  ret->value.error_msg = c_aot_err_strcat_perror(ret->value.error_msg, perror_arg);
  ret->value.error_msg = c_aot_err_strcat(ret->value.error_msg, destroy_error);
}

static void c_aot_compile_result_append_error_len(struct c_aot_compile_result* ret, const char* data, size_t num_elements) {
  char* destroy_error = c_aot_compile_result_convert_to_err(ret);
  ret->value.error_msg = c_aot_err_strcat_len(ret->value.error_msg, data, num_elements);
  ret->value.error_msg = c_aot_err_strcat(ret->value.error_msg, destroy_error);
}

// ==========================================================================================================

// compiler_args is a null terminating list of cstr args which are passed to the
// compiler. some args are already specified; compiler_args is appended to
// existing args.
//
// warning! given that this is a JIT, it's an avenue for arbitrary code
// execution. it's assumed that the input program is properly sanitized -
// ideally have constant programs which are chosen at runtime. additionally,
// c_compiler is the program to execute - should also be a set constant
struct c_aot_compile_result c_aot_compile(const char* program_begin, const char* program_end, const char* c_compiler, const char* const* compiler_args) {
  if (!c_compiler) {
    c_compiler = "cc";
  }

  int stdin_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  // a memory file must be used here instead of a pipe, as otherwise this causes
  // gcc output to fail (/usr/bin/ld: final link failed: Illegal seek)
  int code_fd = -1;

  struct c_aot_compile_result ret;
  ret.type = C_AOT_COMPILE_OK;
  ret.value.dl_handle = NULL;

  // non zero only if in parent and child is running or hasn't been "reaped"
  pid_t pid = 0;

  if (pipe(stdin_pipe) == -1) {
    c_aot_compile_result_append_error_perror(&ret, "pipe");
    goto end;
  }

  if (pipe(stderr_pipe) == -1) {
    c_aot_compile_result_append_error_perror(&ret, "pipe");
    goto end;
  }

  // deliberate no MFD_CLOEXEC - written to by child program
  code_fd = memfd_create("dynamic_compiled_shared_library", 0);
  if (code_fd == -1) {
    c_aot_compile_result_append_error_perror(&ret, "memfd_create");
    goto end;
  }
  
  // buffer is well over maximum output size. and snprintf guards overflow
  // "/dev/fd/" → 8  
  // "2147483647" → 10  
  // "\0" → 1
  char compile_output_file[32];
  {
    int printf_result = snprintf(compile_output_file, //
                                 sizeof(compile_output_file), "/dev/fd/%d", code_fd);
    if (printf_result < 0 || (size_t)printf_result >= sizeof(compile_output_file)) {
      c_aot_compile_result_append_error(&ret, strdup("format error\n"));
      goto end;
    }
  }

  pid = fork();

  if (pid < 0) {
    c_aot_compile_result_append_error_perror(&ret, "fork");
    goto end;
  }

  if (pid == 0) {
    // child process
    if (dup2(stdin_pipe[0], STDIN_FILENO) == -1 || //
                 dup2(stderr_pipe[1], STDERR_FILENO) == -1) {
      perror("dup2 failed before compiler started");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    int dev_null = open("/dev/null", O_WRONLY);
    if (dev_null == -1) {
      perror("open failed before compiler started");
      exit(EXIT_FAILURE); // in child process - exit now
    }
    if (dup2(dev_null, STDOUT_FILENO) == -1) {
      perror("dup2 failed before compiler started");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    if (close(stdin_pipe[1]) == -1) {
      // must close stdin writer or else it will keep child process alive
      // as it waits for input
      perror("close failed before compiler started");
      exit(EXIT_FAILURE); // in child process - exit now
    }

    // buffer size ok, only 2 characters are added from above
    char compile_output_file_arg[sizeof(compile_output_file) / sizeof(*compile_output_file) + 2];
    {
      int printf_result = snprintf(compile_output_file_arg, //
                                   sizeof(compile_output_file_arg), "-o%s", compile_output_file);
      if (printf_result < 0 || (size_t)printf_result >= sizeof(compile_output_file_arg)) {
        fputs("format error before compiler started", stderr);
        exit(EXIT_FAILURE); // in child process - exit now
      }
    }

    size_t num_extra_args = 0;
    while (compiler_args[num_extra_args] != 0) {
      ++num_extra_args;
    }

    // copy required since args are non const. TODO VLA should not be used
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

    // pass ENV vars. append TMPDIR so gcc, clang won't use disk for temp files
    size_t env_count = 0;
    extern char **environ;
    while (environ[env_count] != 0) {
        ++env_count;
    }
    env_count += 2; // +1 for new var, +1 for NULL

    char* env[env_count];

    for (size_t i = 0; i < env_count - 2; ++i) {
      env[i] = environ[i];
    }

    // copy required since env non const
    const char* env_to_add_const = "TMPDIR=/dev/shm";
    size_t env_to_add_size = strlen(env_to_add_const) + 1;
    char env_to_add[env_to_add_size];
    memcpy(env_to_add, env_to_add_const, env_to_add_size);

    env[env_count - 2] = env_to_add; // place it last (highest precedence)
    env[env_count - 1] = (char*)NULL; // env null terminating
    execvpe(c_compiler, args, env);
    perror("execl failed before compiler started");    // only reached on error
    exit(EXIT_FAILURE); // in child process - exit now
    // all other fds will be closed by OS on child process exit.
    // this is required by the code_pipe (can't be closed before execl)
  }

  // parent process

  // write then close the input
  if (write(stdin_pipe[1], program_begin, program_end - program_begin) == -1) {
    c_aot_compile_result_append_error_perror(&ret, "write");
    goto end;
  }

  // must close stdin writer or else it will keep child process alive as it
  // waits for input
  {
    int close_result = close(stdin_pipe[1]);
    stdin_pipe[1] = -1;
    if (close_result == -1) {
      c_aot_compile_result_append_error_perror(&ret, "close");
      goto end;
    }
  }

  // must close output streams here, or else it will keep the parent
  // blocking on read as it waits for the input from child to end
  {
    int close_result = close(stderr_pipe[1]);
    stderr_pipe[1] = -1;
    if (close_result == -1) {
      c_aot_compile_result_append_error_perror(&ret, "close");
      goto end;
    }
  }

  {
    // the compiler might be producing stderr.
    // something must be reading it, or else the stderr write will block if the compiler's error is very large.
    
    // reading will always occur, but only if there is a failure exit status then it will be displayed.
    // only n bytes will be read, and the reset is discarded (constant space)
    const size_t COMPILER_STDERR_BUF_CAPACITY = 1024;
    size_t compiler_stderr_size = 0;
    char compiler_stderr_buf[COMPILER_STDERR_BUF_CAPACITY];

    bool compiler_stderr_was_truncated = false;

    while (compiler_stderr_size != COMPILER_STDERR_BUF_CAPACITY) {
      ssize_t read_ret = read(stderr_pipe[0], compiler_stderr_buf + compiler_stderr_size, COMPILER_STDERR_BUF_CAPACITY - compiler_stderr_size);
      if (read_ret < 0) {
        c_aot_compile_result_append_error_perror(&ret, "reading compiler's stderr");
        goto end;
      }
      if (read_ret == 0) {
        goto after_discard_compiler_stderr;
      }
      compiler_stderr_size += read_ret;
    }

    // the stderr buffer is full, discard any remaining
    while (1) {
      char discard[COMPILER_STDERR_BUF_CAPACITY]; // any positive cap would work
      ssize_t read_ret = read(stderr_pipe[0], discard, sizeof(discard) / sizeof(char));
      if (read_ret < 0) {
        c_aot_compile_result_append_error_perror(&ret, "reading compiler's stderr");
        goto end;
      }
      if (read_ret == 0) {
        break;
      }
      // if this point is reached, then some amount of bytes has been discarded
      compiler_stderr_was_truncated = true;
    }

    after_discard_compiler_stderr:;

    int child_return_status;
    if (waitpid(pid, &child_return_status, 0) == -1) {
      pid = 0; // failed waiting for it. don't try waitpid again during cleanup
      c_aot_compile_result_append_error_perror(&ret, "waitpid");
      goto end;
    }
    pid = 0; // successfully closed out and finished

    if (WIFEXITED(child_return_status)) {
      child_return_status = WEXITSTATUS(child_return_status);
    }

    if (child_return_status != 0) {
      char* formatted_str = c_aot_err_printf_owned("child process for compiler \"%s\" exited with code %d. stderr:\n", c_compiler, child_return_status);
      c_aot_compile_result_append_error(&ret, formatted_str);
      c_aot_compile_result_append_error_len(&ret, compiler_stderr_buf, compiler_stderr_size);
      if (compiler_stderr_was_truncated) {
        char* truncate_msg_formatted = c_aot_err_printf_owned("\n... stderr from \"%s\" was truncated\n", c_compiler);
        c_aot_compile_result_append_error(&ret, truncate_msg_formatted);
      }
      goto end;
    }
  }

  // ret is guaranteed OK right now, since in all cases above, on err it goto
  // end (skipping here). but adding the if condition anyways just in case
  if (ret.type == C_AOT_COMPILE_OK) {
    void* handle = dlopen(compile_output_file, RTLD_NOW);
    if (handle == NULL) {
      char* reason = dlerror();
      char* fmt_err;
      if (reason) {
        fmt_err = c_aot_err_printf_owned("dlopen: %s\n", reason);
      } else {
        fmt_err = strdup("dlopen failed for an unknown reason\n");
      }
      c_aot_compile_result_append_error(&ret, fmt_err);
      goto end;
    } else {
      ret.value.dl_handle = handle;
    }
  }

end:;
  if (stdin_pipe[0] != -1) {
    if (close(stdin_pipe[0])) {
      c_aot_compile_result_append_error_perror(&ret, "close stdin read fd");
    }
  }
  if (stdin_pipe[1] != -1) {
    if (close(stdin_pipe[1])) {
      c_aot_compile_result_append_error_perror(&ret, "close stdin write fd");
    }
  }

  if (stderr_pipe[0] != -1) {
    if (close(stderr_pipe[0])) {
      c_aot_compile_result_append_error_perror(&ret, "close stderr read fd");
    }
  }
  if (stderr_pipe[1] != -1) {
    if (close(stderr_pipe[1])) {
      c_aot_compile_result_append_error_perror(&ret, "close stderr write fd");
    }
  }

  if (code_fd != -1) {
    if (close(code_fd)) {
      c_aot_compile_result_append_error_perror(&ret, "close stdin mem file fd");
    }
  }

  if (pid != 0) {
    // only happens in error context (from reading or writing failing. goes to
    // end and skipped the above waitpid). ensure pid is reaped
    if (waitpid(pid, NULL, 0) == -1) {
      c_aot_compile_result_append_error_perror(&ret, "waitpid after child pipe failure");
    }
    pid = 0; // intentional redundant
  }

  return ret;
}

// build (linux, macos): cc tests/test.c -I. -ldl -lpthread -o /tmp/c_aot_test && /tmp/c_aot_test
// build (windows, mingw): gcc tests/test.c -I. -o c_aot_test.exe && ./c_aot_test.exe
// msvc's headers deprecate getenv and friends (an error with -Werror)
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
// the header goes first: it defines _GNU_SOURCE, which only works before any system header
#include "../c_aot_compile.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef __GLIBC__
#include <gnu/libc-version.h>
#endif

// windows toolchains other than mingw gcc only export what is marked
#ifdef _WIN32
#define EXPORT "__declspec(dllexport) "
#else
#define EXPORT ""
#endif

// the compiler under test, resolved once in main: C_AOT_TEST_COMPILER (a name
// or path; skipped when unset or empty), else the memory first preset
// what a candidate names, and its args (none for a tcc library)
static const char* named(const struct c_aot_candidate* c) {
  switch (c->type) {
  case C_AOT_CANDIDATE_EXECUTABLE: return c->value.executable.compiler_exe_path_or_name;
  case C_AOT_CANDIDATE_ENV: return c->value.env.variable;
  case C_AOT_CANDIDATE_TCC_LIBRARY: return c->value.tcc_library.library_path_or_name;
  }
  return NULL;
}
static const char* const* args_of(const struct c_aot_candidate* c) {
  switch (c->type) {
  case C_AOT_CANDIDATE_EXECUTABLE: return c->value.executable.args;
  case C_AOT_CANDIDATE_ENV: return c->value.env.args;
  case C_AOT_CANDIDATE_TCC_LIBRARY: return NULL;
  }
  return NULL;
}

static struct c_aot_resolve_result g_resolved; // kept for the whole run
static const struct c_aot_compiler* g_compiler; // the ok compiler in it

static struct c_aot_compile_result compile(const char* src) {
  return c_aot_compile(g_compiler, src, strlen(src));
}

static int call_f(struct c_aot_compile_result* r) {
  int (*f)(void);
  *(void**)&f = c_aot_compile_symbol(r, "f");
  assert(f);
  return f();
}

// number of entries in dir (not counting . and ..)
static int count_entries(const char* dir) {
  int count = 0;
#ifdef _WIN32
  char pattern[1024];
  snprintf(pattern, sizeof(pattern), "%s\\*", dir);
  WIN32_FIND_DATAA entry;
  HANDLE find = FindFirstFileA(pattern, &entry);
  assert(find != INVALID_HANDLE_VALUE);
  do {
    if (strcmp(entry.cFileName, ".") != 0 && strcmp(entry.cFileName, "..") != 0) {
      ++count;
    }
  } while (FindNextFileA(find, &entry));
  FindClose(find);
#else
  DIR* d = opendir(dir);
  assert(d);
  struct dirent* entry;
  while ((entry = readdir(d)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      ++count;
    }
  }
  closedir(d);
#endif
  return count;
}

static void test_no_alias(void) {
  // two libraries loaded at once must not alias each other
  struct c_aot_compile_result a = compile(EXPORT "int f(void){return 1;}");
  struct c_aot_compile_result b = compile(EXPORT "int f(void){return 2;}");
  assert(a.type == C_AOT_COMPILE_OK && b.type == C_AOT_COMPILE_OK);
  assert(call_f(&a) == 1);
  assert(call_f(&b) == 2);
  c_aot_compile_result_destroy(&a);
  c_aot_compile_result_destroy(&b);
}

#ifdef C_AOT_MEMORY_FILES
static void test_reused_fd_number_does_not_alias(void) {
  // -z nodelete: dlclose leaves the first library mapped, still known to the
  // loader under the name it was opened with. the next library gets the same
  // fd number, and must not be mistaken for it
  static const char* const keep[] = {"-Wl,-z,nodelete", NULL};
  struct c_aot_candidate list[] = {c_aot_candidate_executable(g_compiler->value.executable.path, keep)};
  struct c_aot_resolve_result resolved = c_aot_compiler_resolve(list, 1);
  assert(resolved.type == C_AOT_RESOLVE_OK);
  const struct c_aot_compiler* compiler = &resolved.value.compiler;
  const char* a_src = EXPORT "int f(void){return 1;}";
  const char* b_src = EXPORT "int f(void){return 2;}";
  struct c_aot_compile_result a = c_aot_compile(compiler, a_src, strlen(a_src));
  assert(a.type == C_AOT_COMPILE_OK && call_f(&a) == 1);
  c_aot_compile_result_destroy(&a);
  struct c_aot_compile_result b = c_aot_compile(compiler, b_src, strlen(b_src));
  assert(b.type == C_AOT_COMPILE_OK);
  assert(call_f(&b) == 2);
  c_aot_compile_result_destroy(&b);
  c_aot_resolve_result_destroy(&resolved);
}
#endif

static void test_compile_error(void) {
  // compile error is reported, with the compiler's stderr
  struct c_aot_compile_result bad = compile("int f(void){ syntax error }");
  assert(bad.type == C_AOT_COMPILE_ERR);
  assert(bad.value.error_msg && strstr(bad.value.error_msg, "error"));
  c_aot_compile_result_destroy(&bad);
}

static void set_env(const char* name, const char* value) {
#ifdef _WIN32
  assert(_putenv_s(name, value) == 0);
#else
  assert(setenv(name, value, 1) == 0);
#endif
}

static void test_resolution_diagnostics(void) {
  // a nonexistent path, an unset variable, a relative path that is not there,
  // a name not in PATH, a variable holding arguments: each is reported by itself
  set_env("C_AOT_TEST_ARGS", "gcc -O2");
  struct c_aot_candidate list[] = {
      c_aot_candidate_executable("/nonexistent/cc", NULL),
      c_aot_candidate_env("C_AOT_TEST_SURELY_UNSET", NULL),
      c_aot_candidate_executable("./some/where", NULL),
      c_aot_candidate_executable("no-such-compiler-xyz", NULL),
      c_aot_candidate_env("C_AOT_TEST_ARGS", NULL),
  };
  struct c_aot_resolve_result none = c_aot_compiler_resolve(list, 5);
  assert(none.type == C_AOT_RESOLVE_ERR);
  assert(none.value.error_msg);
  assert(strstr(none.value.error_msg, "/nonexistent/cc"));
  assert(strstr(none.value.error_msg, "not set"));
  assert(strstr(none.value.error_msg, "no such executable file"));
  assert(strstr(none.value.error_msg, "not found in PATH"));
  assert(strstr(none.value.error_msg, "arguments aren't supported"));
  c_aot_resolve_result_destroy(&none);

  // no candidates at all
  struct c_aot_resolve_result empty = c_aot_compiler_resolve(NULL, 0);
  assert(empty.type == C_AOT_RESOLVE_ERR && empty.value.error_msg);
  c_aot_resolve_result_destroy(&empty);
}

// true if the candidate is the program tcc
static bool is_tcc_program(const struct c_aot_candidate* c) {
  return c->type == C_AOT_CANDIDATE_EXECUTABLE && strcmp(named(c), "tcc") == 0;
}

static void test_memory_first_candidates_order(void) {
  struct c_aot_candidate list[C_AOT_PRESET_CANDIDATES_MAX];
  bool cc_first_without = false, cc_first_with = false;

  // without a libtcc there is none in the list, anywhere
  size_t n = c_aot_memory_first_candidates(list, NULL);
  for (size_t i = 0; i < n; ++i) assert(list[i].type != C_AOT_CANDIDATE_TCC_LIBRARY);
  cc_first_without = list[0].type == C_AOT_CANDIDATE_ENV && strcmp(named(&list[0]), "CC") == 0;

  size_t with = c_aot_memory_first_candidates(list, "/some/libtcc.so");
  assert(with == n + 1);
  cc_first_with = list[0].type == C_AOT_CANDIDATE_ENV && strcmp(named(&list[0]), "CC") == 0;
#ifdef C_AOT_MEMORY_FILES
  // memory files: the system compilers keep nothing on disk, so $CC and they
  // come first, then libtcc, then tcc as a program, last
  assert(cc_first_without && cc_first_with);
  assert(list[with - 2].type == C_AOT_CANDIDATE_TCC_LIBRARY && strcmp(named(&list[with - 2]), "/some/libtcc.so") == 0);
  assert(is_tcc_program(&list[with - 1]));
#else
  // no memory files: libtcc keeps nothing on disk, so it comes first, before $CC
  assert(!cc_first_with);
  assert(list[0].type == C_AOT_CANDIDATE_TCC_LIBRARY && strcmp(named(&list[0]), "/some/libtcc.so") == 0);
#ifdef __linux__
  // tcc as a program stays last on linux (its libraries may not load there)
  assert(cc_first_without);
  assert(is_tcc_program(&list[with - 1]));
  assert(list[1].type == C_AOT_CANDIDATE_ENV);
#else
  // elsewhere: tcc as a program right after libtcc (it compiles fastest), then $CC
  assert(!cc_first_without);
  assert(is_tcc_program(&list[1]));
  assert(list[2].type == C_AOT_CANDIDATE_ENV && strcmp(named(&list[2]), "CC") == 0);
  c_aot_memory_first_candidates(list, NULL);
  assert(is_tcc_program(&list[0]) && list[1].type == C_AOT_CANDIDATE_ENV);
#endif
#endif
  // tcc as a program is in the list exactly once, wherever it is
  with = c_aot_memory_first_candidates(list, "/some/libtcc.so");
  int tcc_programs = 0;
  for (size_t i = 0; i < with; ++i) tcc_programs += is_tcc_program(&list[i]);
  assert(tcc_programs == 1);
}

#ifndef _WIN32
// writes an executable shell script to path
static void write_script(const char* path, const char* body) {
  FILE* f = fopen(path, "w");
  assert(f);
  fputs(body, f);
  fclose(f);
  assert(chmod(path, 0755) == 0);
}

static void test_candidate_args(void) {
  char dir[] = "/tmp/c_aot_test_args_XXXXXX";
  assert(mkdtemp(dir));
  char script[256], record[256], picky[256], body[1024];
  snprintf(script, sizeof(script), "%s/cc.sh", dir);
  snprintf(record, sizeof(record), "%s/record", dir);
  snprintf(picky, sizeof(picky), "%s/picky.sh", dir);

  // 1. a candidate's args come after the fixed ones
  snprintf(body, sizeof(body), "#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\nexec cc \"$@\"\n", record);
  write_script(script, body);
  const char* const candidate_args[] = {"-DFROM_CANDIDATE=1", NULL};
  struct c_aot_candidate list[] = {c_aot_candidate_executable(script, candidate_args)};
  struct c_aot_resolve_result resolved = c_aot_compiler_resolve(list, 1);
  assert(resolved.type == C_AOT_RESOLVE_OK);
  const char* src = EXPORT "int f(void){return FROM_CANDIDATE;}";
  struct c_aot_compile_result r = c_aot_compile(&resolved.value.compiler, src, strlen(src));
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 1);
  c_aot_compile_result_destroy(&r);
  c_aot_resolve_result_destroy(&resolved);
  char seen[2048];
  FILE* in = fopen(record, "r");
  assert(in);
  size_t n = fread(seen, 1, sizeof(seen) - 1, in);
  fclose(in);
  seen[n] = '\0';
  // the fixed core ends with "-" (stdin): then the candidate's
  const char* after_stdin = strstr(seen, "\n-\n");
  assert(after_stdin);
  assert(strcmp(after_stdin, "\n-\n-DFROM_CANDIDATE=1\n") == 0);
  assert(strstr(seen, "-O1\n")); // the default optimization is still there, before them

  // 2. a compiler that rejects the candidate's args: the next candidate wins
  write_script(picky, "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -march=native ] && { echo 'unknown option' >&2; exit 1; }; done\nexec cc \"$@\"\n");
  const char* const fast[] = {"-O2", "-march=native", NULL};
  struct c_aot_candidate with_and_without[] = {c_aot_candidate_executable(picky, fast), c_aot_candidate_executable(picky, NULL)};
  struct c_aot_resolve_result fell = c_aot_compiler_resolve(with_and_without, 2);
  assert(fell.type == C_AOT_RESOLVE_OK);
  assert(fell.value.compiler.candidate == 1); // the first was tried, and failed the test program
  assert(fell.value.compiler.value.executable.args == NULL);
  c_aot_resolve_result_destroy(&fell);

  unlink(script);
  unlink(record);
  unlink(picky);
  rmdir(dir);
}
#endif

static void test_fast_candidates(void) {
  struct c_aot_candidate list[C_AOT_PRESET_CANDIDATES_MAX];
  size_t n = c_aot_fast_candidates(list, NULL);
  assert(n == 9); // $CC and three programs, each with the fast args and then without, then tcc
  for (size_t i = 0; i + 1 < n - 1; i += 2) {
    assert(args_of(&list[i]) && strcmp(args_of(&list[i])[0], "-O2") == 0); // fast args first
    assert(args_of(&list[i + 1]) == NULL);                                 // then without, if rejected
    assert(list[i].type == list[i + 1].type && strcmp(named(&list[i]), named(&list[i + 1])) == 0);
  }
  assert(list[0].type == C_AOT_CANDIDATE_ENV && strcmp(named(&list[0]), "CC") == 0);
  assert(is_tcc_program(&list[n - 1])); // last, everywhere: it doesn't optimize

  // libtcc, if given, comes just before it
  size_t with = c_aot_fast_candidates(list, "/some/libtcc.so");
  assert(with == n + 1);
  assert(list[with - 2].type == C_AOT_CANDIDATE_TCC_LIBRARY);
  assert(is_tcc_program(&list[with - 1]));

  // on this machine it resolves, with the fast args if the compiler takes them
  struct c_aot_resolve_result r = c_aot_compiler_resolve_fast(NULL);
  assert(r.type == C_AOT_RESOLVE_OK);
  assert(r.value.compiler.type == C_AOT_COMPILER_EXECUTABLE);
  c_aot_resolve_result_destroy(&r);
}

static void test_resolution_falls_through(void) {
  // the first candidates fail, the last works: the winner is reported
  struct c_aot_candidate preset[C_AOT_PRESET_CANDIDATES_MAX];
  size_t count = c_aot_memory_first_candidates(preset, NULL);
  struct c_aot_candidate list[C_AOT_PRESET_CANDIDATES_MAX + 2];
  list[0] = c_aot_candidate_executable("/nonexistent/cc", NULL);
  list[1] = c_aot_candidate_tcc_library("/nonexistent/libtcc.so", NULL, NULL);
  for (size_t i = 0; i < count; ++i) list[2 + i] = preset[i];
  struct c_aot_resolve_result c = c_aot_compiler_resolve(list, 2 + count);
  assert(c.type == C_AOT_RESOLVE_OK);
  assert(c.value.compiler.type == C_AOT_COMPILER_EXECUTABLE);
  assert(c.value.compiler.candidate >= 2);
  assert(c.value.compiler.value.executable.path && c.value.compiler.value.executable.path[0]);
  c_aot_resolve_result_destroy(&c);

  // C_AOT_TEST_COMPILER can be a relative path too: made absolute
  // (not tested: it depends on the environment)
}

// the configure functions of the tcc tests
struct configure_log {
  int calls;
  bool state_was_null;
  bool has_set_options;
};

// sets options on the new tcc state directly: a define through the function
// for it, another one as a command line option
static int configure_defines(void* state, const struct c_aot_tcc_api* api, void* user_data) {
  struct configure_log* log = user_data;
  ++log->calls;
  log->state_was_null |= state == NULL;
  log->has_set_options = api->tcc_set_options != NULL;
  api->tcc_define_symbol(state, "FROM_DEFINE", "4");
  if (api->tcc_set_options) {
    api->tcc_set_options(state, "-DFROM_OPTIONS=5");
  }
  return 0;
}

static int configure_fails(void* state, const struct c_aot_tcc_api* api, void* user_data) {
  (void)state;
  (void)api;
  (void)user_data;
  return 7;
}

// a function of this program, for the compiled code to call
static int host_double(int x) { return 2 * x; }

// what the configure function below reads on every compile
struct host_setup {
  int value;
};

// gives the compiled code a function of this program (tcc_add_symbol), and a
// define taken from user_data, which the caller may change between compiles
static int configure_host(void* state, const struct c_aot_tcc_api* api, void* user_data) {
  const struct host_setup* setup = user_data;
  if (!api->tcc_add_symbol) {
    return 1; // an old libtcc without it: stop
  }
  int (*function)(int) = host_double;
  const void* address;
  memcpy(&address, &function, sizeof(address)); // function pointer -> data pointer
  api->tcc_add_symbol(state, "host_double", address);
  char value[16];
  snprintf(value, sizeof(value), "%d", setup->value);
  api->tcc_define_symbol(state, "VALUE", value);
  return 0;
}

// the directory holding a built libtcc (+ libtcc1.a and include/): tcc tests
// run only if C_AOT_TEST_TCC_DIR is set
static void test_tcc(void) {
  const char* dir = getenv("C_AOT_TEST_TCC_DIR");
  if (!dir || !dir[0]) {
    puts("skipping tcc tests (C_AOT_TEST_TCC_DIR is not set)");
    return;
  }
#if defined(_WIN32)
  const char* name = "libtcc.dll";
#elif defined(__APPLE__)
  const char* name = "libtcc.dylib";
#else
  const char* name = "libtcc.so";
#endif
  char library[1024];
  snprintf(library, sizeof(library), "%s/%s", dir, name);

  struct c_aot_candidate list[] = {c_aot_candidate_tcc_library(library, NULL, NULL)};
  struct c_aot_resolve_result resolved = c_aot_compiler_resolve(list, 1);
  if (resolved.type == C_AOT_RESOLVE_ERR) {
    fputs(resolved.value.error_msg ? resolved.value.error_msg : "?", stderr);
  }
  assert(resolved.type == C_AOT_RESOLVE_OK);
  const struct c_aot_compiler* tcc = &resolved.value.compiler;
  assert(tcc->type == C_AOT_COMPILER_TCC);

  // compiles in memory, finds symbols; two at once don't alias
  const char* src_a = "#include <stddef.h>\nint f(void){return 7;}";
  struct c_aot_compile_result a = c_aot_compile(tcc, src_a, strlen(src_a));
  struct c_aot_compile_result b = c_aot_compile(tcc, "int f(void){return 2;}", strlen("int f(void){return 2;}"));
  assert(a.type == C_AOT_COMPILE_OK && b.type == C_AOT_COMPILE_OK);
  assert(call_f(&a) == 7);
  assert(call_f(&b) == 2);
  assert(c_aot_compile_symbol(&a, "no_such_symbol") == NULL);
  c_aot_compile_result_destroy(&a);
  c_aot_compile_result_destroy(&b);

  // a compile error carries tcc's diagnostics
  struct c_aot_compile_result bad = c_aot_compile(tcc, "int f(void){ syntax error }", strlen("int f(void){ syntax error }"));
  assert(bad.type == C_AOT_COMPILE_ERR && bad.value.error_msg && strstr(bad.value.error_msg, "error"));
  c_aot_compile_result_destroy(&bad);

  // a configure function sets options on every new tcc state, directly. it
  // runs for the test program when resolving, then for each compile
  struct configure_log log = {0, false, false};
  struct c_aot_candidate with_configure[] = {c_aot_candidate_tcc_library(library, configure_defines, &log)};
  struct c_aot_resolve_result configured = c_aot_compiler_resolve(with_configure, 1);
  assert(configured.type == C_AOT_RESOLVE_OK);
  assert(log.calls == 1 && !log.state_was_null); // the test program
  const char* sum = EXPORT "int f(void){return FROM_DEFINE * 10 + FROM_OPTIONS;}";
  struct c_aot_compile_result sum_result = c_aot_compile(&configured.value.compiler, sum, strlen(sum));
  assert(sum_result.type == C_AOT_COMPILE_OK);
  assert(log.calls == 2 && log.has_set_options);
  assert(call_f(&sum_result) == 45);
  c_aot_compile_result_destroy(&sum_result);
  c_aot_resolve_result_destroy(&configured);

  // a configure function that returns nonzero stops before the source is compiled: the
  // test program then fails, and so the candidate
  struct c_aot_candidate failing[] = {c_aot_candidate_tcc_library(library, configure_fails, NULL)};
  struct c_aot_resolve_result refused = c_aot_compiler_resolve(failing, 1);
  assert(refused.type == C_AOT_RESOLVE_ERR);
  assert(strstr(refused.value.error_msg, "configure function stopped the compile (returned 7)"));
  c_aot_resolve_result_destroy(&refused);

  // a preset has no configure function; set it on the tcc entry
  struct c_aot_candidate preset[C_AOT_PRESET_CANDIDATES_MAX];
  size_t preset_count = c_aot_memory_first_candidates(preset, library);
  int tcc_entries = 0;
  for (size_t i = 0; i < preset_count; ++i) {
    if (preset[i].type == C_AOT_CANDIDATE_TCC_LIBRARY) {
      assert(preset[i].value.tcc_library.configure == NULL);
      preset[i].value.tcc_library.configure = configure_defines;
      preset[i].value.tcc_library.user_data = &log;
      ++tcc_entries;
    }
  }
  assert(tcc_entries == 1);

  // something that loads but isn't libtcc (libc / the c runtime)
  struct c_aot_candidate wrong[] = {c_aot_candidate_tcc_library(
#if defined(_WIN32)
      "kernel32.dll"
#elif defined(__APPLE__)
      "libSystem.dylib"
#else
      "libm.so.6"
#endif
      , NULL, NULL)};
  struct c_aot_resolve_result not_tcc = c_aot_compiler_resolve(wrong, 1);
  assert(not_tcc.type == C_AOT_RESOLVE_ERR && strstr(not_tcc.value.error_msg, "not a usable libtcc"));
  c_aot_resolve_result_destroy(&not_tcc);

  // compiled code calls a function of this program, and the configure function
  // reads user_data on every compile, so a change between compiles is seen
  struct host_setup setup = {5};
  struct c_aot_candidate with_host[] = {c_aot_candidate_tcc_library(library, configure_host, &setup)};
  struct c_aot_resolve_result hosted = c_aot_compiler_resolve(with_host, 1);
  assert(hosted.type == C_AOT_RESOLVE_OK);
  const char* calls_host = EXPORT "int host_double(int);\n" EXPORT "int f(void){return host_double(VALUE);}";
  struct c_aot_compile_result first = c_aot_compile(&hosted.value.compiler, calls_host, strlen(calls_host));
  assert(first.type == C_AOT_COMPILE_OK && call_f(&first) == 10);
  setup.value = 7;
  struct c_aot_compile_result second = c_aot_compile(&hosted.value.compiler, calls_host, strlen(calls_host));
  assert(second.type == C_AOT_COMPILE_OK && call_f(&second) == 14);
  assert(call_f(&first) == 10); // the first is its own code
  c_aot_compile_result_destroy(&first);
  c_aot_compile_result_destroy(&second);
  c_aot_resolve_result_destroy(&hosted);

  c_aot_resolve_result_destroy(&resolved);
}

#ifdef __linux__
// tcc as a compiler program (C_AOT_TEST_TCC_PROGRAM: an installed tcc), on a
// glibc older than 2.41, where it works. newer glibc refuse to dlopen what tcc
// makes (it writes no PT_GNU_STACK header), so there the test is skipped
static void test_tcc_as_a_program(void) {
  const char* program = getenv("C_AOT_TEST_TCC_PROGRAM");
  if (!program || !program[0]) {
    puts("skipping the tcc as a program test (C_AOT_TEST_TCC_PROGRAM is not set)");
    return;
  }
#ifdef __GLIBC__
  int major = 0, minor = 0;
  assert(sscanf(gnu_get_libc_version(), "%d.%d", &major, &minor) == 2);
  if (major > 2 || (major == 2 && minor >= 41)) {
    printf("skipping the tcc as a program test (glibc %d.%d refuses what tcc makes; it needs glibc < 2.41)\n", major, minor);
    return;
  }
  struct c_aot_candidate list[] = {c_aot_candidate_executable(program, NULL)};
  struct c_aot_resolve_result r = c_aot_compiler_resolve(list, 1);
  if (r.type == C_AOT_RESOLVE_ERR) {
    fputs(r.value.error_msg ? r.value.error_msg : "?", stderr);
  }
  assert(r.type == C_AOT_RESOLVE_OK);
  struct c_aot_compile_result c = c_aot_compile(&r.value.compiler, "int f(void){return 3;}", strlen("int f(void){return 3;}"));
  assert(c.type == C_AOT_COMPILE_OK && call_f(&c) == 3);
  c_aot_compile_result_destroy(&c);
  c_aot_resolve_result_destroy(&r);
  printf("tcc as a program works with glibc %d.%d\n", major, minor);
#else
  puts("skipping the tcc as a program test (not glibc)");
  (void)program;
#endif
}
#endif

static void test_dying_compiler_does_not_hang(void) {
  // big input + compiler that dies immediately must not hang
  size_t n = 4 << 20;
  char* big = malloc(n);
  memset(big, 'x', n);
#ifdef _WIN32
  // a bad flag makes the compiler exit at once, without reading stdin
  const char* const bad_args[] = {"--no-such-flag-xyz", NULL};
  struct c_aot_compile_result dead = c_aot_compile_exec(big, n, g_compiler->value.executable.path, bad_args);
#else
  // "false" via PATH: it's /bin/false on linux, /usr/bin/false on macos
  struct c_aot_compile_result dead = c_aot_compile_exec(big, n, "false", NULL);
#endif
  assert(dead.type == C_AOT_COMPILE_ERR);
  assert(dead.value.error_msg && strstr(dead.value.error_msg, "exited with code")); // it really ran
  c_aot_compile_result_destroy(&dead);
  free(big);
}

static void test_source_need_not_be_nul_terminated(void) {
  // only the first source_size bytes count: here the rest would be a syntax error
  const char* both = EXPORT "int f(void){return 5;}" "@@ not c @@";
  size_t size = strlen(EXPORT "int f(void){return 5;}");
  struct c_aot_compile_result r = c_aot_compile(g_compiler, both, size);
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 5);
  c_aot_compile_result_destroy(&r);
}

static void test_extra_args(void) {
  // spaces and quotes in an argument must survive the trip to the compiler
  const char* const args[] = {"-DVALUE=7", "-DMSG=\"a b \\\"c\\\" d\"", NULL};
  struct c_aot_candidate list[] = {c_aot_candidate_executable(g_compiler->value.executable.path, args)};
  struct c_aot_resolve_result resolved = c_aot_compiler_resolve(list, 1);
  assert(resolved.type == C_AOT_RESOLVE_OK);
  const char* src = EXPORT "int f(void){return VALUE;}\n" EXPORT "const char* g(void){return MSG;}";
  struct c_aot_compile_result r = c_aot_compile(&resolved.value.compiler, src, strlen(src));
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 7);
  const char* (*g)(void);
  *(void**)&g = c_aot_compile_symbol(&r, "g");
  assert(g && strcmp(g(), "a b \"c\" d") == 0);
  assert(c_aot_compile_symbol(&r, "no_such_symbol") == NULL);
  c_aot_compile_result_destroy(&r);
  c_aot_resolve_result_destroy(&resolved);
}

static void test_large_and_empty_source(void) {
  // large source (more than a pipe buffer holds)
  size_t pad = 4 << 20;
  const char* body = EXPORT "int f(void){return 9;}\n";
  size_t body_len = strlen(body);
  char* src = malloc(body_len + pad + 1);
  memcpy(src, body, body_len);
  memset(src + body_len, ' ', pad);
  struct c_aot_compile_result r = c_aot_compile(g_compiler, src, body_len + pad);
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 9);
  c_aot_compile_result_destroy(&r);
  free(src);

  // empty source is a valid (empty) library
  struct c_aot_compile_result e = compile("");
  assert(e.type == C_AOT_COMPILE_OK);
  c_aot_compile_result_destroy(&e);
}

#ifndef _WIN32
// what TMPDIR the compiler is started with. a compiler that records it and
// then runs the real one
static void test_compiler_gets_the_right_tmpdir(void) {
  char dir[] = "/tmp/c_aot_test_tmpdir_XXXXXX";
  assert(mkdtemp(dir));
  char script[256], record[256];
  snprintf(script, sizeof(script), "%s/cc.sh", dir);
  snprintf(record, sizeof(record), "%s/record", dir);
  FILE* f = fopen(script, "w");
  assert(f);
  fprintf(f, "#!/bin/sh\nprintf '%%s' \"$TMPDIR\" > %s\nexec cc \"$@\"\n", record);
  fclose(f);
  assert(chmod(script, 0755) == 0);

  char* saved = getenv("TMPDIR") ? strdup(getenv("TMPDIR")) : NULL;
  struct c_aot_candidate list[] = {c_aot_candidate_executable(script, NULL)};
  const char* src = EXPORT "int f(void){return 1;}";
  char seen[512];

  for (int caller_sets_it = 0; caller_sets_it <= 1; ++caller_sets_it) {
    if (caller_sets_it) {
      assert(setenv("TMPDIR", dir, 1) == 0);
    } else {
      unsetenv("TMPDIR");
    }
    struct c_aot_resolve_result resolved = c_aot_compiler_resolve(list, 1);
    assert(resolved.type == C_AOT_RESOLVE_OK);
    struct c_aot_compile_result r = c_aot_compile(&resolved.value.compiler, src, strlen(src));
    assert(r.type == C_AOT_COMPILE_OK);
    c_aot_compile_result_destroy(&r);
    c_aot_resolve_result_destroy(&resolved);

    FILE* in = fopen(record, "r");
    assert(in);
    size_t n = fread(seen, 1, sizeof(seen) - 1, in);
    fclose(in);
    seen[n] = '\0';

#ifdef C_AOT_MEMORY_FILES
    // a memory file system, if there is one, whatever the caller set
    struct stat st;
    bool shm = stat("/dev/shm", &st) == 0 && S_ISDIR(st.st_mode) && access("/dev/shm", W_OK | X_OK) == 0;
    assert(strcmp(seen, shm ? "/dev/shm" : (caller_sets_it ? dir : "")) == 0);
#else
    // the private directory, under the caller's TMPDIR (or /tmp)
    const char* base = caller_sets_it ? dir : "/tmp";
    char expected[512];
    snprintf(expected, sizeof(expected), "%s/c_aot_compile.", base);
    assert(strncmp(seen, expected, strlen(expected)) == 0);
#endif
  }

  if (saved) {
    setenv("TMPDIR", saved, 1);
    free(saved);
  } else {
    unsetenv("TMPDIR");
  }
  unlink(script);
  unlink(record);
  rmdir(dir);
}
#endif

static void test_temp_dir_cleanup(void) {
  // use a private base directory, so the entries can be counted
#ifdef _WIN32
  char base[MAX_PATH];
  DWORD n = GetTempPathA(sizeof(base), base);
  assert(n > 0 && n < sizeof(base));
  char dir[MAX_PATH + 64];
  snprintf(dir, sizeof(dir), "%sc_aot_test_%lu", base, (unsigned long)GetCurrentProcessId());
  assert(CreateDirectoryA(dir, NULL));
  assert(SetEnvironmentVariableA("TMP", dir));
#else
  char dir[] = "/tmp/c_aot_test_XXXXXX";
  assert(mkdtemp(dir));
  assert(setenv("TMPDIR", dir, 1) == 0);
#endif

  // a failed compile leaves nothing behind
  struct c_aot_compile_result bad = compile("int f(void){ syntax error }");
  assert(bad.type == C_AOT_COMPILE_ERR);
  c_aot_compile_result_destroy(&bad);
  assert(count_entries(dir) == 0);

  // a successful one leaves nothing once destroyed (on posix, not even while loaded)
  struct c_aot_compile_result ok = compile(EXPORT "int f(void){return 1;}");
  assert(ok.type == C_AOT_COMPILE_OK);
#ifndef _WIN32
  assert(count_entries(dir) == 0);
#endif
  c_aot_compile_result_destroy(&ok);
  assert(count_entries(dir) == 0);

#ifdef _WIN32
  RemoveDirectoryA(dir);
#else
  rmdir(dir);
#endif
}

int main(void) {
  // C_AOT_TEST_COMPILER first (skipped when unset), then the preset
  struct c_aot_candidate preset[C_AOT_PRESET_CANDIDATES_MAX];
  size_t count = c_aot_memory_first_candidates(preset, NULL);
  struct c_aot_candidate list[C_AOT_PRESET_CANDIDATES_MAX + 1];
  list[0] = c_aot_candidate_env("C_AOT_TEST_COMPILER", NULL);
  for (size_t i = 0; i < count; ++i) list[1 + i] = preset[i];
  g_resolved = c_aot_compiler_resolve(list, 1 + count);
  if (g_resolved.type == C_AOT_RESOLVE_ERR) {
    fputs(g_resolved.value.error_msg ? g_resolved.value.error_msg : "?", stderr);
  }
  assert(g_resolved.type == C_AOT_RESOLVE_OK);
  g_compiler = &g_resolved.value.compiler;
  assert(g_compiler->type == C_AOT_COMPILER_EXECUTABLE);
  printf("compiler: %s\n", g_compiler->value.executable.path);

  test_no_alias();
  test_compile_error();
#ifdef C_AOT_MEMORY_FILES
  test_reused_fd_number_does_not_alias();
#endif
  test_resolution_diagnostics();
  test_memory_first_candidates_order();
  test_fast_candidates();
#ifndef _WIN32
  test_candidate_args();
#endif
  test_resolution_falls_through();
  test_tcc();
#ifdef __linux__
  test_tcc_as_a_program();
#endif
  test_dying_compiler_does_not_hang();
  test_source_need_not_be_nul_terminated();
  test_extra_args();
  test_large_and_empty_source();
#ifndef _WIN32
  test_compiler_gets_the_right_tmpdir();
#endif
  test_temp_dir_cleanup(); // last: it changes the temp directory
  c_aot_resolve_result_destroy(&g_resolved);
  puts("ok");
  return 0;
}

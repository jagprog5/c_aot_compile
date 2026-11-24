// build (linux, macos): cc tests/test.c -I. -ldl -o /tmp/c_aot_test && /tmp/c_aot_test
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

// windows toolchains other than mingw gcc only export what is marked
#ifdef _WIN32
#define EXPORT "__declspec(dllexport) "
#else
#define EXPORT ""
#endif

// the compiler under test: C_AOT_TEST_COMPILER, else the library's default
static const char* test_compiler(void) {
  const char* compiler = getenv("C_AOT_TEST_COMPILER");
  return compiler && compiler[0] ? compiler : NULL;
}

// compiles with the compiler under test, unless one is given
static struct c_aot_compile_result compile(const char* src, const char* compiler) {
  return c_aot_compile(src, strlen(src), compiler ? compiler : test_compiler(), NULL);
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
  struct c_aot_compile_result a = compile(EXPORT "int f(void){return 1;}", NULL);
  struct c_aot_compile_result b = compile(EXPORT "int f(void){return 2;}", NULL);
  assert(a.type == C_AOT_COMPILE_OK && b.type == C_AOT_COMPILE_OK);
  assert(call_f(&a) == 1);
  assert(call_f(&b) == 2);
  c_aot_compile_result_destroy(&a);
  c_aot_compile_result_destroy(&b);
}

static void test_compile_error(void) {
  // compile error is reported, with the compiler's stderr
  struct c_aot_compile_result bad = compile("int f(void){ syntax error }", NULL);
  assert(bad.type == C_AOT_COMPILE_ERR);
  assert(bad.value.error_msg && strstr(bad.value.error_msg, "error"));
  c_aot_compile_result_destroy(&bad);
}

static void test_missing_compiler(void) {
  struct c_aot_compile_result missing = compile("", "/nonexistent/cc");
  assert(missing.type == C_AOT_COMPILE_ERR);
  assert(missing.value.error_msg && strstr(missing.value.error_msg, "starting compiler"));
  c_aot_compile_result_destroy(&missing);
}

static void test_dying_compiler_does_not_hang(void) {
  // big input + compiler that dies immediately must not hang
  size_t n = 4 << 20;
  char* big = malloc(n);
  memset(big, 'x', n);
#ifdef _WIN32
  // a bad flag makes the compiler exit at once, without reading stdin
  const char* const bad_args[] = {"--no-such-flag-xyz", NULL};
  struct c_aot_compile_result dead = c_aot_compile(big, n, test_compiler(), bad_args);
#else
  // "false" via PATH: it's /bin/false on linux, /usr/bin/false on macos
  struct c_aot_compile_result dead = c_aot_compile(big, n, "false", NULL);
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
  struct c_aot_compile_result r = c_aot_compile(both, size, test_compiler(), NULL);
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 5);
  c_aot_compile_result_destroy(&r);
}

static void test_extra_args(void) {
  // spaces and quotes in an argument must survive the trip to the compiler
  const char* const args[] = {"-DVALUE=7", "-DMSG=\"a b \\\"c\\\" d\"", NULL};
  const char* src = EXPORT "int f(void){return VALUE;}\n" EXPORT "const char* g(void){return MSG;}";
  struct c_aot_compile_result r = c_aot_compile(src, strlen(src), test_compiler(), args);
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 7);
  const char* (*g)(void);
  *(void**)&g = c_aot_compile_symbol(&r, "g");
  assert(g && strcmp(g(), "a b \"c\" d") == 0);
  assert(c_aot_compile_symbol(&r, "no_such_symbol") == NULL);
  c_aot_compile_result_destroy(&r);
}

static void test_large_and_empty_source(void) {
  // large source (more than a pipe buffer holds)
  size_t pad = 4 << 20;
  const char* body = EXPORT "int f(void){return 9;}\n";
  size_t body_len = strlen(body);
  char* src = malloc(body_len + pad + 1);
  memcpy(src, body, body_len);
  memset(src + body_len, ' ', pad);
  struct c_aot_compile_result r = c_aot_compile(src, body_len + pad, test_compiler(), NULL);
  assert(r.type == C_AOT_COMPILE_OK);
  assert(call_f(&r) == 9);
  c_aot_compile_result_destroy(&r);
  free(src);

  // empty source is a valid (empty) library
  struct c_aot_compile_result e = compile("", NULL);
  assert(e.type == C_AOT_COMPILE_OK);
  c_aot_compile_result_destroy(&e);
}

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
  struct c_aot_compile_result bad = compile("int f(void){ syntax error }", NULL);
  assert(bad.type == C_AOT_COMPILE_ERR);
  c_aot_compile_result_destroy(&bad);
  assert(count_entries(dir) == 0);

  // a successful one leaves nothing once destroyed (on posix, not even while loaded)
  struct c_aot_compile_result ok = compile(EXPORT "int f(void){return 1;}", NULL);
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
  test_no_alias();
  test_compile_error();
  test_missing_compiler();
  test_dying_compiler_does_not_hang();
  test_source_need_not_be_nul_terminated();
  test_extra_args();
  test_large_and_empty_source();
  test_temp_dir_cleanup(); // last: it changes the temp directory
  puts("ok");
  return 0;
}

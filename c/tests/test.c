// build: cc tests/test.c -I. -ldl -o /tmp/c_aot_test && /tmp/c_aot_test
// the header goes first: it defines _GNU_SOURCE, which only works before any system header
#include "../c_aot_compile.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct c_aot_compile_result compile(const char* src, const char* compiler) {
  return c_aot_compile(src, src + strlen(src), compiler, NULL);
}

static int call_f(struct c_aot_compile_result* r) {
  int (*f)(void);
  *(void**)&f = dlsym(r->value.dl_handle, "f");
  assert(f);
  return f();
}

int main(void) {
  // two libraries loaded at once must not alias each other
  struct c_aot_compile_result a = compile("int f(void){return 1;}", NULL);
  struct c_aot_compile_result b = compile("int f(void){return 2;}", NULL);
  assert(a.type == C_AOT_COMPILE_OK && b.type == C_AOT_COMPILE_OK);
  assert(call_f(&a) == 1);
  assert(call_f(&b) == 2);
  c_aot_compile_result_destroy(&a);
  c_aot_compile_result_destroy(&b);

  // compile error is reported, with the compiler's stderr
  struct c_aot_compile_result bad = compile("int f(void){ syntax error }", NULL);
  assert(bad.type == C_AOT_COMPILE_ERR);
  assert(bad.value.error_msg && strstr(bad.value.error_msg, "error"));
  c_aot_compile_result_destroy(&bad);

  // missing compiler
  struct c_aot_compile_result missing = compile("", "/nonexistent/cc");
  assert(missing.type == C_AOT_COMPILE_ERR);
  c_aot_compile_result_destroy(&missing);

  // big input + compiler that dies immediately must not hang
  size_t n = 4 << 20;
  char* big = malloc(n);
  memset(big, 'x', n);
  // "false" via PATH: it's /bin/false on linux, /usr/bin/false on macos
  struct c_aot_compile_result dead = c_aot_compile(big, big + n, "false", NULL);
  assert(dead.type == C_AOT_COMPILE_ERR);
  assert(dead.value.error_msg && strstr(dead.value.error_msg, "exited with code")); // it really ran
  c_aot_compile_result_destroy(&dead);
  free(big);

  // reversed range
  struct c_aot_compile_result rev = c_aot_compile("b", "a", NULL, NULL);
  assert(rev.type == C_AOT_COMPILE_ERR);
  c_aot_compile_result_destroy(&rev);

  puts("ok");
  return 0;
}

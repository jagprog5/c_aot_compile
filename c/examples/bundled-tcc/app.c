// A tiny app that compiles a C expression at run time and calls it:
//
//   ./app "x * x + 1" 7      # prints 50
//
// It gives the library the tcc shipped next to it (dist/tcc/), and lets the
// library's memory first preset decide: on Linux the system compilers first (their
// source and library are memory files, so nothing touches disk), then the
// bundled tcc; on macOS and Windows the bundled tcc first (nothing touches
// disk), then the system compilers.
//   --system-only    don't offer the bundled tcc
//   --bundled-only   use only the bundled tcc
#include "../../c_aot_compile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// the directory this executable is in, so the bundled files can be found no
// matter where the app is run from
static int exe_dir(const char* argv0, char* out, size_t size) {
  char path[4096];
#if defined(__linux__)
  ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 1);
  if (n <= 0) return 0;
  path[n] = '\0';
#elif defined(__APPLE__)
  uint32_t len = sizeof(path);
  if (_NSGetExecutablePath(path, &len) != 0) return 0;
#else
  snprintf(path, sizeof(path), "%s", argv0); // started with a path, hopefully
#endif
  (void)argv0;
  char* slash = strrchr(path, '/');
  if (!slash) return 0;
  *slash = '\0';
  return snprintf(out, size, "%s", path) < (int)size;
}

int main(int argc, char** argv) {
  bool system_only = argc > 1 && strcmp(argv[1], "--system-only") == 0;
  bool bundled_only = argc > 1 && strcmp(argv[1], "--bundled-only") == 0;
  if (system_only || bundled_only) {
    --argc;
    ++argv;
  }
  if (argc != 3) {
    fprintf(stderr, "usage: %s [--system-only | --bundled-only] \"<expression of x>\" <x>\n", argv[0]);
    return 2;
  }

  // the libtcc shipped next to this program. its support files (libtcc1.a,
  // include/) are next to it too, and are found there
  char tcc_library[4200];
  const char* tcc = NULL;
  char dir[4096];
  if (!system_only && exe_dir(argv[0], dir, sizeof(dir))) {
#ifdef __APPLE__
    const char* name = "libtcc.dylib";
#else
    const char* name = "libtcc.so";
#endif
    snprintf(tcc_library, sizeof(tcc_library), "%s/tcc/%s", dir, name);
    tcc = tcc_library;
  }

  struct c_aot_candidate candidates[C_AOT_PRESET_CANDIDATES_MAX];
  size_t count;
  if (bundled_only) {
    if (!tcc) {
      fputs("can't find the bundled tcc: this program's own path is unknown\n", stderr);
      return 1;
    }
    candidates[0] = c_aot_candidate_tcc_library(tcc, NULL, NULL);
    count = 1;
  } else {
    // the library's own order: $CC, system compilers and the libtcc, whichever
    // keeps nothing on disk first on this system
    count = c_aot_memory_first_candidates(candidates, tcc);
  }

  struct c_aot_resolve_result resolved = c_aot_compiler_resolve(candidates, count);
  if (resolved.type == C_AOT_RESOLVE_ERR) {
    fputs(resolved.value.error_msg, stderr); // what was tried, and why each failed
    c_aot_resolve_result_destroy(&resolved);
    return 1;
  }
  const struct c_aot_compiler* compiler = &resolved.value.compiler;
  if (compiler->type == C_AOT_COMPILER_TCC) {
    printf("compiling with the bundled tcc, in memory: %s\n", candidates[compiler->candidate].value.tcc_library.library_path_or_name);
  } else {
    printf("compiling with a system compiler: %s\n", compiler->value.executable.path);
  }

  char source[4096];
  snprintf(source, sizeof(source), "int f(int x) { return %s; }\n", argv[1]);
  struct c_aot_compile_result result = c_aot_compile(compiler, source, strlen(source));
  if (result.type == C_AOT_COMPILE_ERR) {
    fputs(result.value.error_msg, stderr);
    c_aot_compile_result_destroy(&result);
    c_aot_resolve_result_destroy(&resolved);
    return 1;
  }
  int (*f)(int);
  *(void**)&f = c_aot_compile_symbol(&result, "f");
  printf("f(%s) = %d\n", argv[2], f(atoi(argv[2])));

  c_aot_compile_result_destroy(&result);
  c_aot_resolve_result_destroy(&resolved); // after every result made with it
  return 0;
}

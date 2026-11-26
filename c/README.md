# c_aot_compile (C)

A single header, [`c_aot_compile.h`](c_aot_compile.h), for Linux, macOS and Windows. What it's for, the presets and
the requirements are in the [top-level README](../README.md).

- Copy the header into your project and include it **before any system header**. It defines `_GNU_SOURCE`, which
  only works that way. Otherwise, define `_GNU_SOURCE` yourself.
- Linking: add `-ldl -lpthread` on Linux with glibc older than 2.34. They're harmless on newer glibc, and macOS and
  Windows need nothing extra.

## Example

From [`examples/add.c`](examples/add.c), with the cleanup in full:

```c
#include "c_aot_compile.h"

int main(void) {
    // 1. find a compiler, once
    struct c_aot_resolve_result resolved = c_aot_compiler_resolve_fast(NULL); // NULL: no libtcc
    if (resolved.type == C_AOT_RESOLVE_ERR) {
        fputs(resolved.value.error_msg, stderr); // what was tried, and why each failed
        c_aot_resolve_result_destroy(&resolved);
        return 1;
    }

    // 2. compile with it, as often as you like
    const char* src = "int add(int a, int b) { return a + b; }";
    struct c_aot_compile_result code = c_aot_compile(&resolved.value.compiler, src, strlen(src));
    if (code.type == C_AOT_COMPILE_ERR) {
        fputs(code.value.error_msg, stderr); // the compiler's messages
        c_aot_compile_result_destroy(&code);
        c_aot_resolve_result_destroy(&resolved);
        return 1;
    }

    // 3. use it
    int (*add)(int, int);
    *(void**)&add = c_aot_compile_symbol(&code, "add");
    printf("%d\n", add(1, 2)); // 3

    // 4. clean up: the code first, then the compiler
    c_aot_compile_result_destroy(&code);
    c_aot_resolve_result_destroy(&resolved);
    return 0;
}
```

```bash
cd c
cc examples/add.c -ldl -lpthread -o /tmp/add && /tmp/add   # prints "Ok!"
```

## Choosing the compiler

The presets are one call each. Pass the path of an optional libtcc you bundle with your app, or `NULL`:

```c
struct c_aot_resolve_result fast = c_aot_compiler_resolve_fast("/opt/myapp/tcc/libtcc.so");
struct c_aot_resolve_result mem  = c_aot_compiler_resolve_memory_first("/opt/myapp/tcc/libtcc.so");
```

Their orders are in the [top-level README](../README.md#choosing-the-compiler). To write your own list, make one
candidate per entry:

```c
const char* const args[] = {"-O2", "-DMODE=1", NULL}; // after the defaults, so -O2 overrides -O1
struct c_aot_candidate candidates[] = {
    c_aot_candidate_env("CC", args),                                  // $CC
    c_aot_candidate_executable("gcc", args),                          // looked up in PATH
    c_aot_candidate_executable("/usr/local/bin/clang", NULL),         // exactly this file
    c_aot_candidate_tcc_library("/opt/myapp/tcc/libtcc.so", NULL, NULL),
};
struct c_aot_resolve_result resolved = c_aot_compiler_resolve(candidates, 4);
```

`c_aot_fast_candidates(out, tcc)` and `c_aot_memory_first_candidates(out, tcc)` fill an array with a preset, if you
want to change it before resolving. Give the array room for `C_AOT_PRESET_CANDIDATES_MAX` entries.

### Configuring tcc

A tcc library has no args. It takes a function instead, which sets up the tcc state directly with libtcc's own
functions. Every compile gets a fresh tcc state, so the function runs before every single compile, not once:

```c
static int configure(void* tcc, const struct c_aot_tcc_api* api, void* user_data) {
    api->tcc_define_symbol(tcc, "MODE", "1");
    if (api->tcc_add_symbol) api->tcc_add_symbol(tcc, "host_log", (const void*)host_log); // code can call host_log
    return 0; // nonzero stops before compiling, and the compile returns an error
}

struct c_aot_candidate tcc = c_aot_candidate_tcc_library("/opt/myapp/tcc/libtcc.so", configure, &my_settings);
```

The function runs on every compile, including the test compile when resolving. `user_data` must stay valid for as long
as the compiler is in use. Some of libtcc's functions may be missing in an older libtcc, and are then `NULL`.

## Reference

| Function                                                     | What it does                                                                 |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| `c_aot_compiler_resolve_fast(tcc)`                           | resolve with the fast preset. `tcc`: a libtcc path, or `NULL`                |
| `c_aot_compiler_resolve_memory_first(tcc)`                   | resolve with the memory first preset                                         |
| `c_aot_compiler_resolve(candidates, count)`                  | resolve with your own list                                                   |
| `c_aot_resolve_result_destroy(&resolved)`                    | free the compiler, or the error message                                      |
| `c_aot_compile(compiler, source, size)`                      | compile `source[0, size)` (need not end in a NUL) and load it                |
| `c_aot_compile_symbol(&code, name)`                          | look up a symbol, or `NULL`. Valid until the code is destroyed               |
| `c_aot_compile_result_destroy(&code)`                        | unload the code, or free the error message                                   |
| `c_aot_candidate_executable(path_or_name, args)`             | a candidate program, with optional extra args (NULL terminated, or `NULL`)   |
| `c_aot_candidate_env(variable, args)`                        | a candidate named by an environment variable                                 |
| `c_aot_candidate_tcc_library(path_or_name, configure, data)` | a candidate libtcc, with an optional configure function                      |

Results are tagged unions: check `.type`, then read `.value`. A resolved compiler can be used from several threads.
It must outlive every compile result made with it, so destroy the code before the compiler.

## Tests

```bash
cd c
cc tests/test.c -I. -ldl -lpthread -o /tmp/c_aot_test && /tmp/c_aot_test
```

These environment variables select what the tests use:

- `C_AOT_TEST_COMPILER`: a compiler name or path to test with. Otherwise the memory first preset is used.
- `C_AOT_TEST_TCC_DIR`: a directory holding a built libtcc with its `libtcc1.a` and `include/`, such as the demo's
  `dist/tcc/`. This runs the tcc tests.
- `C_AOT_TEST_TCC_PROGRAM`: the path of an installed `tcc` program. This tests tcc as a compiler program on Linux with
  glibc older than 2.41, and is skipped on newer glibc.

On Windows, with mingw gcc, for example from Git Bash:

```bash
cd c
gcc tests/test.c -I. -o c_aot_test.exe && ./c_aot_test.exe
```

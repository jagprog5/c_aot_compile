# c_aot_compile (C)

Single header (`c_aot_compile.h`), no dependencies. Linux and macOS. Link with `-ldl` (required on Linux with
glibc older than 2.34, harmless elsewhere).
Background, design, platform support and security notes are in the [top-level README](../README.md).

## Example

See [examples/add.c](examples/add.c).

```bash
cd c
cc examples/add.c -ldl -o /tmp/add && /tmp/add   # prints "Ok!"
```

```c
#include "c_aot_compile.h"

const char* program = "int add(int a, int b) {return a + b;}";
struct c_aot_compile_result result = c_aot_compile(program, program + strlen(program), NULL, NULL);
if (result.type == C_AOT_COMPILE_ERR) {
    fputs(result.value.error_msg, stderr);
    c_aot_compile_result_destroy(&result);
    return 1;
}
int (*add)(int, int);
*(void**)&add = dlsym(result.value.dl_handle, "add");
// ... use add ...
c_aot_compile_result_destroy(&result); // dlclose + closes the library file
```

## Tests

```bash
cd c
cc tests/test.c -I. -ldl -o /tmp/c_aot_test && /tmp/c_aot_test
```

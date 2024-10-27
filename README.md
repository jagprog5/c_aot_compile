This facilitates dynamic ahead of time compilation by piping c source code to a compiler and linking against the shared object. Works with all major compilers including: [tcc](https://bellard.org/tcc/), gcc, clang.

Alternatives to this lib exist:

 - [libtcc](https://github.com/frida/tinycc/blob/main/libtcc.h)
 - [libgccjit](https://gcc.gnu.org/onlinedocs/jit/)
 - [llvm](https://llvm.org/docs/tutorial/BuildingAJIT1.html)
 - [MIR](https://github.com/vnmakarov/mir)
 - [lightning](https://www.gnu.org/software/lightning/)
 - [lightening](https://wingolog.org/archives/2019/05/24/lightening-run-time-code-generation)
 - ...

But all of them are harder to use! With this lib, just construct C code at runtime then call it!

This is [not a new idea](https://forums.raspberrypi.com/viewtopic.php?t=319919#p1962876).

Here's a test case and example:

```bash
cc main.c -DCOMPILER_USED=gcc -D_GNU_SOURCE
```

```c
// main.c
#include <assert.h>
#include <string.h>

#include "c_aot_compile.h"

#ifndef COMPILER_USED
    // for example, in a makefile add: -DCOMPILER_USED=$(CC)
    #error "COMPILER_USED must be defined to the c compiler"
#endif

// Stringify the COMPILER_USED macro
#define STR(x) #x
#define XSTR(x) STR(x)

int main(void) {
    const char* program = "\
#ifndef MUST_BE_DEFINED\n\
    #error arg pass failure\n\
#endif\n\
#ifndef MUST_BE_DEFINED2\n\
    #error arg pass failure\n\
#endif\n\
int add(int a, int b) {return a + b;}";
    const char* compiler = XSTR(COMPILER_USED);
    const char* const compile_args[] = {"-DMUST_BE_DEFINED", "-DMUST_BE_DEFINED2", NULL};
    void* dl_handle = c_aot_compile(compiler, program, program + strlen(program), compile_args);


    if (dl_handle == NULL) {
        return 1; // error printed by function
    }

    int (*add_symbol)(int, int);
    // https://linux.die.net/man/3/dlopen
    *(void**)(&add_symbol) = dlsym(dl_handle, "add");
    if (add_symbol == NULL) {
        fputs("failed to resolve symbol", stderr);
        return 1;
    }

    assert((*add_symbol)(1, 2) == 3);

    if (dlclose(dl_handle) != 0) {
        char* reason = dlerror();
        if (reason) {
            fprintf(stderr, "dlclose: %s\n", reason);
        } else {
            fputs("dlclose failed for an unknown reason", stderr);
        }
        return 1;
    }
    puts("Ok!");
    return 0;
}
```
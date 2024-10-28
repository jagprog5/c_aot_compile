# Runtime C Compilation

This facilitates compilation at runtime by piping C source code to a compiler and linking against the shared object.

## But wait, this adds a whole compiler as a dependency?

Yes.

And that might be ok! Consider the following:

 - This lib works with all major compilers including: tcc, gcc, clang. Likely others as well.
 - POSIX requires a C compiler. If your target is POSIX, then your dependency will be there!
 - Note [tcc](https://bellard.org/tcc/). It's whole spiel is that it's tiny. If needed, add tcc to the package.

## Background

Alternatives to this lib exist: [libtcc](https://github.com/frida/tinycc/blob/main/libtcc.h), [libgccjit](https://gcc.gnu.org/onlinedocs/jit/), [llvm](https://llvm.org/docs/tutorial/BuildingAJIT1.html), [MIR](https://github.com/vnmakarov/mir), [lightning](https://www.gnu.org/software/lightning/), [lightening](https://wingolog.org/archives/2019/05/24/lightening-run-time-code-generation), ...

But all of them are harder to use! And they're pretty big! With this lib, just construct C code at runtime and use it!

It's [not a new idea](https://forums.raspberrypi.com/viewtopic.php?t=319919#p1962876). In fact, there's a [jit implementation for Ruby (called MJIT)](https://blog.heroku.com/ruby-mjit#mjit) that does something similar.

## Implementation Note

The lib tries its very best to encourage the compiler to never write to disk:
 - Temp files are in memory
 - The output object is stored in memory

## Example

```bash
cc main.c -DRUNTIME_C_COMPILER=cc -D_GNU_SOURCE
```

```c
// main.c
#include <assert.h>
#include <string.h>

#include "c_aot_compile.h"

#ifndef RUNTIME_C_COMPILER
    // for example, in a makefile add: -DRUNTIME_C_COMPILER=$(CC)
    #error "RUNTIME_C_COMPILER must be defined to a c compiler"
#endif

// Stringify the RUNTIME_C_COMPILER macro
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
    const char* compiler = XSTR(RUNTIME_C_COMPILER);
    const char* const compile_args[] = {"-DMUST_BE_DEFINED", "-DMUST_BE_DEFINED2", NULL};

    // ================= IMPORTANT LINE HERE ================= 
    struct c_aot_compile_result result = c_aot_compile(
            compiler,
            program, program + strlen(program),
            compile_args);
    // =================================================

    if (result.type == C_AOT_COMPILE_ERR) {
        fputs(result.value.error_msg, stderr);
        free(result.value.error_msg);
        return 1;
    }

    void* dl_handle = result.value.dl_handle;

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
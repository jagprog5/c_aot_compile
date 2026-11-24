// build: cc examples/add.c -ldl (from the c/ directory)
// the header goes first: it defines _GNU_SOURCE, which only works before any system header
#include "../c_aot_compile.h"

#include <assert.h>
#include <string.h>

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
    const char* const compile_args[] = {"-DMUST_BE_DEFINED", "-DMUST_BE_DEFINED2", NULL};

    // ================= IMPORTANT LINE HERE ================= 
    struct c_aot_compile_result result = c_aot_compile(
            program, program + strlen(program), NULL, compile_args);
    // =================================================

    if (result.type == C_AOT_COMPILE_ERR) {
        fputs(result.value.error_msg, stderr);
        c_aot_compile_result_destroy(&result);
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

    // closes the library (dlclose) and the memory file it was loaded from.
    // the memory file must stay open as long as the library is loaded
    c_aot_compile_result_destroy(&result);
    puts("Ok!");
    return 0;
}

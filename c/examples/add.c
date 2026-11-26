// build: cc examples/add.c -ldl -lpthread (from the c/ directory). windows (mingw): gcc examples/add.c
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

    // ================= IMPORTANT LINES HERE ================
    // find a compiler once, and keep it. a compiler's args belong to its
    // candidate (-O2 overrides the default -O1). tcc takes a configure function
    // instead: see examples/bundled-tcc
    const char* const args[] = {"-O2", "-DMUST_BE_DEFINED", "-DMUST_BE_DEFINED2", NULL};
    struct c_aot_candidate candidates[] = {
        c_aot_candidate_env("CC", args), // $CC
        c_aot_candidate_executable("cc", args),
        c_aot_candidate_executable("gcc", args),
        c_aot_candidate_executable("clang", args),
    };
    struct c_aot_resolve_result resolved = c_aot_compiler_resolve(candidates, 4);
    if (resolved.type == C_AOT_RESOLVE_ERR) {
        fputs(resolved.value.error_msg, stderr); // says what was tried, and why each failed
        c_aot_resolve_result_destroy(&resolved);
        return 1;
    }
    struct c_aot_compile_result result = c_aot_compile(&resolved.value.compiler, program, strlen(program));
    // =================================================

    if (result.type == C_AOT_COMPILE_ERR) {
        fputs(result.value.error_msg, stderr);
        c_aot_compile_result_destroy(&result);
        c_aot_resolve_result_destroy(&resolved);
        return 1;
    }

    int (*add_symbol)(int, int);
    // dlsym / GetProcAddress
    *(void**)(&add_symbol) = c_aot_compile_symbol(&result, "add");
    if (add_symbol == NULL) {
        fputs("failed to resolve symbol", stderr);
        c_aot_compile_result_destroy(&result);
        c_aot_resolve_result_destroy(&resolved);
        return 1;
    }

    assert((*add_symbol)(1, 2) == 3);

    // unloads the library and closes the file it was loaded from.
    // the file must stay open as long as the library is loaded
    c_aot_compile_result_destroy(&result);
    c_aot_resolve_result_destroy(&resolved); // after every result made with it
    puts("Ok!");
    return 0;
}

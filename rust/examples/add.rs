use c_aot_compile::Candidate;

fn main() {
    let source = "\
#ifndef MUST_BE_DEFINED
    #error arg pass failure
#endif
C_AOT_EXPORT int add(int a, int b) { return a + b; }";

    // find a compiler once, and keep it. a compiler's args belong to its
    // candidate (-O2 overrides the default -O1). tcc takes a configure function
    // instead (Candidate::tcc_library_with)
    let args = ["-O2", "-DMUST_BE_DEFINED"];
    let compiler = match c_aot_compile::Compiler::resolve(&[
        Candidate::env_with_args("CC", args), // $CC
        Candidate::executable_with_args("cc", args),
        Candidate::executable_with_args("gcc", args),
        Candidate::executable_with_args("clang", args),
    ]) {
        Ok(compiler) => compiler,
        Err(err) => {
            eprintln!("{err}"); // says what was tried, and why each failed
            std::process::exit(1);
        }
    };
    let lib = match compiler.compile(source) {
        Ok(lib) => lib,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    // SAFETY: `add` is defined above as `int add(int, int)`.
    let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }
        .expect("symbol `add` not found");

    assert_eq!(add(1, 2), 3);
    println!("Ok!");
}

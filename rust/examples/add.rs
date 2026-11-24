fn main() {
    let source = "\
#ifndef MUST_BE_DEFINED
    #error arg pass failure
#endif
int add(int a, int b) { return a + b; }";

    let lib = match c_aot_compile::compile(source, None, &["-DMUST_BE_DEFINED"]) {
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

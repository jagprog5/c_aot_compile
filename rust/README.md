# c_aot_compile (Rust)

Compile C at run time and call it, from Rust. Linux, macOS and Windows. What it's for, the presets and the
requirements are in the [top-level README](../README.md). The API docs are in `src/lib.rs` (`cargo doc --open`).

```toml
[dependencies]
c_aot_compile = { path = "rust" }
```

## Example

```rust
use c_aot_compile::Compiler;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // find a compiler once. the error says what was tried, and why each failed
    let compiler = Compiler::resolve_fast(None)?; // None: no libtcc

    // compile with it, as often as you like
    let lib = compiler.compile("int add(int a, int b) { return a + b; }")?;

    // SAFETY: `add` really is `int add(int, int)`
    let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }.unwrap();
    println!("{}", add(1, 2)); // 3
    Ok(())
}
```

```bash
cd rust
cargo run --example add   # prints "Ok!"
```

- `add` borrows `lib`, so using it after `lib` is dropped won't compile.
- `Library` unloads on drop, and keeps what it needs alive, so it can outlive the `Compiler`.
- `Compiler` is cheap to clone and can be shared between threads.

## Choosing the compiler

The presets are one call each. Pass the path of an optional libtcc you bundle with your app, or `None`:

```rust
use std::path::Path;
let tcc = Some(Path::new("/opt/myapp/tcc/libtcc.so"));
let fast = Compiler::resolve_fast(tcc)?;
let mem = Compiler::resolve_memory_first(tcc)?;
```

Their orders are in the [top-level README](../README.md#choosing-the-compiler). To write your own list:

```rust
use c_aot_compile::{Candidate, Compiler};

let compiler = Compiler::resolve(&[
    Candidate::env_with_args("CC", ["-O2", "-DMODE=1"]),          // $CC; after the defaults, so -O2 overrides -O1
    Candidate::executable_with_args("gcc", ["-O2", "-DMODE=1"]),  // looked up in PATH
    Candidate::executable("/usr/local/bin/clang"),                // exactly this file
    Candidate::tcc_library("/opt/myapp/tcc/libtcc.so"),
])?;
println!("{:?} won, candidate {}", compiler.kind(), compiler.candidate());
```

`fast_candidates(tcc)` and `memory_first_candidates(tcc)` return a preset as a `Vec`, if you want to change it before
resolving.

### Configuring tcc

A tcc library has no args. It takes a closure instead, which sets up the tcc state directly with libtcc's own
functions. Every compile gets a fresh tcc state, so the closure runs before every single compile, not once:

```rust
let tcc = Candidate::tcc_library_with("/opt/myapp/tcc/libtcc.so", |tcc| {
    // SAFETY: the state is live, and the strings end in a NUL
    unsafe { (tcc.api.define_symbol)(tcc.state.as_ptr(), c"MODE".as_ptr(), c"1".as_ptr()) };
    Ok(()) // Err(..) stops before compiling, and the compile returns an error
});
```

The closure runs on every compile, including the test compile when resolving. A panic in it becomes an error. Some of
libtcc's functions may be missing in an older libtcc, and are then `None`.

## Errors

- `ResolveError` means no candidate worked. It lists each candidate and why it failed.
- `Error` means a compile failed. It's one of:
  - `Error::Compiler`: the compiler program failed. It includes its messages.
  - `Error::Tcc`: libtcc reported the failure.
  - `Error::Io` or `Error::Load`: something around the compile failed.

## Tests

```bash
cd rust
cargo test
```

These environment variables select what the tests use:

- `C_AOT_TEST_COMPILER`: a compiler name or path to test with. Otherwise the memory first preset is used.
- `C_AOT_TEST_TCC_DIR`: a directory holding a built libtcc with its `libtcc1.a` and `include/`, such as the C demo's
  `dist/tcc/`. This runs the tcc tests.
- `C_AOT_TEST_TCC_PROGRAM`: the path of an installed `tcc` program. This tests tcc as a compiler program on Linux. On
  glibc 2.41 and later it needs a tcc from `mob@772dc70d` on, such as the one the C demo builds.

The `no_memory_files` feature makes Linux use a temporary directory, as other systems do, to test that route.

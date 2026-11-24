# c_aot_compile (Rust)

Compile C source at runtime with the system C compiler, then load it. Linux only.
See the [top-level README](../README.md) for the design; API docs are in `src/lib.rs` (`cargo doc --open`).

```rust
let lib = c_aot_compile::compile("int add(int a, int b) { return a + b; }", None, &[])?;
// SAFETY: `add` really is `int add(int, int)`
let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }.unwrap();
assert_eq!(add(1, 2), 3); // `add` borrows `lib`: using it after `lib` drops won't compile
```

`Library` unloads on drop, and owns the memory file the code was loaded from.

```bash
cargo run --example add
cargo test
```

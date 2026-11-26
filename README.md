# c_aot_compile

Write C at run time, compile it with a real C compiler, and call it. Cross-platform (Linux, macOS and Windows), as a
single C header and as a Rust crate.

## Background

Programs often have work whose exact shape is only known at runtime. The usual answers are an interpreter, which is
flexible but slow, or a JIT built on a code-generation library, which is fast but a large dependency with its own
intermediate language to learn. Alternatives along those lines include
[libtcc](https://github.com/frida/tinycc/blob/main/libtcc.h), [libgccjit](https://gcc.gnu.org/onlinedocs/jit/),
[LLVM](https://llvm.org/docs/tutorial/BuildingAJIT1.html), [MIR](https://github.com/vnmakarov/mir),
[lightning](https://www.gnu.org/software/lightning/) and
[lightening](https://wingolog.org/archives/2019/05/24/lightening-run-time-code-generation).

This library takes a simpler route: C is the intermediate language, and an ordinary compiler is the backend. You
generate plain C text and get back callable functions with the full optimizer behind them, and nothing new to learn.
The price is compile latency and needing a compiler, which is what the presets and bundled libtcc are for.

It's [not a new idea](https://forums.raspberrypi.com/viewtopic.php?t=319919#p1962876). Ruby's
[MJIT](https://blog.heroku.com/ruby-mjit#mjit) compiled hot methods the same way, by writing and compiling C.

What it promises:

1. **C text in, callable code out**, at the quality of the compiler that built it.
2. **Finds the right compiler for you.** Say what you prefer, the fastest code or no writes to disk, and it works out
   which compiler on this machine best gives you that: it tries the candidates in that order and test-compiles each,
   so the one you get is known to work. Where there is no compiler, it falls back to a bundled libtcc if you ship one,
   or otherwise reports clearly what was tried.
3. **Leaves nothing behind.** It keeps files in memory where the system allows, and removes temporary files otherwise.
4. **One design** for C and Rust, on Linux, macOS and Windows.


## Example

Find a compiler once, then compile as often as you like. The same code works on Linux, macOS and Windows.

```c
#include "c_aot_compile.h"

struct c_aot_resolve_result resolved = c_aot_compiler_resolve_fast(NULL);
if (resolved.type == C_AOT_RESOLVE_ERR) { fputs(resolved.value.error_msg, stderr); return 1; }

const char* src = "int add(int a, int b) { return a + b; }";
struct c_aot_compile_result code = c_aot_compile(&resolved.value.compiler, src, strlen(src));
if (code.type == C_AOT_COMPILE_ERR) { fputs(code.value.error_msg, stderr); return 1; }

int (*add)(int, int);
*(void**)&add = c_aot_compile_symbol(&code, "add");
printf("%d\n", add(1, 2)); // 3

c_aot_compile_result_destroy(&code);
c_aot_resolve_result_destroy(&resolved);
```

```rust
use c_aot_compile::Compiler;

let compiler = Compiler::resolve_fast(None)?;
let lib = compiler.compile("int add(int a, int b) { return a + b; }")?;
let add = unsafe { lib.get::<extern "C" fn(i32, i32) -> i32>(c"add") }.unwrap();
println!("{}", add(1, 2)); // 3
```

The C and Rust READMEs have the full examples: [C](c/README.md), [Rust](rust/README.md).

**AOT or JIT?** Both, in a sense. The code is generated while your program runs, as with a JIT, but by an ordinary
ahead-of-time compiler that compiles a whole unit up front. There is no lazy per-function compilation and no
recompiling of hot code. Expect tens of milliseconds per compile with gcc or clang, and code as fast as any C those
compilers produce.

## Choosing the compiler

A compiler is resolved once, from an ordered list of candidates. The first candidate that really works (it compiles a
small test program) is the one you get. If none works, you get a single error that lists every candidate and why it
failed:

```
no working compiler. tried:
  1. environment variable "CC": not set
  2. executable "cc": not found in PATH
  3. executable "gcc": not found in PATH
  4. executable "clang": not found in PATH
```

The list is yours to configure. Two ready-made ones, the presets, cover the usual choices:

- **Fast** (`c_aot_compiler_resolve_fast`, `Compiler::resolve_fast`): the fastest generated code. It tries the system's
  optimizing compilers first, with optimizing flags, and falls back to tcc last.
- **Memory first** (`c_aot_compiler_resolve_memory_first`, `Compiler::resolve_memory_first`): keep source and compiled
  code off disk where possible. On Linux the system compilers work in memory, so they come first. Elsewhere only libtcc
  does, so it comes first there. This is a priority, not a guarantee: a compiler that writes temporary files is still
  used if it is the only one.

Both take an optional libtcc. If you bundle one as a fallback for systems with no compiler at all (see
[below](#no-compiler-on-the-system-bundle-libtcc)), pass its path, otherwise `NULL` (`None` in Rust). The memory first
preset also tries the system's libtcc (`libtcc.so`, `libtcc.dylib` or `libtcc.dll`, wherever the loader finds it) right
after yours, if one is installed. The exact orders are documented in the header and the crate docs.

### Your own list

A candidate is one of:

- **an executable**: a path, or a name looked up in `PATH`, as a shell does. Optionally with extra compiler args.
- **an environment variable** such as `CC`, which names an executable. Optionally with extra compiler args.
- **a tcc library**: a libtcc shared object. Optionally with a function that configures each tcc instance.

## No compiler on the system? Bundle libtcc

This is optional, for when a machine truly has no C compiler. [tcc](https://bellard.org/tcc/) is a small C compiler
that is also a library, `libtcc`. Ship its shared object with your app and give it as a candidate, and your app can
compile C anywhere.

- It is loaded at run time, never linked, so your program starts and works without it, and a missing one is just a
  candidate that failed.
- It compiles in your process, to memory, with no files and no child process.
- It doesn't optimize, so it fits best as the fallback: the presets put it after the system compilers on Linux, and
  in the fast list.
- You get libtcc by building it from [its source](https://repo.or.cz/tinycc.git). Distro packages usually ship only a
  static library, which can't be loaded at run time. [`c/examples/bundled-tcc`](c/examples/bundled-tcc) builds it and
  bundles it with an example app in one script, and is the thing to copy.
- tcc is licensed under the LGPL 2.1, while this library is MIT/Apache and contains none of tcc's code. Whoever ships a
  libtcc carries the LGPL's duties for it: its license text, where to get its source, and leaving it replaceable. The
  demo's bundle does all three. This isn't legal advice.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. This library doesn't include or link libtcc (LGPL 2.1), see
[No compiler on the system?](#no-compiler-on-the-system-bundle-libtcc).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

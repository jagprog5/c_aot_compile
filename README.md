# Runtime C Compilation

Emit then compile C source at runtime with a compiler. Available as a single C header and as a Rust crate. Both
implement the same design.

Is it JIT or AOT? Both, in a sense: the machine code is generated while your program runs (JIT-like flexibility), but
by an ordinary ahead-of-time compiler that compiles a whole unit up front. There is no lazy per-function compilation
or recompilation of hot code, so expect tens of milliseconds per compile, not microseconds.

|      | Directory        | Use it as                                  |
| ---- | ---------------- | ------------------------------------------ |
| C    | [`c/`](c/)       | copy `c/c_aot_compile.h` into your project |
| Rust | [`rust/`](rust/) | `c_aot_compile = { path = "rust" }`        |

## But wait, this adds a whole compiler as a dependency?

Yes.

And that might be ok! Consider the following:

- This lib works with all major compilers including: tcc, gcc, clang. Likely
  others as well, and gets the same gains for free.
- POSIX requires a C compiler. If your target is POSIX, then your dependency
  will be there!
- Note [tcc](https://bellard.org/tcc/). It's whole spiel is that it's tiny. If
  needed, add tcc to the package.

## Background

Alternatives to this lib exist: [libtcc](https://github.com/frida/tinycc/blob/main/libtcc.h), [libgccjit](https://gcc.gnu.org/onlinedocs/jit/), [llvm](https://llvm.org/docs/tutorial/BuildingAJIT1.html), [MIR](https://github.com/vnmakarov/mir), [lightning](https://www.gnu.org/software/lightning/), [lightening](https://wingolog.org/archives/2019/05/24/lightening-run-time-code-generation), ...

But all of them are harder to use! And they're pretty big! With this lib, just construct C code at runtime and use it!

It's [not a new idea](https://forums.raspberrypi.com/viewtopic.php?t=319919#p1962876). In fact, there's a [jit implementation for Ruby (called MJIT)](https://blog.heroku.com/ruby-mjit#mjit) that does something similar.

## Goals

- **Safe by default:** no hangs, truncated input, or silently loading the wrong code, including when
  called from several threads.
- **Avoid writing to disk where possible:** the source and the compiled library live in memory files and
  `TMPDIR` points at `/dev/shm`. This is best effort, not a guarantee: the compiler is a separate program, and
  anything that ignores `TMPDIR` or writes elsewhere (caches, extra args you pass) can still touch disk. tcc
  writes directly to memory and is the most reliable in this regard (it was built for this!)

## Platform support

Linux only (`memfd_create`, `/dev/fd` needs `/proc`). Tested on glibc and musl (Alpine).

## Security

This is a JIT: it executes arbitrary code. Source and compiler must be trusted.
The header comment and the crate docs list the details (environment passthrough, `PATH` lookup, diagnostics leaking file contents).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

# Bundling libtcc with an app

An app that compiles C at run time even on a machine with **no** C compiler, because it carries
[tcc](https://bellard.org/tcc/)'s library, libtcc, next to it. It is the "no compiler on the system" route from the
[top-level README](../../../README.md#no-compiler-on-the-system-bundle-libtcc), ready to copy.

```bash
./build.sh                   # builds libtcc and the app into dist/
./dist/app "x * x + 1" 7     # f(7) = 50
```

The app wraps your expression in `int f(int x) { return <expression>; }`, compiles it and calls it. It prints which
compiler it used.

## Try it without a compiler

```bash
cp -R dist /tmp/moved
env -i PATH=/nonexistent /tmp/moved/app "x * x + 1" 7                 # works: the bundled libtcc
env -i PATH=/nonexistent /tmp/moved/app --system-only "x * x + 1" 7   # fails, and says what it tried
./dist/app --bundled-only "x * x + 1" 7                               # the bundled libtcc, even with gcc around
```

By default the app uses the library's memory first preset, with the bundled libtcc in it. On Linux, the system
compilers come first and libtcc is the fallback. On macOS and Windows, libtcc comes first. Swap in the fast preset in
`app.c` if you want the fastest generated code instead.

## What you ship

```
dist/
  app           the program. it doesn't link libtcc
  tcc/
    libtcc.so   libtcc.dylib on macOS, libtcc.dll on Windows
    libtcc1.a   tcc's runtime support (on Windows: lib/libtcc1.a)
    include/    tcc's own headers
    COPYING     tcc's license, the LGPL 2.1
    SOURCE.txt  where tcc's source is
```

Copy `dist/` as it is, anywhere. The app finds `tcc/` next to itself. Because libtcc is loaded at run time, `tcc/` is a
plain folder your users can replace, which is part of what the LGPL asks of whoever ships it. The license text and the
source location are included. This isn't legal advice.

## What `build.sh` does

1. Fetches tcc's source at a pinned commit. Set `TCC_COMMIT` to build another version.
2. Builds libtcc as a shared library.
3. Collects it into `dist/tcc/`, with the files tcc needs beside it and its license.
4. Builds the app.

It needs `git`, `make` and a C compiler to build. The finished `dist/` needs none of them.

**Systems:** the build and the app work on Linux and macOS. On Windows (Git Bash with mingw gcc), `build.sh` builds
and bundles libtcc but not the app, whose way of finding its own folder is POSIX-only.

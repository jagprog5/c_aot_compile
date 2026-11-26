#!/bin/sh
# Builds a libtcc shared object from source, and bundles it with the example app.
#
#   ./build.sh            -> dist/ (the app, plus everything it needs, in one folder)
#   ./dist/app "x * x + 1" 7
#
# Needs: git, a C compiler (to build tcc and the app; the finished app doesn't
# need one), and make. On Windows (Git Bash, with mingw gcc) it runs tcc's
# win32/build-tcc.bat and bundles libtcc.dll the same way, without the app.
set -eu

# a tcc commit that this header's libtcc binding was tested with (from
# mob@772dc70d on, tcc as a program also works on glibc 2.41 and later)
TCC_URL=https://repo.or.cz/tinycc.git
# override to test another version, e.g. TCC_COMMIT=release_0_9_27 ./build.sh
TCC_COMMIT=${TCC_COMMIT:-772dc70df00f53461c526dddca42b63d1b7148c7}

here=$(cd "$(dirname "$0")" && pwd)
src="$here/build/tinycc"
dist="$here/dist"

# 1. get tcc's source, at exactly that commit. the server only hands out a
#    commit by hash while it is a branch tip, so fetch the branches and tags
#    whole (no --depth: an older pinned commit is then always in them), and
#    check the commit out from there
if [ ! -d "$src/.git" ]; then
  mkdir -p "$src"
  git -C "$src" init -q
  git -C "$src" remote add origin "$TCC_URL"
fi
git -C "$src" fetch -q --tags origin '+refs/heads/*:refs/remotes/origin/*'
# a hash or a tag, else a branch name (TCC_COMMIT=mob: its tip)
commit=$(git -C "$src" rev-parse -q --verify "$TCC_COMMIT^{commit}" ||
  git -C "$src" rev-parse -q --verify "origin/$TCC_COMMIT^{commit}") || {
  echo "tcc: $TCC_COMMIT is not in $TCC_URL (was the branch rewritten?)" >&2
  exit 1
}
git -C "$src" checkout -q -f --detach "$commit"
git -C "$src" clean -fdxq # no leftovers from an earlier build

case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) windows=yes ;;
  *) windows=no ;;
esac

cd "$src"
rm -rf "$dist"
mkdir -p "$dist/tcc"

if [ "$windows" = no ]; then
  # 2. build libtcc as a shared object (--disable-static), plus libtcc1.a
  ./configure --disable-static > /dev/null
  make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" > /dev/null

  # 3. the folder to ship: the shared object and the files tcc needs next to it
  #    (its runtime archive and its own headers)
  cp libtcc.so "$dist/tcc/" 2>/dev/null || cp libtcc.dylib "$dist/tcc/"
  cp libtcc1.a "$dist/tcc/"
  cp -R include "$dist/tcc/include"
else
  # 2. tcc's own windows build (needs mingw gcc): libtcc.dll, lib/libtcc1.a, include/
  (cd win32 && cmd //c build-tcc.bat)

  # 3. on windows, tcc looks for lib/libtcc1.a and include/ next to the dll
  cp win32/libtcc.dll "$dist/tcc/"
  mkdir "$dist/tcc/lib"
  cp win32/lib/libtcc1.a "$dist/tcc/lib/"
  cp -R win32/include "$dist/tcc/include"
fi

# ... and its license and source
cp COPYING "$dist/tcc/COPYING"
cat > "$dist/tcc/SOURCE.txt" <<TXT
libtcc (TinyCC) is licensed under the GNU LGPL 2.1, see COPYING.
Source: $TCC_URL
Commit: $commit
It is loaded at run time, never linked: replace libtcc.so / libtcc.dylib /
libtcc.dll with your own build of tcc to change it.
TXT

# 4. the app (not on windows: it finds its own folder the posix way). it
#    doesn't link libtcc, or anything but libc, libdl and libpthread
if [ "$windows" = no ]; then
  cc -Wall -Wextra -O2 "$here/app.c" -ldl -lpthread -o "$dist/app"
fi

echo "built $dist:"
ls -R "$dist" | head -30

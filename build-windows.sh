#!/usr/bin/env bash
# Builds WAC.exe from Linux (MinGW-w64 cross-compilation), with no Windows machine.
#
# Produces a self-contained exe (static C++ runtime) that depends only on the
# Windows system DLLs (offreg.dll and the base DLLs; wevtapi is no longer needed).
#
# Prerequisites: packages  g++-mingw-w64-x86-64  binutils-mingw-w64-x86-64  mingw-w64-tools
# Usage: ./build-windows.sh [--clean] [--test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/WAC"
TP="$ROOT/third_party"
BUILD="$ROOT/build-windows"

CXX=x86_64-w64-mingw32-g++
WINDRES=x86_64-w64-mingw32-windres
DLLTOOL=x86_64-w64-mingw32-dlltool
command -v "$CXX" >/dev/null || { echo "MinGW-w64 missing: apt install g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools" >&2; exit 1; }

[[ "${1:-}" == "--clean" ]] && rm -rf "$BUILD"
mkdir -p "$BUILD"

# --- offreg import library (Offline Registry; absent from MinGW) ------------
if [[ ! -f "$TP/offreg/liboffreg.a" ]]; then
  echo "== Generating liboffreg.a =="
  "$DLLTOOL" -d "$TP/offreg/offreg.def" -l "$TP/offreg/liboffreg.a" -D offreg.dll -m i386:x86-64
fi

# --- Common options --------------------------------------------------------
FLAGS=(-std=c++17 -O2
  -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00
  -include "$TP/compat-include/wac_mingw_compat.h"
  -I"$TP/offreg" -I"$TP/compat-include"
  -finput-charset=UTF-8 -fexec-charset=UTF-8
  # -Wall: the project used to build without it, which let through 46 dead
  # declarations and a GetVolumeInformationW whose result was ignored.
  # The three remaining exclusions are idioms the project assumes:
  #   missing-field-initializers: "= { 0 }" on the Win32 structures,
  #   sign-compare              : comparisons with the STL sizes,
  #   cast-function-type        : GetProcAddress, a mandatory cast.
  -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
  -Wno-sign-compare -Wno-cast-function-type
  -Wno-unknown-pragmas -Wno-deprecated -Wno-conversion-null)

# --- Resource (VS .rc in UTF-16 -> UTF-8 for windres) ----------------------
echo "== Resource =="
iconv -f UTF-16LE -t UTF-8 "$SRC/WAC.rc" | tr -d '\r' | sed -E 's#\\+#/#g' > "$BUILD/WAC.utf8.rc"
"$WINDRES" -I"$SRC" -I"$TP/compat-include" -c 65001 "$BUILD/WAC.utf8.rc" -O coff -o "$BUILD/WAC_res.o"

# --- Compilation units -----------------------------------------------------
echo "== Compilation =="
# Compilation units: discovered automatically (main.cpp last, test harnesses
# excluded). No list to keep by hand any more.
mapfile -t TUS < <(cd "$SRC" && ls *.cpp | grep -v -e '^main\.cpp$' -e '_test\.cpp$'; echo main.cpp)
OBJS=()
for tu in "${TUS[@]}"; do
  echo "   - $tu"
  "$CXX" "${FLAGS[@]}" -c "$SRC/$tu" -o "$BUILD/${tu%.cpp}.o"
  OBJS+=("$BUILD/${tu%.cpp}.o")
done

# --- Link --------------------------------------------------------------------
echo "== Link =="
LIBS=(-L"$TP/offreg" -loffreg -lole32 -loleaut32
      -luuid -lshlwapi -ladvapi32 -lshell32 -lversion -lwtsapi32
      -lsecur32 -lpropsys -lntdll)
"$CXX" -static -static-libgcc -static-libstdc++ \
  "${OBJS[@]}" "$BUILD/WAC_res.o" -o "$BUILD/WAC.exe" "${LIBS[@]}"

# --- raw_hive test exe (optional) -------------------------------------------
if [[ "${1:-}" == "--test" || "${2:-}" == "--test" ]]; then
  echo "== Build raw_hive_test.exe =="
  # raw_hive's dependencies: the fingerprints (sha, quickdigest5) and the NTFS
  # decompression (lznt1, xpress). This list must be kept up to date — it has
  # drifted once already, and a test exe that no longer links is only noticed
  # at the moment it is needed.
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
    "$SRC/raw_hive.cpp" "$SRC/hive_recover.cpp" "$SRC/quickdigest5.cpp" \
    "$SRC/sha.cpp" "$SRC/lznt1.cpp" "$SRC/xpress.cpp" \
    "$SRC/raw_hive_test.cpp" -o "$BUILD/raw_hive_test.exe"
  echo "   -> $BUILD/raw_hive_test.exe"

  echo "== Build lnk_test.exe =="
  # The shortcut parser pulls in most of WAC (shell items, GUID names, paths,
  # log): the harness links every WAC object but main.o rather than a list
  # that would drift. Run: wine lnk_test.exe <file.lnk> [file.lnk ...]
  TEST_OBJS=()
  for o in "${OBJS[@]}"; do [[ "$o" == "$BUILD/main.o" ]] || TEST_OBJS+=("$o"); done
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/lnk_test.cpp" "${TEST_OBJS[@]}" -o "$BUILD/lnk_test.exe" "${LIBS[@]}"
  echo "   -> $BUILD/lnk_test.exe"
  # Wine lacks PSGetNameFromPropertyKey (see the stub's header): needed to run
  # lnk_test on real shortcuts, with WINEDLLOVERRIDES="propsys=n".
  x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra -Wl,--kill-at \
    "$TP/compat-include/propsys_wine_stub.c" -o "$BUILD/propsys.dll"
  echo "   -> $BUILD/propsys.dll (Wine stub, tests only)"
fi

echo
echo "Executable: $BUILD/WAC.exe"
x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -qiE 'libstdc|libgcc|winpthread' \
  && echo "WARNING: MinGW runtime dependency detected!" \
  || echo "Static C++ runtime: self-contained exe (Windows system DLLs only)."

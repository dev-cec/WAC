#!/usr/bin/env bash
# Builds WAC.exe from Linux (MinGW-w64 cross-compilation), with no Windows machine.
#
# Produces a self-contained exe (static C++ runtime) that depends only on the
# Windows system DLLs. The offline registry reader is WAC's own
# (offline_registry.cpp): offreg.dll is no longer needed.
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
command -v "$CXX" >/dev/null || { echo "MinGW-w64 missing: apt install g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools" >&2; exit 1; }

[[ "${1:-}" == "--clean" ]] && rm -rf "$BUILD"
mkdir -p "$BUILD"

# --- Common options --------------------------------------------------------
FLAGS=(-std=c++17 -O2
  -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00
  -include "$TP/compat-include/wac_mingw_compat.h"
  -I"$TP/compat-include"
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

# --- libyaml, WAC's one third-party library (third_party/libyaml-0.2.5) ------
# The reading of wac.yml (see its VENDORED.md): the parser's four files only,
# UNMODIFIED, compiled as C. The version macros are the ones autotools would
# put in config.h. -Wall -Wextra apply here too: they build without a warning.
echo "== libyaml =="
CC=x86_64-w64-mingw32-gcc
YAML="$TP/libyaml-0.2.5"
YAML_FLAGS=(-O2 -Wall -Wextra -DYAML_DECLARE_STATIC -DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2
  -DYAML_VERSION_PATCH=5 '-DYAML_VERSION_STRING="0.2.5"' -I"$YAML/include")
YAML_OBJS=()
for c in api reader scanner parser; do
  "$CC" "${YAML_FLAGS[@]}" -c "$YAML/src/$c.c" -o "$BUILD/yaml_$c.o"
  YAML_OBJS+=("$BUILD/yaml_$c.o")
done
FLAGS+=(-DYAML_DECLARE_STATIC -I"$YAML/include")

# --- Compilation units -----------------------------------------------------
echo "== Compilation =="
# Compilation units: discovered automatically (main.cpp last, test harnesses
# excluded). No list to keep by hand any more.
mapfile -t TUS < <(cd "$SRC" && ls *.cpp | grep -v -e '^main\.cpp$' -e '_test\.cpp$'; echo main.cpp)
OBJS=("${YAML_OBJS[@]}")
for tu in "${TUS[@]}"; do
  echo "   - $tu"
  "$CXX" "${FLAGS[@]}" -c "$SRC/$tu" -o "$BUILD/${tu%.cpp}.o"
  OBJS+=("$BUILD/${tu%.cpp}.o")
done

# --- Link --------------------------------------------------------------------
echo "== Link =="
# Only what querying the running system requires: accounts, tokens and
# services (advapi32), the process list (wtsapi32), the logon sessions
# (secur32). Formatting and parsing — GUIDs, SIDs, OLE dates, property names,
# the command line, the registry hives — are WAC's own code.
LIBS=(-ladvapi32 -lwtsapi32 -lsecur32)
# -municode: WAC's entry point is wmain (arguments in UTF-16).
# --no-insert-timestamp: no link date in the PE header — the same sources give
# the same WAC.exe, byte for byte; its version is in its resource (WAC.rc).
"$CXX" -municode -static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp \
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
    "$SRC/sha.cpp" "$SRC/lznt1.cpp" "$SRC/xpress.cpp" "$SRC/lzx.cpp" \
    "$SRC/raw_hive_test.cpp" -o "$BUILD/raw_hive_test.exe"
  echo "   -> $BUILD/raw_hive_test.exe"

  # The test harnesses go into a SEPARATE folder: they are never to be copied
  # onto a collection key with WAC.exe.
  TESTS="$BUILD/tests"
  mkdir -p "$TESTS"

  echo "== Build lnk_test.exe =="
  # The shortcut parser pulls in most of WAC (shell items, GUID names, paths,
  # log): the harness links every WAC object but main.o rather than a list
  # that would drift. See its header, and doc/tests, for the usage.
  TEST_OBJS=()
  for o in "${OBJS[@]}"; do [[ "$o" == "$BUILD/main.o" ]] || TEST_OBJS+=("$o"); done
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/lnk_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/lnk_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/lnk_test.exe"

  echo "== Build parsers_test.exe =="
  # Jump lists and Prefetch, same guard pages; see its header for the usage.
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/parsers_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/parsers_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/parsers_test.exe"

  echo "== Build system_conversions_test.exe =="
  # WAC's GUID, SID, OLE date and property name conversions against the Windows
  # functions they replaced: the only program still linked with those.
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
    "$SRC/system_conversions_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/system_conversions_test.exe" \
    "${LIBS[@]}" -lole32 -loleaut32 -lpropsys -luuid
  echo "   -> $TESTS/system_conversions_test.exe"

  echo "== Build evtx_test.exe, consigne_test.exe, trust_set_test.exe, config_test.exe =="
  # Built here rather than by a hand-written list of sources: that list, in the
  # README, had drifted and no longer linked. Both run under Wine.
  for t in evtx_test consigne_test trust_set_test config_test; do
    "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
      "$SRC/$t.cpp" "${TEST_OBJS[@]}" "$BUILD/WAC_res.o" -o "$TESTS/$t.exe" "${LIBS[@]}"
    echo "   -> $TESTS/$t.exe"
  done

  echo "== Build ntfs_fixup_test.exe =="
  # The check of NTFS multi-sector records (torn records refused); runs under Wine.
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/ntfs_fixup_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/ntfs_fixup_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/ntfs_fixup_test.exe"

  echo "== Build offline_registry_test.exe =="
  # WAC's hive reader against Microsoft's offreg.dll, loaded dynamically: run
  # it on Windows (the test VM) with the path of that DLL.
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
    "$SRC/offline_registry_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/offline_registry_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/offline_registry_test.exe"
fi

echo
echo "Executable: $BUILD/WAC.exe"
x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -qiE 'libstdc|libgcc|winpthread' \
  && echo "WARNING: MinGW runtime dependency detected!" \
  || echo "Static C++ runtime: self-contained exe (Windows system DLLs only)."

# Functions WAC must never import: resolving a name through them may QUERY THE
# DOMAIN CONTROLLER — a trace of the collection on another machine — and makes
# the output depend on the machine running WAC. The SIDs are named offline
# from the hives (WAC/account_names.cpp). A build that imports them fails.
FORBIDDEN='LookupAccountSid|LookupAccountName|LsaLookupSids|LsaLookupNames'
if x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -qE "\\b($FORBIDDEN)"; then
  echo "ERROR: WAC.exe imports a name-resolution function that queries the domain:"
  x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -E "\\b($FORBIDDEN)"
  exit 1
fi
echo "No network name resolution imported ($FORBIDDEN)."

# No network library either: WAC.exe runs on the examined machine, where it
# must never be able to reach the network. --update-trust, run on the analysis
# workstation only, loads WinHTTP DYNAMICALLY, in that mode alone (see
# http_client.cpp); a static import would load it at every start.
NETWORK='winhttp\.dll|wininet\.dll|ws2_32\.dll|wsock32\.dll'
if x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -iE "DLL Name: ($NETWORK)" >/dev/null; then
  echo "ERROR: WAC.exe imports a network library statically:"
  x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -iE "DLL Name: ($NETWORK)"
  exit 1
fi
echo "No network library imported."

# --- WAC/bin: the last build, ready to download ------------------------------
# The executables and the reference configuration (WAC/wac.yml, also built
# into WAC.exe), copied where the repository keeps them, and staged — not
# committed: the commit stays a decision. The test executables stay in
# build-windows/tests.
BIN="$SRC/bin"
mkdir -p "$BIN"
for f in WAC.exe raw_hive_test.exe; do
  [[ -f "$BUILD/$f" ]] && cp "$BUILD/$f" "$BIN/"
done
cp "$SRC/wac.yml" "$BIN/wac.yml"
( cd "$BIN" && sha256sum WAC.exe $( [[ -f raw_hive_test.exe ]] && echo raw_hive_test.exe ) wac.yml > SHA256SUMS )
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$ROOT" add -f "$BIN"
  echo "WAC/bin updated and staged: $(cd "$BIN" && ls | tr '\n' ' ')"
else
  echo "WAC/bin updated: $(cd "$BIN" && ls | tr '\n' ' ')"
fi

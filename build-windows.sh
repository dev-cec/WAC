#!/usr/bin/env bash
# Builds WAC.exe with MinGW-w64 — the one build procedure, the same on Linux and
# on Windows.
#
#   Linux  : cross-compilation, no Windows machine needed.
#            Prerequisites: packages  g++-mingw-w64-x86-64  binutils-mingw-w64-x86-64
#            mingw-w64-tools
#   Windows: optional — the published WAC.exe is the Linux build's. Through
#            build-windows.cmd: the bash of Git for Windows, and MinGW-Builds'
#            gcc 13.2.0 (win32-seh-msvcrt) first in the PATH; not MSYS2's
#            gcc, whose posix threads add 38 imports (see THREAD MODEL below).
#
# Produces a self-contained exe (static C++ runtime) that depends only on the
# Windows system DLLs. The offline registry reader is WAC's own
# (offline_registry.cpp): offreg.dll is no longer needed.
#
# Usage: ./build-windows.sh [--clean] [--test]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$ROOT/sources"
TP="$ROOT/third_party"
BUILD="$ROOT/build-windows"

# --- Toolchain ----------------------------------------------------------------
# Chosen by the system, never by fallback: on Linux an unprefixed g++ is the
# native compiler, which would build a Linux program. MINGW64 only, not UCRT64:
# the UCRT runtime would change WAC.exe's imports (api-ms-win-crt-*.dll instead
# of msvcrt.dll), which the harmlessness file lists.
case "$(uname -s)" in
  Linux)
    TOOL_PREFIX=x86_64-w64-mingw32-
    MISSING="apt install g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools" ;;
  MINGW64_NT*)
    TOOL_PREFIX=
    # Git Bash (Git for Windows), with MinGW-Builds' compiler — win32 threads,
    # msvcrt — first in the PATH: build-windows.cmd sets it (doc/BUILD_EN.md, B-024).
    MISSING="MinGW-Builds x86_64-13.2.0-release-win32-seh-msvcrt first in the PATH (build-windows.cmd, doc/BUILD_EN.md)" ;;
  *)
    echo "Unsupported system $(uname -s): build on Linux, or in the MSYS2 MINGW64 shell on Windows." >&2
    exit 1 ;;
esac
CXX=${TOOL_PREFIX}g++
CC=${TOOL_PREFIX}gcc
WINDRES=${TOOL_PREFIX}windres
OBJDUMP=${TOOL_PREFIX}objdump
for tool in "$CXX" "$CC" "$WINDRES" "$OBJDUMP"; do
  command -v "$tool" >/dev/null || { echo "$tool missing: $MISSING" >&2; exit 1; }
done
# The compiler must produce 64-bit Windows programs, whatever the shell.
[[ "$("$CXX" -dumpmachine)" == x86_64-w64-mingw32 ]] \
  || { echo "$CXX does not target x86_64-w64-mingw32 ($("$CXX" -dumpmachine)): $MISSING" >&2; exit 1; }
# Its THREAD MODEL must be "win32" — Windows' own threads —, not "posix":
# a posix gcc (MSYS2's) links winpthreads into WAC.exe, and with it 38
# imports WAC never calls but its import table shows — SetSystemTime,
# SetThreadContext, SuspendThread, TerminateProcess, OpenProcess… —, a wider
# footprint than the harmlessness file states, and one a defender watches
# (measured, B-024). "win32" has nothing to do with 32 bits: the program is
# x86_64 either way.
THREAD_MODEL="$("$CXX" -v 2>&1 | sed -n 's/^Thread model: //p')"
[[ "$THREAD_MODEL" == win32 ]] \
  || { echo "$CXX: thread model \"$THREAD_MODEL\", win32 expected (a posix gcc adds 38 imports to WAC.exe): $MISSING" >&2; exit 1; }

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

# --- Resource (WAC.rc, UTF-8, read by windres as code page 65001) ----------
# Kept in UTF-8 since B-024 — it was Visual Studio's UTF-16, which needed
# iconv. Carriage returns removed (a Windows checkout may add them), backslashes
# of its paths made forward slashes.
echo "== Resource =="
tr -d '\r' < "$SRC/WAC.rc" | sed -E 's#\\+#/#g' > "$BUILD/WAC.utf8.rc"
"$WINDRES" -I"$SRC" -I"$TP/compat-include" -c 65001 "$BUILD/WAC.utf8.rc" -O coff -o "$BUILD/WAC_res.o"

# --- libyaml, the reading of wac.yml (third_party/libyaml-0.2.5) -------------
# The reading of wac.yml (see its VENDORED.md): the parser's four files only,
# UNMODIFIED, compiled as C. The version macros are the ones autotools would
# put in config.h. -Wall -Wextra apply here too: they build without a warning.
echo "== libyaml =="
YAML="$TP/libyaml-0.2.5"
YAML_FLAGS=(-O2 -Wall -Wextra -DYAML_DECLARE_STATIC -DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2
  -DYAML_VERSION_PATCH=5 '-DYAML_VERSION_STRING="0.2.5"' -I"$YAML/include")
THIRD_PARTY_OBJS=()
for c in api reader scanner parser; do
  "$CC" "${YAML_FLAGS[@]}" -c "$YAML/src/$c.c" -o "$BUILD/yaml_$c.o"
  THIRD_PARTY_OBJS+=("$BUILD/yaml_$c.o")
done
FLAGS+=(-DYAML_DECLARE_STATIC -I"$YAML/include")

# --- SQLite, the browsers' databases (third_party/sqlite-3.53.4) -------------
# The amalgamation, UNMODIFIED, compiled as C (see its VENDORED.md). Options:
# no thread safety (WAC reads one database at a time, from one thread), no
# extension loading, no deprecated interfaces, double-quoted strings refused.
# The documented warning exclusions, upstream code not to be patched:
# -Wno-unused-parameter, for two parameters SQLite's Windows layer leaves
# unused (winUnfetch, the busy timeout); -Wno-unused-but-set-variable, for a
# variable g++ 16 (MSYS2) finds set and never read (nIdx), g++ 13 not (B-024).
echo "== SQLite =="
SQLITE="$TP/sqlite-3.53.4"
SQLITE_OPTIONS=(-DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_DEPRECATED
  -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_DQS=0 -DSQLITE_OMIT_SHARED_CACHE)
"$CC" -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable "${SQLITE_OPTIONS[@]}" -c "$SQLITE/sqlite3.c" -o "$BUILD/sqlite3.o"
THIRD_PARTY_OBJS+=("$BUILD/sqlite3.o")   # linked with WAC and every test harness
FLAGS+=("${SQLITE_OPTIONS[@]}" -I"$SQLITE")

# --- Compilation units -----------------------------------------------------
echo "== Compilation =="
# Compilation units: discovered automatically (main.cpp last, test harnesses
# excluded). No list to keep by hand any more.
mapfile -t TUS < <(cd "$SRC" && ls *.cpp | grep -v -e '^main\.cpp$' -e '_test\.cpp$'; echo main.cpp)
OBJS=("${THIRD_PARTY_OBJS[@]}")
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
LIBS=(-ladvapi32 -lwtsapi32 -lsecur32 -lbcrypt)
# -municode: WAC's entry point is wmain (arguments in UTF-16).
# --no-insert-timestamp: no link date in the PE header — the same sources give
# the same WAC.exe, byte for byte; its version is in its resource (WAC.rc).
"$CXX" -municode -static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp \
  "${OBJS[@]}" "$BUILD/WAC_res.o" -o "$BUILD/WAC.exe" "${LIBS[@]}"

# --- WAC32.exe, the 32-bit WAC -------------------------------------------------
# The same sources, for the Windows that only exist or still run in 32 bits:
# Windows XP SP1 to Windows 8 x86 (backlog B-037). WAC.exe stays the program of
# every 64-bit Windows. Built on Linux only, with the i686 MinGW-w64 of the same
# gcc (packages g++-mingw-w64-i686 binutils-mingw-w64-i686); without it, WAC32 is
# skipped and said so. The functions XP lacks are defined by xp_imports.cpp —
# an empty unit in the 64-bit build.
CXX32=i686-w64-mingw32-g++
BUILD32="$BUILD/x86"
WAC32=""
if command -v "$CXX32" >/dev/null && [[ "$("$CXX32" -v 2>&1 | sed -n 's/^Thread model: //p')" == win32 ]]; then
  echo "== WAC32.exe (32 bits) =="
  mkdir -p "$BUILD32"
  OBJS32=()
  for c in api reader scanner parser; do
    i686-w64-mingw32-gcc "${YAML_FLAGS[@]}" -c "$YAML/src/$c.c" -o "$BUILD32/yaml_$c.o"
    OBJS32+=("$BUILD32/yaml_$c.o")
  done
  i686-w64-mingw32-gcc -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-but-set-variable "${SQLITE_OPTIONS[@]}" \
    -c "$SQLITE/sqlite3.c" -o "$BUILD32/sqlite3.o"
  OBJS32+=("$BUILD32/sqlite3.o")
  i686-w64-mingw32-windres -I"$SRC" -I"$TP/compat-include" -c 65001 "$BUILD/WAC.utf8.rc" -O coff -o "$BUILD32/WAC_res.o"
  # The units in parallel: this second pass must not double the time of a build.
  export CXX32 BUILD32 SRC
  printf '%s\n' "${FLAGS[@]}" > "$BUILD32/flags.txt"
  printf '%s\n' "${TUS[@]}" | xargs -P "$(nproc)" -I{} bash -c \
    'mapfile -t F < "$BUILD32/flags.txt"; tu="{}"; "$CXX32" "${F[@]}" -c "$SRC/$tu" -o "$BUILD32/${tu%.cpp}.o"'
  for tu in "${TUS[@]}"; do OBJS32+=("$BUILD32/${tu%.cpp}.o"); done
  # No -lbcrypt: bcrypt.dll does not exist under XP, xp_imports.cpp loads it where it does.
  LIBS32=(-ladvapi32 -lwtsapi32 -lsecur32)
  "$CXX32" -municode -static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp \
    "${OBJS32[@]}" "$BUILD32/WAC_res.o" -o "$BUILD/WAC32.exe" "${LIBS32[@]}"
  WAC32="$BUILD/WAC32.exe"
  # EVERY IMPORT MUST EXIST UNDER WINDOWS XP SP1: one that does not keeps the
  # program from loading at all, and is otherwise found on the examined
  # machine. The reference is the export list of XP SP1's own DLLs.
  XP_EXPORTS="$TP/windows-xp-sp1/exports.txt"
  ABSENT="$(LC_ALL=C i686-w64-mingw32-objdump -p "$WAC32" \
            | awk '/DLL Name/{d=tolower($3)} /^\t[0-9a-f]+\t +[0-9]+  /{print d, $3}' | sort -u \
            | grep -vxFf "$XP_EXPORTS" || true)"
  if [[ -n "$ABSENT" ]]; then
    echo "ERROR: WAC32.exe imports what Windows XP SP1 does not export (define it in xp_imports.cpp):"
    echo "$ABSENT" | sed 's/^/   /'
    exit 1
  fi
  echo "   -> $WAC32: every import exists under Windows XP SP1"
else
  echo "== WAC32.exe skipped: $CXX32 (thread model win32) not installed =="
  rm -f "$BUILD/WAC32.exe"
fi

# --- raw_hive test exe (optional) -------------------------------------------
if [[ "${1:-}" == "--test" || "${2:-}" == "--test" ]]; then
  echo "== Build raw_hive_test.exe =="
  # raw_hive's dependencies: the fingerprints (sha, quickdigest5), the NTFS
  # decompression (lznt1, xpress), the shadow copies (vss) and the boot sector
  # (ntfs_boot_sector). This list must
  # be kept up to date — it has drifted once already, and a test exe that no
  # longer links is only noticed at the moment it is needed.
  # --no-insert-timestamp, as WAC.exe: it goes to bin, and must be the same
  # file from the same sources (it was not — its link date changed each build).
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp \
    "$SRC/raw_hive.cpp" "$SRC/hive_recover.cpp" "$SRC/quickdigest5.cpp" \
    "$SRC/sha.cpp" "$SRC/lznt1.cpp" "$SRC/xpress.cpp" "$SRC/lzx.cpp" "$SRC/vss.cpp" "$SRC/ntfs_boot_sector.cpp" \
    "$SRC/raw_hive_test.cpp" -o "$BUILD/raw_hive_test.exe"
  echo "   -> $BUILD/raw_hive_test.exe"
  # Its 32-bit twin, for the harness on a 32-bit Windows (8 x86, XP), with
  # the XP equivalents WAC32 links (xp_imports.o); not copied to bin.
  if [[ -n "$WAC32" ]]; then
    mapfile -t FLAGS32 < "$BUILD32/flags.txt"
    "$CXX32" "${FLAGS32[@]}" -municode -static -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp \
      "$SRC/raw_hive.cpp" "$SRC/hive_recover.cpp" "$SRC/quickdigest5.cpp" \
      "$SRC/sha.cpp" "$SRC/lznt1.cpp" "$SRC/xpress.cpp" "$SRC/lzx.cpp" "$SRC/vss.cpp" "$SRC/ntfs_boot_sector.cpp" \
      "$SRC/raw_hive_test.cpp" "$BUILD32/xp_imports.o" -o "$BUILD/raw_hive_test32.exe" -ladvapi32
    echo "   -> $BUILD/raw_hive_test32.exe"
  fi

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

  echo "== Build evtx_test.exe, consigne_test.exe, trust_set_test.exe, config_test.exe, mft_test.exe, usn_journal_test.exe, file_artefacts_test.exe, cim_test.exe, ese_test.exe, fat_test.exe, link_tracking_test.exe, ie_index_dat_test.exe, activities_cache_test.exe, pst_test.exe, shell_items_test.exe, hive_recover_test.exe, sam_secrets_test.exe, vss_test.exe, deleted_files_test.exe, carving_test.exe =="
  # Built here rather than by a hand-written list of sources: that list, in the
  # README, had drifted and no longer linked. Both run under Wine.
  for t in evtx_test consigne_test trust_set_test config_test mft_test usn_journal_test file_artefacts_test cim_test ese_test fat_test link_tracking_test ie_index_dat_test activities_cache_test pst_test shell_items_test hive_recover_test sam_secrets_test vss_test deleted_files_test carving_test; do
    "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
      "$SRC/$t.cpp" "${TEST_OBJS[@]}" "$BUILD/WAC_res.o" -o "$TESTS/$t.exe" "${LIBS[@]}"
    echo "   -> $TESTS/$t.exe"
  done

  echo "== Build ntfs_fixup_test.exe =="
  # The check of NTFS multi-sector records (torn records refused); runs under Wine.
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/ntfs_fixup_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/ntfs_fixup_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/ntfs_fixup_test.exe"

  echo "== Build ntfs_runs_test.exe =="
  # The check of the data runs (a forged list refused whole); runs under Wine.
  "$CXX" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
    "$SRC/ntfs_runs_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/ntfs_runs_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/ntfs_runs_test.exe"

  echo "== Build offline_registry_test.exe =="
  # WAC's hive reader against Microsoft's offreg.dll, loaded dynamically: run
  # it on Windows (the test VM) with the path of that DLL.
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
    "$SRC/offline_registry_test.cpp" "${TEST_OBJS[@]}" -o "$TESTS/offline_registry_test.exe" "${LIBS[@]}"
  echo "   -> $TESTS/offline_registry_test.exe"

  if [[ -n "$WAC32" ]]; then
    echo "== Build xp_imports_test.exe (32 bits) =="
    # The equivalents of the functions XP lacks, against the system's own: a
    # 32-bit program, run on any Windows that has both (the test VM).
    "$CXX32" "${FLAGS[@]}" -static -static-libgcc -static-libstdc++ \
      "$SRC/xp_imports_test.cpp" "$BUILD32/xp_imports.o" -o "$TESTS/xp_imports_test.exe"
    echo "   -> $TESTS/xp_imports_test.exe"
  fi

  echo "== artefact_catalogue_test (native, run here) =="
  # The table of the artefacts is portable C++ without windows.h: built for
  # this machine and run at once. Run before only when the documentation's
  # table was rebuilt, a change of the table once broke it unnoticed.
  g++ -std=c++17 -Wall -Wextra -I"$SRC" "$SRC/artefact_catalogue.cpp" "$SRC/artefact_catalogue_test.cpp" \
    -o "$TESTS/artefact_catalogue_test"
  "$TESTS/artefact_catalogue_test" "$SRC/wac.yml" | tail -1 | sed 's/^/   /'
fi

# Each executable built answers the same checks: WAC.exe, and WAC32.exe when it was built.
for EXE in "$BUILD/WAC.exe" ${WAC32:+"$WAC32"}; do
  echo
  echo "Executable: $EXE"
  "$OBJDUMP" -p "$EXE" | grep -qiE 'libstdc|libgcc|winpthread' \
    && echo "WARNING: MinGW runtime dependency detected!" \
    || echo "Static C++ runtime: self-contained exe (Windows system DLLs only)."

  # Functions WAC must never import: resolving a name through them may QUERY THE
  # DOMAIN CONTROLLER — a trace of the collection on another machine — and makes
  # the output depend on the machine running WAC. The SIDs are named offline
  # from the hives (sources/account_names.cpp). A build that imports them fails.
  FORBIDDEN='LookupAccountSid|LookupAccountName|LsaLookupSids|LsaLookupNames'
  if "$OBJDUMP" -p "$EXE" | grep -qE "\\b($FORBIDDEN)"; then
    echo "ERROR: $(basename "$EXE") imports a name-resolution function that queries the domain:"
    "$OBJDUMP" -p "$EXE" | grep -E "\\b($FORBIDDEN)"
    exit 1
  fi
  echo "No network name resolution imported ($FORBIDDEN)."

  # No network library either: WAC.exe runs on the examined machine, where it
  # must never be able to reach the network. --update-trust, run on the analysis
  # workstation only, loads WinHTTP DYNAMICALLY, in that mode alone (see
  # http_client.cpp); a static import would load it at every start. The
  # network state (artefacts.network) reads the TCP/IP stack's tables through
  # iphlpapi, loaded dynamically too, and only when that artefact is asked for.
  NETWORK='winhttp\.dll|wininet\.dll|ws2_32\.dll|wsock32\.dll|iphlpapi\.dll'
  if "$OBJDUMP" -p "$EXE" | grep -iE "DLL Name: ($NETWORK)" >/dev/null; then
    echo "ERROR: $(basename "$EXE") imports a network library statically:"
    "$OBJDUMP" -p "$EXE" | grep -iE "DLL Name: ($NETWORK)"
    exit 1
  fi
  echo "No network library imported."

  # Nor any function that starts a process: a program started by WAC would leave
  # its own execution traces on the examined machine (Prefetch, BAM, ShimCache).
  # The screen used to be cleared by system("cls"), a cmd.exe each run, which
  # the compared footprint measure showed (backlog B-027).
  SPAWN='system|_wsystem|_w?spawn[lv]p?e?|_w?exec[lv]p?e?|_w?popen|CreateProcess[AW]?|CreateProcessAsUser[AW]|CreateProcessWithLogonW|CreateProcessWithTokenW|ShellExecute[AW]|ShellExecuteEx[AW]|WinExec'
  if "$OBJDUMP" -p "$EXE" | grep -qE "^\s+[0-9a-f]+\s+[0-9]+\s+($SPAWN)\s*$"; then
    echo "ERROR: $(basename "$EXE") imports a function that starts a process:"
    "$OBJDUMP" -p "$EXE" | grep -E "^\s+[0-9a-f]+\s+[0-9]+\s+($SPAWN)\s*$"
    exit 1
  fi
  echo "No process-starting function imported."
done

# --- bin: the last build, ready to download ------------------------------
# The executables, the reference configuration (sources/wac.yml, also built into
# WAC.exe) and the scripts that verify a collection, copied where the
# repository keeps them, and staged — not committed: the commit stays a
# decision. The test executables stay in build-windows/tests.
# The scripts travel with the binary: the investigator verifies a collection
# with what came in the same folder, from Windows (.ps1) or from a Linux
# investigation machine (.sh). Their source is in sources/scripts; the user
# manuals list them from there.
BIN="$ROOT/bin"
VERIFICATION_SCRIPTS=(verify-exhibits.ps1 verifier-consigne.ps1 verify-exhibits.sh verifier-consigne.sh)
mkdir -p "$BIN"
for f in WAC.exe WAC32.exe raw_hive_test.exe; do
  [[ -f "$BUILD/$f" ]] && cp "$BUILD/$f" "$BIN/"
done
# The reference configuration with the executable's version in place of its
# placeholder, as --write-config writes it: a wac.yml of another version is refused.
VERSION="$("$ROOT/wac-version.sh")"
sed "s/@WAC_VERSION@/$VERSION/" "$SRC/wac.yml" > "$BIN/wac.yml"
grep -q "^wac_version: $VERSION\$" "$BIN/wac.yml" || { echo "bin/wac.yml: wac_version not written" >&2; exit 1; }
for f in "${VERIFICATION_SCRIPTS[@]}"; do
  cp "$SRC/scripts/$f" "$BIN/$f"
done
# A WAC32.exe of an earlier build does not stay beside a WAC.exe it no longer matches.
[[ -n "$WAC32" ]] || rm -f "$BIN/WAC32.exe"
( cd "$BIN" && sha256sum WAC.exe $( [[ -f WAC32.exe ]] && echo WAC32.exe ) $( [[ -f raw_hive_test.exe ]] && echo raw_hive_test.exe ) wac.yml \
    "${VERIFICATION_SCRIPTS[@]}" > SHA256SUMS )
if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$ROOT" add -f "$BIN"
  echo "bin updated and staged: $(cd "$BIN" && ls | tr '\n' ' ')"
else
  echo "bin updated: $(cd "$BIN" && ls | tr '\n' ' ')"
fi

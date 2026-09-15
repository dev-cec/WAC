#!/usr/bin/env bash
# Build de WAC.exe depuis Linux (cross-compilation MinGW-w64), sans poste Windows.
#
# Produit un exe autonome (runtime C++ statique) ne dépendant que des DLL
# système Windows (offreg.dll, wevtapi.dll, vssapi.dll… tous présents sur cible).
#
# Prérequis : paquets  g++-mingw-w64-x86-64  binutils-mingw-w64-x86-64  mingw-w64-tools
# Usage : ./build-windows.sh [--clean]
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$RACINE/WAC"
TP="$RACINE/third_party"
BUILD="$RACINE/build-windows"

CXX=x86_64-w64-mingw32-g++
WINDRES=x86_64-w64-mingw32-windres
DLLTOOL=x86_64-w64-mingw32-dlltool
command -v "$CXX" >/dev/null || { echo "MinGW-w64 absent : apt install g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools" >&2; exit 1; }

[[ "${1:-}" == "--clean" ]] && rm -rf "$BUILD"
mkdir -p "$BUILD"

# --- Import lib offreg (Offline Registry ; absent de MinGW) -----------------
if [[ ! -f "$TP/offreg/liboffreg.a" ]]; then
  echo "== Génération de liboffreg.a =="
  "$DLLTOOL" -d "$TP/offreg/offreg.def" -l "$TP/offreg/liboffreg.a" -D offreg.dll -m i386:x86-64
fi

# --- Options communes ------------------------------------------------------
FLAGS=(-std=c++17 -O2
  -DUNICODE -D_UNICODE -DWINVER=0x0A00 -D_WIN32_WINNT=0x0A00
  -include "$TP/compat-include/wac_mingw_compat.h"
  -I"$TP/offreg" -I"$TP/compat-include"
  -finput-charset=UTF-8 -fexec-charset=UTF-8
  # -Wall : le projet compilait sans, ce qui laissait passer 46 declarations
  # mortes et un GetVolumeInformationW dont le resultat etait ignore (doc §14.16).
  # Les trois exclusions restantes sont des idiomes assumes du projet :
  #   missing-field-initializers : « = { 0 } » sur les structures Win32,
  #   sign-compare               : comparaisons avec les tailles STL,
  #   cast-function-type         : GetProcAddress, cast obligatoire.
  -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
  -Wno-sign-compare -Wno-cast-function-type
  -Wno-unknown-pragmas -Wno-deprecated -Wno-conversion-null)

# --- Ressource (.rc VS en UTF-16 → UTF-8 pour windres) ---------------------
echo "== Ressource =="
iconv -f UTF-16LE -t UTF-8 "$SRC/WAC.rc" | tr -d '\r' | sed -E 's#\\+#/#g' > "$BUILD/WAC.utf8.rc"
"$WINDRES" -I"$SRC" -I"$TP/compat-include" -c 65001 "$BUILD/WAC.utf8.rc" -O coff -o "$BUILD/WAC_res.o"

# --- Compilation des unités ------------------------------------------------
echo "== Compilation =="
# Unités de compilation : découvertes automatiquement (main.cpp en dernier,
# harnais de test exclus). Plus de liste à maintenir à la main.
mapfile -t TUS < <(cd "$SRC" && ls *.cpp | grep -v -e '^main\.cpp$' -e '_test\.cpp$'; echo main.cpp)
OBJS=()
for tu in "${TUS[@]}"; do
  echo "   - $tu"
  "$CXX" "${FLAGS[@]}" -c "$SRC/$tu" -o "$BUILD/${tu%.cpp}.o"
  OBJS+=("$BUILD/${tu%.cpp}.o")
done

# --- Édition de liens ------------------------------------------------------
echo "== Link =="
LIBS=(-L"$TP/offreg" -loffreg -lwevtapi -lole32 -loleaut32
      -luuid -lshlwapi -ladvapi32 -lshell32 -lversion -lwtsapi32
      -lsecur32 -lpropsys -lntdll)
"$CXX" -static -static-libgcc -static-libstdc++ \
  "${OBJS[@]}" "$BUILD/WAC_res.o" -o "$BUILD/WAC.exe" "${LIBS[@]}"

# --- Exe de test raw_hive (optionnel) --------------------------------------
if [[ "${1:-}" == "--test" || "${2:-}" == "--test" ]]; then
  echo "== Build raw_hive_test.exe =="
  "$CXX" "${FLAGS[@]}" -municode -static -static-libgcc -static-libstdc++ \
    "$SRC/raw_hive.cpp" "$SRC/hive_recover.cpp" "$SRC/quickdigest5.cpp" \
    "$SRC/raw_hive_test.cpp" -o "$BUILD/raw_hive_test.exe"
  echo "   -> $BUILD/raw_hive_test.exe"
fi

echo
echo "Exécutable : $BUILD/WAC.exe"
x86_64-w64-mingw32-objdump -p "$BUILD/WAC.exe" | grep -qiE 'libstdc|libgcc|winpthread' \
  && echo "AVERTISSEMENT : dépendance runtime MinGW détectée !" \
  || echo "Runtime C++ statique : exe autonome (DLL système Windows uniquement)."

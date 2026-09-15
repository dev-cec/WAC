# Compilation de WAC depuis Linux (cross-compilation MinGW-w64)

Produit `WAC.exe` (PE32+ x64) depuis Linux, **sans poste Windows**, en un exe
**autonome** : runtime C++ lié en statique, ne dépendant que des **DLL système
Windows** (présentes sur toute cible). Le build MSVC/Visual Studio d'origine reste
intact et utilisable en parallèle.

## Prérequis (une fois)
```bash
sudo apt-get install -y g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools
```

## Compiler
```bash
./build-windows.sh            # incrémental
./build-windows.sh --clean    # from scratch
# -> build-windows/WAC.exe
```

## Ce que le script fait
1. Génère l'import lib `third_party/offreg/liboffreg.a` (API Offline Registry,
   absente de MinGW) à partir de `offreg.def`.
2. Convertit `WAC.rc` (UTF-16 VS) en UTF-8 pour `windres`, normalise les chemins
   (icône), compile la ressource (version + icône).
3. Compile chaque unité avec un header de **compat force-include**.
4. Lie en statique (`-static -static-libgcc -static-libstdc++`) + import libs système.

## Briques de compatibilité (dossier `third_party/`)
| Élément | Rôle |
|---|---|
| `offreg/offreg.h` + `offreg.def` + `liboffreg.a` | Shim de l'Offline Registry API (offreg.dll), absente de MinGW. x64 → convention d'appel unique. |
| `compat-include/wac_mingw_compat.h` | Force-include : `math.h`/`filesystem`, `ERROR_NDIS_BAD_VERSION`, constantes `SERVICE_*`/`TASK_TRIGGER_CUSTOM_TRIGGER_01` manquantes. |
| `compat-include/taskschd_missing.h` | `IComHandlerAction` (absente de mingw taskschd.h), dérivée d'`IAction` → vtable exacte au runtime. |
| `compat-include/{LM,Sddl,ShellAPI,Wbemidl}.h` | Alias de casse (MSVC insensible à la casse, MinGW/Linux non). |

## Corrections de portabilité MSVC→MinGW (sources)
Écarts où MSVC était permissif ; corrections neutres pour le comportement, sauf 2
qui corrigent de **vrais bugs** (repérés lors des analyses précédentes) :
- `get<N>(...)` → `std::get<N>(...)` (ADL sur template-id explicite) — plusieurs fichiers.
- `std::ifstream(<wstring>)` → `std::filesystem::path(...)` (5 sites).
- Casse d'include : `oleParser.hpp` → `oleparser.hpp`.
- `vss.cpp` : `#include <strsafe.h>` déplacé **après** tchar.h/shlwapi.h (conflit de macros).
- `schedulesTasks.hpp` : `#include "taskschd_missing.h"` après `<taskschd.h>`.
- **[BUG]** `idList.cpp` (VT_I1/VT_UI1) : `reinterpret_cast<char>(ptr)` → `*reinterpret_cast<char*>(ptr)` (déréférencement).
- **[BUG latent]** `events.hpp` : `FILETIME((DWORD)FileTimeVal)` → `FILETIME{(DWORD)FileTimeVal,0}` (compile ; conserve la sémantique MSVC — **tronque toujours le FILETIME 64 bits sur 32**, à corriger dans le chantier horodatage §7).

## Autonomie vérifiée
`WAC.exe` n'importe que : `ADVAPI32, KERNEL32, msvcrt, NETAPI32, offreg, ole32,
OLEAUT32, PROPSYS, Secur32, VSSAPI, wevtapi` — **aucune DLL MinGW** (runtime statique).

# Compilation de WAC depuis Linux (compilation croisée MinGW-w64)

*English version: [BUILD-LINUX_EN.md](BUILD-LINUX_EN.md)*

Produit `WAC.exe` (PE32+ x64) depuis Linux, **sans poste Windows**, en un
exécutable **autonome** : le runtime C++ est lié en statique, et le programme ne
dépend que des **DLL système Windows** (présentes sur toute cible). Le build
MSVC / Visual Studio d'origine (`WAC.sln`) reste utilisable en parallèle.

## Prérequis (une fois)
```bash
sudo apt-get install -y g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools
```

## Compiler
```bash
./build-windows.sh            # incrémental
./build-windows.sh --clean    # depuis zéro
./build-windows.sh --test     # construit aussi raw_hive_test.exe et les harnais de build-windows/tests/
# -> build-windows/WAC.exe
```

## Ce que fait le script
1. Convertit `WAC.rc` (UTF-16 de Visual Studio) en UTF-8 pour `windres`,
   normalise ses chemins (icône) et compile la ressource (version + icône).
2. Compile chaque unité trouvée dans `WAC/` (hors `*_test.cpp`) avec un en-tête
   de **compatibilité inclus d'office**.
3. Compile libyaml (lecture de `wac.yml`, voir ci-dessous) en C.
4. Lie en statique (`-static -static-libgcc -static-libstdc++`) avec les
   bibliothèques d'import système, **sans horodatage** (`--no-insert-timestamp`) :
   les mêmes sources donnent le même `WAC.exe`, octet pour octet.
5. Vérifie les gardes : aucune bibliothèque réseau ni résolution de noms
   importée, et **chaque source listée dans `WAC.vcxproj`** (refus sinon).
6. Copie `WAC.exe`, `raw_hive_test.exe`, `wac.yml` et `SHA256SUMS` dans
   `WAC/bin` et les ajoute à l'index git (sans commit).

## Version et publication
Format `<majeur>.<mineure>.<correctif>`, écrit dans `WAC/WAC.rc` seulement
(propriétés de l'exécutable ; WAC la relit à l'exécution). Pour publier :
commiter les sources, lancer `./bump-version.sh --bugfix|--minor|--major`
(incrémente, recompile, indexe `WAC.rc` et `WAC/bin`, régénère la documentation du code `WAC/doc/html` avec la même version), commiter.

## Briques de compatibilité (dossier `third_party/`)
| Élément | Rôle |
|---|---|
| `compat-include/wac_mingw_compat.h` | Inclus d'office : `math.h` / `<filesystem>`, et constantes absentes de MinGW. |
| `compat-include/{Sddl,ShellAPI}.h` | Alias de casse (MSVC ignore la casse des noms d'en-têtes, MinGW sous Linux non). |
| `libyaml-0.2.5/` | Lecture de `wac.yml` : les 4 fichiers du lecteur de libyaml 0.2.5, non modifiés (origine et empreinte dans `VENDORED.md`). Seule bibliothèque tierce de WAC. |

## Tenir le projet Visual Studio à jour
`build-windows.sh` découvre les sources automatiquement, mais **pas** le projet
Visual Studio : tout nouveau `.cpp` / `.h` doit aussi être ajouté à
`WAC/WAC.vcxproj` et `WAC/WAC.vcxproj.filters`. Un oubli a cassé la compilation
MSVC pendant plusieurs commits, sans que rien ne le signale, seule la
compilation Linux étant testée.

## Autonomie vérifiée
`WAC.exe` n'importe que : `ADVAPI32, KERNEL32, msvcrt, Secur32, WTSAPI32` — ce
qu'exige l'interrogation du système en marche. **Aucune DLL MinGW** (runtime
statique) ; plus d'`offreg.dll` (les ruches sont lues par
`WAC/offline_registry.cpp`) ; plus d'`ole32`, `oleaut32`, `propsys` ni `shell32`
(GUID, SID, dates OLE, noms de propriétés et ligne de commande sont traités par
WAC lui-même, vérifiés contre Windows par `system_conversions_test`). Vérifier
avec :
```bash
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"
```

# Compilation de WAC (Linux et Windows, MinGW-w64)

*English version: [BUILD_EN.md](BUILD_EN.md)*

Une seule procédure, `build-windows.sh`, la même sous Linux et sous Windows :
elle produit `WAC.exe` (PE32+ x64), un exécutable **autonome** — le runtime C++
est lié en statique, et le programme ne dépend que des **DLL système Windows**
(présentes sur toute cible). La compilation MSVC / Visual Studio a été retirée :
deux chaînes de compilation, c'étaient deux programmes à vérifier, et le projet
Visual Studio, qui ne découvrait pas les sources, avait déjà cassé plusieurs
commits sans que rien ne le signale.

## Prérequis (une fois)

**Linux** (compilation croisée, aucun poste Windows nécessaire) :
```bash
sudo apt-get install -y g++-mingw-w64-x86-64 binutils-mingw-w64-x86-64 mingw-w64-tools
```

**Windows** : installer MSYS2 (https://www.msys2.org), ouvrir le shell
**MSYS2 MINGW64** (pas UCRT64 : son runtime changerait les imports de
`WAC.exe`), puis :
```bash
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-binutils libiconv git
```

## Compiler
Depuis la racine du dépôt, dans le shell Linux ou MSYS2 MINGW64 :
```bash
./build-windows.sh            # incrémental
./build-windows.sh --clean    # depuis zéro
./build-windows.sh --test     # construit aussi raw_hive_test.exe et les harnais de build-windows/tests/
# -> build-windows/WAC.exe
```

Le script choisit la chaîne selon le système — le compilateur préfixé
`x86_64-w64-mingw32-` sous Linux, celui de MSYS2 sous Windows — et vérifie
qu'elle produit bien des programmes Windows 64 bits (`-dumpmachine`). Jamais
de repli : sous Linux, un `g++` sans préfixe produirait un programme Linux.

La compilation est reproductible pour une même version de GCC : les mêmes
sources donnent le même `WAC.exe`, octet pour octet. Deux versions de GCC
différentes (celle de la distribution Linux et celle de MSYS2) peuvent donner
deux exécutables différents, tous deux corrects : c'est `bin/SHA256SUMS`,
produit par la compilation livrée, qui fait foi.

## Ce que fait le script
1. Convertit `WAC.rc` (UTF-16) en UTF-8 pour `windres`, normalise ses chemins
   (icône) et compile la ressource (version, icône, `wac.yml` de référence).
2. Compile chaque unité trouvée dans `sources/` (hors `*_test.cpp`) avec un
   en-tête de **compatibilité inclus d'office**.
3. Compile libyaml (lecture de `wac.yml`, voir ci-dessous) en C.
4. Lie en statique (`-static -static-libgcc -static-libstdc++`) avec les
   bibliothèques d'import système, **sans horodatage** (`--no-insert-timestamp`).
5. Vérifie les gardes : runtime statique, aucune bibliothèque réseau ni
   fonction de résolution de noms par le domaine importée (refus sinon).
6. Copie `WAC.exe`, `raw_hive_test.exe`, `wac.yml`, les scripts de vérification
   d'une collecte et `SHA256SUMS` dans `bin`, et les ajoute à l'index git (sans
   commit).

## Version et publication
Format `<majeur>.<mineure>.<correctif>`, écrit dans `sources/WAC.rc` seulement
(propriétés de l'exécutable ; WAC la relit à l'exécution). Pour publier :
commiter les sources, lancer `./bump-version.sh --bugfix|--minor|--major`
(incrémente, recompile, indexe `WAC.rc` et `bin`, régénère la documentation du
code `sources/doc/html` avec la même version), commiter.

## Briques de compatibilité (dossier `third_party/`)
| Élément | Rôle |
|---|---|
| `compat-include/wac_mingw_compat.h` | Inclus d'office : `<filesystem>`, et les constantes que les en-têtes MinGW n'ont pas et que WAC utilise. |
| `libyaml-0.2.5/` | Lecture de `wac.yml` : les 4 fichiers du lecteur de libyaml 0.2.5, non modifiés (origine et empreinte dans `VENDORED.md`). Seule bibliothèque tierce de WAC. |

## Autonomie vérifiée
`WAC.exe` n'importe que : `ADVAPI32, KERNEL32, msvcrt, Secur32, WTSAPI32` — ce
qu'exige l'interrogation du système en marche. **Aucune DLL MinGW** (runtime
statique) ; plus d'`offreg.dll` (les ruches sont lues par
`sources/offline_registry.cpp`) ; plus d'`ole32`, `oleaut32`, `propsys` ni
`shell32` (GUID, SID, dates OLE, noms de propriétés et ligne de commande sont
traités par WAC lui-même, vérifiés contre Windows par `system_conversions_test`).
La liste complète des fonctions importées, et ce qu'elle prouve, est dans le
dossier d'innocuité. Vérifier avec :
```bash
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"   # sous MSYS2 : objdump
```

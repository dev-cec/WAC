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

**Windows** — facultatif : le `WAC.exe` publié dans `bin/` est celui de la
compilation Linux, et c'est lui qu'on télécharge. Pour compiler quand même
sous Windows, deux installations :

1. **Git for Windows** (https://git-scm.com), de toute façon nécessaire pour
   cloner le dépôt : il apporte aussi le bash et les outils Unix (`sed`,
   `grep`, `tar`, `sha256sum`…) que demande `build-windows.sh`. Le dépôt garde
   ses scripts `.sh` en fins de ligne LF (`.gitattributes`), même avec le
   réglage par défaut de Git for Windows (`core.autocrlf=true`).
2. **Le compilateur MinGW-Builds** (projet niXman) :
   `x86_64-13.2.0-release-win32-seh-msvcrt-rt_v11-rev1.7z`
   (https://github.com/niXman/mingw-builds-binaries/releases, publication
   `13.2.0-rt_v11-rev1`), décompressé avec 7-Zip dans `C:\mingw-win32` —
   ou ailleurs, en donnant le dossier dans la variable `WAC_MINGW`. C'est
   exactement la chaîne de Debian : GCC 13.2.0, MinGW-w64 v11, threads
   **win32**, runtime **msvcrt**. Aucune empreinte n'est publiée ; celle
   relevée pour WAC est
   `15b914f38f2f2e2d6f7b9b8425ff22b7e406878b01920190b09ce0dd8259c6aa`.

Puis, à la racine du dépôt, depuis `cmd`, PowerShell ou un double-clic :
```
build-windows.cmd            :: ou build-windows.cmd --test
```
`build-windows.cmd` ne fait que placer le compilateur de MinGW-Builds en tête
du chemin et lancer `build-windows.sh` dans le bash de Git : la procédure de
compilation reste une seule.

**Pourquoi ce compilateur et pas un autre** — celui de MSYS2, par exemple.
Le *modèle de threads* de ce dernier est « posix » :
il intègre winpthreads à `WAC.exe`, et avec lui **38 imports** que WAC
n'appelle jamais mais que sa table d'imports montre — `SetSystemTime`,
`SetThreadContext`, `SuspendThread`, `TerminateProcess`, `OpenProcess`,
`SetProcessAffinityMask`… Un outil d'analyse ou de défense les voit : une
empreinte plus large que celle que décrit le dossier d'innocuité, et des
noms qui attirent l'attention sur la machine examinée. Avec des threads
« win32 » (les threads de Windows eux-mêmes), ces imports disparaissent :
mesuré sous Windows, les mêmes six DLL que la compilation Linux, et huit
fonctions d'entrée-sortie de msvcrt de différence (`_exit` d'un côté,
`fgetpos`, `fsetpos`, `getwc`, `putc`, `putwc`, `ungetwc`, `_filelengthi64`
de l'autre). « win32 » est le nom du modèle de threads, pas une
architecture : le programme est x86_64 dans les deux cas. Le runtime
**msvcrt** compte aussi : UCRT64 changerait les DLL importées
(`api-ms-win-crt-*`). `build-windows.sh` refuse tout compilateur dont le
modèle de threads n'est pas « win32 ».

## Compiler
Depuis la racine du dépôt, sous Linux (sous Windows : `build-windows.cmd`,
mêmes options) :
```bash
./build-windows.sh            # incrémental
./build-windows.sh --clean    # depuis zéro
./build-windows.sh --test     # construit aussi raw_hive_test.exe et les harnais de build-windows/tests/
# -> build-windows/WAC.exe
```

Le script choisit la chaîne selon le système — le compilateur préfixé
`x86_64-w64-mingw32-` sous Linux, le `g++` du chemin sous Windows — et vérifie
qu'elle produit bien des programmes Windows 64 bits (`-dumpmachine`) avec des
threads « win32 » (`-v`). Jamais de repli : sous Linux, un `g++` sans préfixe
produirait un programme Linux.

La compilation est reproductible pour une même version de GCC : les mêmes
sources donnent le même `WAC.exe`, octet pour octet. Deux versions de GCC
différentes, ou deux constructions de la même (Debian et MinGW-Builds), peuvent donner
deux exécutables différents, tous deux corrects : c'est `bin/SHA256SUMS`,
produit par la compilation livrée, qui fait foi.

## Ce que fait le script
1. Compile la ressource (version, icône, `wac.yml` de référence) : `WAC.rc`,
   en UTF-8, passé à `windres` en page de code 65001, ses fins de ligne et le
   chemin de l'icône normalisés.
2. Compile chaque unité trouvée dans `sources/` (hors `*_test.cpp`) avec un
   en-tête de **compatibilité inclus d'office**.
3. Compile libyaml (lecture de `wac.yml`) et SQLite (bases des navigateurs), voir ci-dessous, en C.
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
code `doc/html` avec la même version), commiter.

## Ajouter une version de Windows, ou un format d'artefact

Ce que WAC sait des versions de Windows tient dans **une table**, `sources/artefact_catalogue.cpp` : pour chaque clé de `wac.yml`, le premier build où l'artefact existe, celui où il a disparu, ses formes successives (emplacement, format, converti ou non) et depuis quand sa source est toujours présente. Aucun autre fichier ne nomme une version.

- **Une nouvelle version de Windows** : ajouter sa ligne à `windowsReleases()` (premier et dernier build connus) ; si elle déplace ou change un artefact, ajouter une forme à cet artefact ; si elle en retire un, renseigner `untilBuild`. Tant que ce n'est pas fait, la version est traitée comme la dernière connue et signalée comme telle dans le journal d'investigation.
- **Un nouveau format** : ajouter la forme (avec `decoded` à faux tant que le décodeur n'existe pas : la pièce est alors collectée brute), puis le décodeur, reconnu par la signature ou la version interne du fichier.
- **Un nouvel artefact** : sa clé dans `wac.yml`, son interrupteur dans `artefactSwitches()` (`config.cpp`) et sa ligne dans la table — le test refuse une clé qui manque d'un côté.

Puis, depuis `sources/` :

```
g++ -std=c++17 -g -fsanitize=address,undefined -I. artefact_catalogue.cpp artefact_catalogue_test.cpp -o /tmp/act
/tmp/act wac.yml                                # la table est cohérente, et wac.yml la suit
/tmp/act wac.yml --dump > /tmp/artefacts.tsv
../doc/artefact-table.py /tmp/artefacts.tsv     # la table des manuels, FR et EN
../doc/build-docs.sh ../doc/user/documentation_FR.tex ../doc/user/documentation_EN.tex
```

`artefact-table.py` s'arrête si un texte de la table n'a pas sa traduction française : l'ajouter à son dictionnaire.

## Briques de compatibilité (dossier `third_party/`)
| Élément | Rôle |
|---|---|
| `compat-include/wac_mingw_compat.h` | Inclus d'office : `<filesystem>`, et les constantes que les en-têtes MinGW n'ont pas et que WAC utilise. |
| `libyaml-0.2.5/` | Lecture de `wac.yml` : les 4 fichiers du lecteur de libyaml 0.2.5, non modifiés (origine et empreinte dans `VENDORED.md`). |
| `sqlite-3.53.4/` | Lecture des bases des navigateurs : l'amalgamation SQLite 3.53.4, non modifiée (origine, SHA3-256 et options dans `VENDORED.md`) ; sa seule exclusion d'avertissement, `-Wno-unused-parameter`, est documentée dans `build-windows.sh`. |

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
x86_64-w64-mingw32-objdump -p build-windows/WAC.exe | grep "DLL Name"   # sous Windows (Git Bash, MinGW-Builds en tête du chemin) : objdump
```

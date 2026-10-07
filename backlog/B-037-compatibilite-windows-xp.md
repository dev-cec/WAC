# B-037 — Collecte compatible avec toutes les versions de Windows depuis XP SP1

| Statut | Priorité | Effort |
|---|---|---|
| à faire (en dernier ; prérequis : B-039) | P3 | fort |

## Pourquoi
Les machines examinées ne sont pas toutes récentes : postes industriels, caisses, serveurs oubliés tournent encore sous Windows XP, Server 2003, Vista ou 7. WAC est aujourd'hui développé et éprouvé sur Windows 10 et 11. Demande utilisateur du 2026-10-02 : la collecte doit fonctionner depuis Windows XP SP1. Pas prioritaire, à faire après les autres fiches.

## Source
Tout ce que la collecte touche sur la machine examinée :
- **le binaire lui-même** : fonctions de l'API Windows absentes de XP (bcrypt, `GetTickCount64`, `CreateFile2`, fonctions de chaînes récentes, chemins longs…) — un import manquant empêche WAC de démarrer ; runtime MinGW statique et sous-système (version minimale du PE) ;
- **les emplacements** : `Documents and Settings\<compte>`, `Local Settings\Temporary Internet Files`, `Application Data`, ruches et profils de XP ;
- **les formats anciens** : journaux d'événements `.evt` (XP, 2003) au lieu de `.evtx`, Prefetch version 17, `index.dat` d'IE 5 à 8 (déjà lus, B-016), raccourcis et jump lists absents avant 7, SRUM et Amcache absents, ShimCache au format XP/2003, NTFS 3.0/3.1 ;
- **la lecture brute** : volumes, `\\.\X:` et droits sous XP.

- **l'architecture** : toutes les images disponibles sont 32 bits — un WAC.exe 64 bits ne s'y lance pas. Il faut une version **32 bits** de WAC (chaîne `i686-w64-mingw32`, paquet `g++-mingw-w64-i686`, à installer sur la machine de compilation : `sudo apt install g++-mingw-w64-i686`), avec `_WIN32_WINNT` et la version de sous-système du PE abaissées pour XP (5.01), et SQLite, libyaml et les tests compilés de même ;
- **un WAC 32 bits sur un Windows 64 bits** : redirection WOW64 de `System32` et du registre — la collecte d'un Windows 64 bits reste le travail du WAC 64 bits ; le 32 bits sert les Windows 32 bits.

## Sortie attendue
Deux binaires, WAC.exe (64 bits) et WAC32.exe (32 bits), des mêmes sources : le 32 bits démarre et collecte de XP SP1 à Windows 8 32 bits, le 64 bits de Vista 64 bits à Windows 11 ; chaque artefact absent d'une version le dit (`CollectionStatus`) au lieu d'échouer.

## Référence indépendante
Une VM par version passée par le harnais (création sans interaction comme `create-vm.sh`, agent invité — qemu-guest-agent n'existe pas pour XP : un autre canal sera nécessaire), avec les outils de référence déjà utilisés (EZ, plaso/libyal) sur les mêmes pièces.

Images ISO disponibles, toutes 32 bits, dans `vmtest/tools/isos/` (non versionné) :
- Windows XP Professionnel RTM, SP1, SP2 et SP3 (x86) ;
- Windows 8 (x86).
Une seule VM par version suffit, en 32 ou en 64 bits : les artefacts sont les mêmes dans les deux architectures (décision utilisateur du 2026-10-02). Le WAC 32 bits est éprouvé sur les versions fournies en 32 bits (XP, 8), le WAC 64 bits l'est déjà sur Windows 10 et 11. Manquent pour couvrir l'historique : Server 2003, Vista, 7 et 8.1, dans l'une ou l'autre architecture.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- WAC.exe se charge sur XP SP1 : aucune importation absente (vérifiée sur le PE et par un lancement réel).
- Chaque artefact propre à une version récente est déclaré absent sur les anciennes, jamais en échec.
- Les formats anciens rencontrés (au moins `.evt`) sont convertis ou déclarés non pris en charge, avec leur raison.

## Tâches
- [ ] Chaîne 32 bits (`g++-mingw-w64-i686`) et build-windows.sh produisant aussi WAC32.exe (SQLite, libyaml, tests)
- [ ] Inventaire des importations de WAC.exe et de leur disponibilité par version
- [ ] VM XP SP1 (et autres versions) dans le harnais, canal de pilotage sans qemu-guest-agent
- [ ] Emplacements XP (Documents and Settings…)
- [ ] Journaux `.evt`
- [ ] Prefetch v17, ShimCache XP/2003

## Journal
- 2026-10-02 : créée à la demande de l'utilisateur — compatibilité depuis Windows XP SP1, à faire en dernier.
- 2026-10-02 : décision utilisateur — une version de Windows suffit dans une seule architecture, 32 ou 64 bits, les artefacts étant les mêmes.
- 2026-10-02 : images ISO fournies par l'utilisateur (XP RTM, SP1, SP2, SP3, Windows 8 — toutes x86) ; une version 32 bits de WAC est nécessaire (demande utilisateur). La chaîne i686 a été installée par l'utilisateur le même jour (`i686-w64-mingw32-g++` 13, variante win32).
- 2026-10-06 : prérequis ajouté à la demande de l'utilisateur : B-039 (artefacts organisés par version de Windows et par disponibilité). Server 2003 relève aussi de B-038.
- 2026-10-07 : décision utilisateur — la rétrocompatibilité (B-037, B-038, avec B-039) constitue la version 3.0, après la 2.0.0 et l'article.

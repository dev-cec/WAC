# B-037 — Collecte compatible avec toutes les versions de Windows depuis XP SP1

| Statut | Priorité | Effort |
|---|---|---|
| en cours (64 bits : Windows 7 et 8.1 collectés ; reste le 32 bits, XP et Vista) | P3 | fort |

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

Images ISO disponibles dans `vmtest/tools/isos/` (non versionné) :
- Windows XP Professionnel RTM, SP1, SP2 et SP3 (x86) ;
- Windows 7 Ultimate SP1 (x64) ;
- Windows 8 (x86) ;
- Windows 8.1 (x64, néerlandais) ;
- virtio-win 0.1.173 et 0.1.189, dont Windows 7 et 8.1 acceptent les pilotes.
Server 2003 (standard et SP1) est dans `~/Téléchargements`.
Une seule VM par version suffit, en 32 ou en 64 bits : les artefacts sont les mêmes dans les deux architectures (décision utilisateur du 2026-10-02). Le WAC 32 bits est éprouvé sur les versions fournies en 32 bits (XP, 8), le WAC 64 bits l'est déjà sur Windows 10 et 11. Manque pour couvrir l'historique : Vista.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- WAC.exe se charge sur XP SP1 : aucune importation absente (vérifiée sur le PE et par un lancement réel).
- Chaque artefact propre à une version récente est déclaré absent sur les anciennes, jamais en échec.
- Les formats anciens rencontrés (au moins `.evt`) sont convertis ou déclarés non pris en charge, avec leur raison.

## Tâches
- [x] Chaîne 32 bits (`g++-mingw-w64-i686`) et build-windows.sh produisant aussi WAC32.exe (SQLite, libyaml, test des équivalents XP), copié dans `bin/`
- [x] Importations de WAC.exe (64 bits) confrontées aux exports de Windows 7 SP1 : 285 fonctions, une seule absente, corrigée
- [x] Inventaire du 32 bits sous XP SP1 : 14 fonctions absentes sur 271 (voir le journal)
- [x] Les 14 importations levées (`xp_imports.cpp`) ; la compilation refuse toute importation absente de XP SP1
- [x] VM Windows 8 Pro x86 (`create-vm.sh win8`) ; WAC32 y collecte et convertit sans échec
- [ ] WAC32 lancé sous XP SP1 réel : VM XP, canal de pilotage sans agent
- [ ] Même inventaire sous Windows 8 x86 et Vista
- [x] VM Windows 8.1 et Windows 7 SP1 (x64) créées sans interaction (`create-vm.sh win81`, `win7`), agent invité compris
- [x] WAC 64 bits collecte et convertit sous Windows 8.1 et Windows 7 SP1, sans échec
- [ ] Cycle du harnais (`run-wac-test.sh`) sur ces deux VM : témoins et contrôles à adapter à la version
- [ ] VM XP SP1 et Windows 8 (x86) dans le harnais ; canal de pilotage sans qemu-guest-agent pour XP
- [ ] Console sous Windows 7 : la bannière sort en caractères illisibles (police de la console)
- [ ] Emplacements XP (Documents and Settings…)
- [ ] Journaux `.evt`
- [ ] Prefetch v17, ShimCache XP/2003

## Journal
- 2026-10-02 : créée à la demande de l'utilisateur — compatibilité depuis Windows XP SP1, à faire en dernier.
- 2026-10-02 : décision utilisateur — une version de Windows suffit dans une seule architecture, 32 ou 64 bits, les artefacts étant les mêmes.
- 2026-10-02 : images ISO fournies par l'utilisateur (XP RTM, SP1, SP2, SP3, Windows 8 — toutes x86) ; une version 32 bits de WAC est nécessaire (demande utilisateur). La chaîne i686 a été installée par l'utilisateur le même jour (`i686-w64-mingw32-g++` 13, variante win32).
- 2026-10-06 : prérequis ajouté à la demande de l'utilisateur : B-039 (artefacts organisés par version de Windows et par disponibilité). Server 2003 relève aussi de B-038.
- 2026-10-07 : décision utilisateur — la rétrocompatibilité (B-037, B-038, avec B-039) constitue la version 3.0, après la 2.0.0 et l'article.
- 2026-10-13 : mesure faite pendant B-039 — WAC 2.0 (64 bits) se lance et va au bout sous **Windows 8.1 x64** sans modification (collecte et conversion, 74 JSON) ; VM `win81-test` créée par `create-vm.sh win81`. ISO disponibles dans `vmtest/tools/isos` : XP RTM, SP1, SP2, SP3 (x86), Windows 7 Ultimate x64, Windows 8 (x86), Windows 8.1 (x64, néerlandais) ; Vista manque. Windows 8 et XP sont en 32 bits : ils demandent WAC32. virtio-win 0.1.189 (pilotes signés pour 7 et 8.1) est dans le même dossier.
- 2026-10-13 : démarrage par le 64 bits, avec les ISO de `vmtest/tools/isos`. VM **Windows 7 SP1 Ultimate x64** (`create-vm.sh win7` : BIOS et disque MBR, fichier de réponses sans les réglages apparus avec Windows 8, fuseau horaire, virtio-win 0.1.173 — la dernière qu'un Windows 7 sans la mise à jour SHA-2 accepte). L'agent livré avec cette version tombe sur une commande contenant `%` (le harnais devra l'éviter sur cette VM) ; redémarrage automatique du service réglé dans la VM.
- 2026-10-13 : deux défauts empêchaient WAC de travailler sous Windows 7, corrigés :
  - WAC.exe ne se chargeait pas (« point d'entrée introuvable ») : il importait `GetSystemTimePreciseAsFileTime`, apparue avec Windows 8. Contrôle fait sur les 285 fonctions importées, confrontées aux exports des six DLL de la VM (kernel32, advapi32, bcrypt, secur32, wtsapi32, msvcrt) : c'était la seule absente. Elle est maintenant résolue à l'exécution, avec repli sur `GetSystemTimeAsFileTime`.
  - L'état du réseau n'était pas relevé (« paramètre incorrect ») : `LoadLibraryExW` refuse `LOAD_LIBRARY_SEARCH_SYSTEM32` sous un Windows 7 sans la mise à jour KB2533623. Repli sur le chemin absolu de System32 (vaut aussi pour `winhttp.dll` et `esent.dll`).
- 2026-10-13 : résultat sous Windows 7 SP1 (build 7601) : collecte en 82 s, conversion en 14 s, 73 JSON valides, aucun échec. Cinq artefacts déclarés absents de la version (Chronologie, BAM, Defender, PSReadLine, SRUM) ; déclarés « format non pris en charge » : ShimCache (0xBADC0FEE), les 69 Prefetch (version 23), les 5 caches de miniatures (disposition de Vista et 7), Amcache (`RecentFileCache.bcf`), BITS, index de recherche. État du réseau : 35 connexions, 18 voisins, 3 interfaces, 20 routes. Ce sont autant de décodeurs à écrire pour que ces versions rendent leurs traces, à chiffrer fiche par fiche.

- 2026-10-13 : essai de compilation 32 bits (`i686-w64-mingw32-g++` 13, dans un dossier temporaire, sans toucher à `bin/`) : les 111 unités de WAC, libyaml et SQLite compilent sans une erreur ni un avertissement. L'édition de liens échoue sur une seule référence : `WTSEnumerateProcessesExW`, absente de la bibliothèque d'import 32 bits de MinGW — et de toute façon apparue avec Vista : importée, elle empêcherait WAC32 de se charger sous XP. Elle devra être résolue à l'exécution, avec repli sur `WTSEnumerateProcessesW` (XP) ; c'est le premier point de l'inventaire des importations 32 bits.
- 2026-10-13 : propriétaires des processus lus par `WTSEnumerateProcessesW` (depuis XP) au lieu de `WTSEnumerateProcessesExW` (depuis Windows 7) : mêmes lignes — session, PID, nom, SID —, et la déclaration faite à la main disparaît. Avec ce changement, un **WAC32.exe d'essai se lie** (12,2 Mo, 271 fonctions importées de six DLL). Reste à le confronter aux exports de XP et de Windows 8 x86 : `bcrypt.dll` n'existe pas sous XP.
- 2026-10-13 : inventaire des importations du WAC32 d'essai contre **Windows XP SP1** (DLL extraites de l'ISO : kernel32, advapi32, secur32, wtsapi32, msvcrt — build 5.1.2600.1106). 14 fonctions sur 271 manquent :
  - `bcrypt.dll` tout entière (6 fonctions, AES des condensats de la SAM) : n'existe que depuis Vista. Elle ne sert qu'à la conversion, qui ne se fait pas sur la machine examinée : à charger à l'exécution, comme `esent.dll`.
  - `InitializeConditionVariable`, `SleepConditionVariableCS`, `WakeConditionVariable`, `WakeAllConditionVariable`, `GetThreadId` : variables de condition et fils d'exécution de la bibliothèque C++ (parallélisation de la collecte), apparus avec Vista.
  - `GetTickCount64`, `CompareStringOrdinal` (Vista), `wcsncpy_s` (msvcrt de Vista).
  Tout le reste — fichiers, volumes, jetons, sessions LSA, services, instantané des processus — existe sous XP SP1.

- 2026-10-13 : cycle complet Windows 11 après les deux correctifs Windows 7 : 499 contrôles réussis, aucun échec ; commité.
- 2026-10-13 : `WTSEnumerateProcessesW` vérifiée sous Windows 7 et 8.1 : 36 et 35 processus, tous avec leur SID sauf le processus inactif, `lsass.exe` compris (S-1-5-18).

- 2026-10-13 : cycle complet Windows 11 avec `WTSEnumerateProcessesW` et sans le faux prérequis : 499 contrôles réussis, 135 propriétaires lus sur 136 processus comme auparavant ; commité.
- 2026-10-13 : **WAC32.exe**. `build-windows.sh` refait la compilation en 32 bits (unités en parallèle), lie `WAC32.exe` et le copie dans `bin/` ; les gardes d'importation (réseau, résolution de noms, lancement de processus) portent sur les deux exécutables. Les 14 fonctions que XP n'a pas sont définies par `sources/xp_imports.cpp` sous le nom que cherche l'éditeur de liens (fonction et pointeur d'importation) : chacune appelle la fonction du système quand elle existe, un équivalent sinon — variables de condition faites d'un compteur et d'un sémaphore, `GetThreadId` par `NtQueryInformationThread`, `CompareStringOrdinal` par `RtlUpcaseUnicodeChar`, `GetTickCount` 32 bits, `wcsncpy_s` écrite, `bcrypt.dll` chargée à l'exécution (absente : `STATUS_NOT_SUPPORTED`). Piège rencontré : ces définitions ne peuvent pas employer de variable statique locale, que la bibliothèque C++ garde… par les variables de condition qu'elles définissent. Le fichier est vide en 64 bits.
  - Garde de compilation : chaque importation de WAC32 est confrontée à la liste des exports de XP SP1 (`third_party/windows-xp-sp1/exports.txt`, 2 555 noms tirés de l'ISO) ; 259 importations, aucune absente, plus de `bcrypt.dll`.
  - Test `xp_imports_test.exe` (32 bits, lancé dans la VM Windows 11) : 22 contrôles — 6 936 comparaisons de chaînes identiques à `CompareStringOrdinal`, identifiants de fil identiques, `wcsncpy_s` identique à celle de `msvcrt.dll`, file d'attente à un producteur et quatre consommateurs (20 000 éléments reçus une fois chacun), délai d'attente respecté, `WakeAll`. Vu échouer sur une copie mutée (majuscules par `towupper` : 8 comparaisons fausses ; `WakeAll` ne libérant qu'un fil : consommateurs restés en attente).
  - Deux avertissements propres au 32 bits (faux positifs de gcc dans la bibliothèque standard) supprimés par deux réécritures locales (`ese_database.cpp`, `trust_set.cpp`).
- 2026-10-13 : VM **Windows 8 Pro x86** (build 9200), `create-vm.sh win8`. Sous la machine q35, son Setup affiche sa première page puis ne prend ni touche ni clic ; sous i440FX (`pc`) l'installation se fait seule. Le pilote du canal de l'agent est désormais posé par `guest/install-agent-driver.ps1`, porté par le support du fichier de réponses (l'éditeur approuvé d'après le catalogue signé, puis `pnputil`) : vérifié sur cette VM, sans question posée. La création de bout en bout avec ce script reste à rejouer.
- 2026-10-13 : **WAC32 sous Windows 8 x86** : collecte en 60 s, conversion en 13 s, 74 JSON valides, aucun échec. Version lue (build 9200), trois artefacts absents de la version ; ShimCache déclaré avec la signature « 00ts » (0x73743030, mesurée), 45 Prefetch (version 26), Amcache, BITS et index de recherche déclarés non pris en charge. Condensats NT de la SAM déchiffrés (donc `bcrypt.dll` bien chargée à l'exécution). 62 435 enregistrements `$MFT`, 2 478 événements, 37 processus.

- 2026-10-13 : cycle complet Windows 11 avec ce build : 497 contrôles réussis, aucun échec ; commité. Deux contrôles de moins qu'au cycle précédent, pour une raison étrangère à WAC : Windows a purgé son dossier Prefetch arrivé à 512 fichiers (257 suppressions en une minute au journal USN), et le recoupement UserAssist/Prefetch n'avait plus de programme commun.

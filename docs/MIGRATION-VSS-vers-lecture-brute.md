# Migration WAC : VSS → lecture brute du volume (NTFS/MFT)

> Objectif : remplacer la collecte des ruches via **Volume Shadow Copy** par une
> **lecture brute en lecture seule** du volume, afin de minimiser l'empreinte
> forensique sur le système investigué.

## État au 2026-09-15

| | Statut |
|---|---|
| VSS | **supprimé** — lecture brute du volume (§2 à §8) |
| COM | **supprimé** — dernier consommateur (`scheduledTasks`) basculé hors ligne (§14.13) |
| Ruches « dirty » | **résolu** — patch documenté du bloc de base d'une COPIE (§4.1ter) |
| Bascule hors ligne des collecteurs | **achevée** (§9.4ter, §14.13 à §14.15) |
| Horodatages | **une source de vérité unique**, le fuseau du suspect (§14.5, §14.14) |
| Sortie JSON | 24 fichiers conformes, contrôles croisés verts (`vmtest/`) |

**Ne reste en collecte live** que ce dont l'objet *est* l'instant de la collecte :
`processes`, `sessions` — plus `events`, seul collecteur dont une source hors
ligne existe sans être encore exploitée (**§14.3**, le dernier chantier de la
migration : il supprimerait la dernière sollicitation d'un service du système
examiné, les vingt minutes d'attente et le pic de 473 Mo).

Chantiers ouverts, hors migration : complétude des formats (**§14.4**, liste de
travail fournie par les avertissements du compilateur), non-régression du contenu
par instantané de référence (**§14.2**).

> **Avertissement de lecture.** Les sections §14.x consignent les défauts trouvés
> *et corrigés*, avec leur cause. Elles se lisent comme un journal de bord, pas
> comme une liste de bogues ouverts : ce qui reste à faire est marqué comme tel.

---

## 1. Contexte et motivation

### Méthode actuelle (`vss.cpp` / `GetSnapshots`)
Le flux actuel est :

1. `CreateVssBackupComponents` + `SetContext(VSS_CTX_BACKUP)` + `SetBackupState(..., VSS_BT_COPY)`
2. `StartSnapshotSet` / `AddToSnapshotSet("c:\\")` / `DoSnapshotSet`
3. `CreateSymbolicLink(C:\Windows\temp\{guid} → \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\)`
4. `OROpenHive("{mountpoint}\Windows\system32\config\SYSTEM")` (et SOFTWARE, UsrClass.dat…)
5. `RemoveDirectoryW(mountpoint)`

### Traces laissées (à éliminer)
| Source | Trace | Journal concerné |
|---|---|---|
| VSS | Création/suppression du shadow | `Microsoft-Windows-VolumeSnapshot-Driver/Operational` |
| VSS | Événements service (8224…) | Journal `Application`, source `VSS` |
| VSS (writers) | Événements ESENT | `Application` |
| VSS | Écritures NTFS | `$LogFile`, `$UsnJrnl:$J` |
| `CreateSymbolicLink` | Reparse point créé | `$MFT`, `$LogFile`, `$UsnJrnl` |
| `RemoveDirectoryW` | Suppression | `$LogFile`, `$UsnJrnl` |

### Méthode cible
Lecture brute des clusters du volume via un handle `\\.\C:` ouvert en **lecture
seule**, parsing des structures **NTFS** ($BOOT, $MFT, data runs de l'attribut
`$DATA`), extraction des octets des ruches directement, sans passer par
l'ouverture de fichier du système (donc sans verrou, sans VSS, sans symlink).

**Empreinte** : lecture seule de secteurs → aucune écriture `$LogFile`/`$UsnJrnl`,
pas de mise à jour du *last access*, aucun événement VSS.

> ⚠️ Rappel déontologique : le but est de **minimiser et documenter** l'empreinte,
> pas de l'effacer (ce qui relèverait de l'anti-forensique). Lancer `WAC.exe`
> touchera toujours Prefetch, mémoire, `$UsnJrnl` pour les fichiers de sortie, etc.

---

## 2. Principe technique

### 2.1 Ouverture du volume (lecture seule)
```cpp
HANDLE hVol = CreateFileW(
    L"\\\\.\\C:",
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // ne pas verrouiller
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,       // pas d'écriture
    NULL);
```
- Nécessite les privilèges **administrateur** (accès volume brut).
- `FILE_FLAG_NO_BUFFERING` impose des lectures alignées sur la taille de secteur
  (lire par multiples de `bytesPerSector`, buffers alignés).

### 2.2 Chaîne de parsing NTFS
1. **VBR / $BOOT** (secteur 0 du volume) → `bytesPerSector`, `sectorsPerCluster`,
   `MFT cluster` (offset 0x30), `clustersPerFileRecordSegment` (offset 0x40).
2. **$MFT** : lire l'enregistrement 0 pour obtenir les data runs de `$DATA` du
   `$MFT` lui-même, puis parcourir/atteindre l'enregistrement de la ruche cible.
3. **Résolution du chemin** : soit parser `$MFT`+`$INDEX_ROOT`/`$INDEX_ALLOCATION`
   des répertoires pour descendre `\Windows\System32\config\`, soit (plus simple)
   scanner les enregistrements `$MFT` et matcher `$FILE_NAME` + parent reference.
4. **Enregistrement de la ruche** : lire l'attribut `$DATA` non résident, décoder
   les **data runs** (longueur + LCN delta), lire les clusters correspondants.
5. Écrire les octets vers la destination de collecte (disque externe / réseau),
   puis `OROpenHive()` sur la copie extraite.

### 2.3 Décodage des data runs (cœur du parseur)
```
Chaque run : 1 octet header = (nibble_haut = taille champ offset)(nibble_bas = taille champ longueur)
  - lire `longueur` clusters (little-endian, taille = nibble_bas)
  - lire `offset` LCN signé (little-endian, taille = nibble_haut) → delta vs LCN précédent
  - header == 0x00 → fin
  - offset absent (nibble_haut=0) → run sparse (zéros), à gérer si ruche fragmentée sparse
```

---

## 3. Options d'implémentation

| Option | Effort | Dépendances | Remarques |
|---|---|---|---|
| **A. Parseur NTFS minimal maison** | Moyen | aucune | ~300-500 lignes ; contrôle total ; à tester sur volumes fragmentés/compressés |
| **B. libtsk (The Sleuth Kit)** | Faible | libtsk (LGPL) | `tsk_fs_open` → `tsk_fs_file_open` → `tsk_fs_file_read` ; éprouvé, gère MFT/runs |
| **C. Bibliothèque libfsntfs (libyal)** | Faible | libfsntfs | API dédiée NTFS ; très robuste |

**Recommandation** : commencer par **B (libtsk)** pour fiabiliser vite, garder
l'option A en tête si l'on veut zéro dépendance externe dans le binaire de collecte.

---

## 4. Plan de refactoring dans WAC

### 4.1 Nouveau module `raw_hive.cpp` / `raw_hive.h`
Interface cible (miroir de l'usage actuel de `GetSnapshots`) :
```cpp
// Extrait une ruche du volume brut vers un fichier local, sans VSS.
// volumeLetter : L"C"
// hivePathOnVolume : L"\\Windows\\System32\\config\\SYSTEM"
// outFile : chemin de sortie (répertoire de collecte)
HRESULT ExtractHiveRaw(const std::wstring& volumeLetter,
                       const std::wstring& hivePathOnVolume,
                       const std::wstring& outFile);
```

### 4.1bis État : module implémenté (parseur maison, à valider sur Windows)
`WAC/raw_hive.{h,cpp}` est écrit (Option A, ~340 lignes, zéro dépendance) et
**compile** dans la chaîne Linux. Il fait : ouverture `\\.\C:` lecture seule →
VBR → bootstrap `$MFT` (fragmenté) → résolution de chemin via `$INDEX_ROOT` +
`$INDEX_ALLOCATION` → extraction `$DATA` (résident, non résident, runs sparse),
avec fixups (Update Sequence Array) appliqués.

**Interface réelle** : `ExtractFileRaw(volumeLetter, filePathOnVolume, outFile)`
(+ `RawHiveSetVerbose`). Exe de test : `raw_hive_test.exe` (`build-windows.sh --test`).

**⚠️ Validation requise sur Windows réel** (impossible depuis Linux) :
```
raw_hive_test.exe C \Windows\System32\config\SYSTEM SYSTEM.hiv
# comparer le hash de SYSTEM.hiv avec une extraction de référence (VSS/FTK Imager)
```
Ne **pas** câbler dans `main.cpp` (ni retirer VSS) avant ce test hash concluant.

**État réel, testé sur Windows 11 25H2 en VM (2026-09-14)** — corrige une
affirmation antérieure erronée (« validé » avait été inscrit sur un retour de test
mal interprété ; l'extraction ne fonctionnait en réalité pas encore) :

1. **Bug corrigé — `findAttr()` et les index de répertoires.** La fonction n'acceptait
   que les attributs **non nommés** (`p[9]==0`). C'est correct pour `$DATA` (viser le
   flux principal, pas un ADS) mais **faux** pour `$INDEX_ROOT`/`$INDEX_ALLOCATION`,
   qui portent **toujours** le nom `"$I30"` → aucun répertoire n'était listable et
   `resolvePath` échouait systématiquement (`ERROR_FILE_NOT_FOUND`).
   `findAttr` prend désormais un paramètre `unnamedOnly` (vrai pour `$DATA`, faux
   pour les index).
2. **Extraction désormais fonctionnelle** : résolution complète
   `racine(MFT#5) → Windows(#3750) → System32(#5797) → config(#5842) → SYSTEM`,
   et extraction de SYSTEM (14 942 208 o), SOFTWARE (92 012 544 o), Amcache.hve,
   ntuser.dat et UsrClass.dat. En-tête `regf` valide, nom de ruche correct.
3. **Bug corrigé — affichage** : sous MinGW/msvcrt, `%s` dans les `*w*printf` attend
   une chaîne **étroite** ; il faut `%ls` pour les `wchar_t*` (diagnostics tronqués).

### ✅ §4.1ter RÉSOLU : module `hive_recover` (2026-09-14)
Le **rejeu des journaux est impossible** sur une copie à chaud — mesuré : ruche à
`0x6e2/0x6e3`, journaux couvrant seulement `0x720→0x730` (écart de ~62). Les `.LOG`
ne contiennent que les entrées *depuis le dernier flush*, le bloc de base sur disque
étant bien plus ancien. L'option A est donc écartée **par l'expérience**.

`offreg` ne propose aucun mode tolérant : `OROpenHive`, `OROpenHiveByHandle(0)` et
`OROpenHiveByHandle(OFFREG_OPEN_READ_ONLY)` renvoient tous **1009 (ERROR_BADDB)**.

**Solution retenue et vérifiée** — `WAC/hive_recover.{h,cpp}` : aligner
`secondaire := primaire` et recalculer le checksum du bloc de base (XOR des 127
premiers uint32, à l'offset 508). C'est le « chargement de ruche dirty » des outils
du domaine. Résultat mesuré sur la ruche SYSTEM ainsi traitée :
`OROpenHive` → 0, racine = **17 sous-clés** attendues, `Select\Current` = 1 (REG_DWORD),
`ControlSet001\Services` = **739 services** → **données cohérentes**.

**Garde-fous forensiques** (implémentés) :
- **MD5 de la copie brute calculé AVANT le patch** et consigné ;
- séquences d'origine, checksum avant/après et patch consignés → la copie brute est
  **reconstructible à l'octet** (le patch ne touche que 8 octets du bloc de base) ;
- les **journaux `.LOG1/.LOG2` sont extraits** à côté : artefacts à part entière, et
  trace de ce qui n'est PAS appliqué dans la ruche ;
- module **portable** (C++ pur) : testé sous Linux contre la vraie ruche, patch
  identique à l'octet et **idempotent**.

Extrait réel du journal WAC :
```
SYSTEM : dirty séq 0x6e3/0x6e2 -> aligné 0x6e3, checksum 0xfd1aff82 -> 0xfd1aff83 [patch appliqué]
MD5 copie brute (avant patch) : 935070847B9F9AAB237D90E48826120F
Ruches remises en état : 4, échecs : 0
```

### ⛔ (historique) BLOQUANT identifié : ruches « dirty » (et ce que VSS masquait)
Une copie brute d'une ruche d'un système **en fonctionnement** est forcément
**incohérente** : numéros de séquence primaire ≠ secondaire (observé : `0x06e3` vs
`0x06e2`), les modifications en attente résidant dans les **journaux de transaction**.
Conséquence mesurée : **`OROpenHive` échoue** sur la ruche extraite (et `reg load`
répond « Registre de configuration endommagé ») → `main.cpp` fait `return` et WAC
s'arrête juste après l'extraction (seuls les JSON de la phase live sont produits).

**Ce que VSS apportait sans qu'on le réalise** : le snapshot déclenchait le *registry
writer*, qui **flushait** les ruches → on obtenait des ruches **propres**. La lecture
brute n'a pas ce service. Ce n'est donc pas un simple détail (§5.3) mais un
**prérequis** de la migration.

**Options (par ordre de pertinence forensique)** :
- **A. Rejouer les journaux de transaction** (`SYSTEM.LOG1/.LOG2`, etc.). Ils sont
  **extractibles en lecture brute** — vérifié : `SYSTEM.LOG1` = 294 912 o,
  `SYSTEM.LOG2` = 3 748 864 o. Appliquer les pages sales puis corriger les séquences
  produit une ruche propre, acceptée par `offreg`. Méthode des outils du domaine
  (yarp, Registry Explorer). **Recommandé.**
- **B. Écrire notre propre parseur de ruches**, tolérant au dirty et rejouant les
  journaux. Plus de travail, mais supprime la dépendance à `offreg.dll` — cohérent
  avec l'objectif « ne pas faire confiance aux DLL du suspect » (§9) et avec
  l'exe unique.
- **C.** Forcer la séquence secondaire = primaire pour faire accepter la ruche :
  **à écarter** — cela masque des modifications non appliquées, donc falsifie l'état.

**✅ Intégré (2026-09)** : VSS **supprimé** (vss.cpp/vss.h/stdafx.* retirés) ;
`main.cpp` appelle `ExtractHivesRaw()` (`raw_collect.hpp`) à la place de `GetSnapshots`.
Les ruches sont extraites vers `<_outputDir>\hives` **sur la clé USB** (plus de
point de montage ni d'écriture sur l'hôte) ; `conf.mountpoint` sert désormais de
simple préfixe vers ce répertoire, donc tout le pipeline `OROpenHive` est inchangé.
Ruches extraites : SYSTEM, SOFTWARE, Amcache.hve, et par profil ntuser.dat +
UsrClass.dat. Ouverture du volume **une seule fois** pour tous les fichiers
(`ExtractFilesRaw`). Build : `vss.cpp`/`stdafx.cpp` retirés, `-lvssapi` retiré,
`VSSAPI.dll` **absent** des imports.

**Limites connues (échec explicite, pas de corruption silencieuse)** :
- `$DATA` **compressé NTFS** → non géré (rare pour les ruches ; renvoie `ERROR_NOT_SUPPORTED`).
- Attributs éclatés via **`$ATTRIBUTE_LIST`** (fichiers très fragmentés) → non suivi
  (détecté et journalisé). À ajouter si des `.evtx`/gros fichiers le déclenchent.
- Transaction logs (`.LOG1/.LOG2`) non rejoués (cf. §5.3) — à extraire à part.

**⚠️ Conséquence du retrait de VSS — collecteurs basés sur des FICHIERS à migrer** :
sous VSS, `mountpoint` exposait **tout** le volume ; désormais il ne contient que
les **ruches extraites**. Les modules qui lisent des fichiers (non-ruches) via
`mountpoint` sont donc **temporairement sans données** tant que leur extraction
brute n'est pas ajoutée :
- `prefetchs.hpp` → `mountpoint\Windows\Prefetch\*.pf`
- `jumplist_automatic.hpp` / `jumplist_custom.hpp` → `...\AppData\...\*Destinations`
- `recent_docs.hpp` → fichiers `.lnk`
- `events.hpp` (EVTX) — cf. §10, à remplacer par le parseur embarqué
À faire : étendre `ExtractHivesRaw`/`raw_hive` pour extraire aussi ces fichiers (et
répertoires) par lecture brute NTFS. Les collecteurs **registre** (la majorité)
fonctionnent, eux, dès maintenant (ruches extraites).

### 4.2 Points de modification dans `main.cpp`
- **Supprimer** l'appel `GetSnapshots(&snapshotSetId, pBackup)` (~ligne 332).
- **Supprimer** le `RemoveDirectoryW(conf.mountpoint)` (~ligne 635).
- Remplacer la construction des chemins basés sur `conf.mountpoint` :
  - `conf.mountpoint + L"\\Windows\\system32\\config\\SYSTEM"` (l.365)
  - `... SOFTWARE` (l.378)
  - dans `reg_shellbags.hpp` (l.104) : `usrClass.dat` par profil
  → par un appel `ExtractHiveRaw(...)` produisant un fichier local, puis
    `OROpenHive()` sur ce fichier.
- `conf.mountpoint` peut être conservé et pointé vers le **répertoire d'extraction
  local** (ex. `conf._outputDir + L"\\hives"`) pour limiter les changements en aval :
  tout le reste du pipeline (`OROpenHive` sur `{mountpoint}\Windows\...`) continue
  de fonctionner si l'on recrée l'arborescence relative dans le répertoire local.

### 4.3 Chemins de ruches à couvrir
- `\Windows\System32\config\SYSTEM`
- `\Windows\System32\config\SOFTWARE`
- `\Windows\System32\config\SAM`
- `\Windows\System32\config\SECURITY`
- Par profil utilisateur (cf. `conf.profiles`) :
  - `\Users\<user>\NTUSER.DAT`
  - `\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat`

> Voir aussi la 2ᵉ analyse (shellbags) : penser à extraire **NTUSER.DAT ET
> UsrClass.dat**, les shellbags étant répartis sur les deux ruches.

### 4.4 Suppression / conservation de code
- `vss.cpp` / `vss.h` : à **retirer du build** (`WAC.vcxproj`) une fois `raw_hive`
  validé. Conserver en branche pour comparaison/repli.
- Vérifier qu'aucun autre `reg_*.hpp` n'ouvre une ruche **hors** `conf.mountpoint`
  (audit `grep -rn OROpenHive`).

---

## 5. Points de vigilance

1. **Ruches fragmentées** : les `$DATA` runs peuvent être multiples → bien
   concaténer dans l'ordre des VCN.
2. **Compression NTFS** : improbable sur les ruches système, mais gérer/ detecter
   l'attribut compressé (flag dans l'en-tête d'attribut) pour ne pas produire une
   copie corrompue.
3. **Cohérence transactionnelle** : la ruche lue sur disque peut être « sale »
   (dirty) ; les fichiers de **transaction logs** (`SYSTEM.LOG1/.LOG2`) doivent
   être extraits **aussi** et rejoués (ou laissés à l'outil d'analyse aval) pour
   obtenir un état cohérent. À documenter dans le rapport.
4. **Alignement secteur** (`FILE_FLAG_NO_BUFFERING`) : buffers alignés, tailles
   multiples du secteur.
5. **BitLocker** : si le volume est chiffré, l'accès brut à `\\.\C:` renvoie le
   **clair déchiffré** tant que le volume est monté/déverrouillé (le déchiffrement
   se fait sous la couche volume). OK pour la collecte live.
6. **Privilèges** : exiger l'élévation ; échouer proprement sinon.
7. **Documentation forensique** : journaliser précisément chaque secteur/fichier
   lu et chaque fichier de sortie écrit (hash), pour la chaîne de preuve.
8. **Exécution depuis une clé USB** (principe retenu) — voir §5bis.

## 5bis. Exécution depuis clé USB : ce que ça règle et ce que ça ne règle pas

Le binaire `WAC.exe` **et** le répertoire de sortie (`conf._outputDir`) résident sur
la **clé USB**, jamais sur le disque investigué. C'est la bonne pratique de
*live response* et elle se combine avec la lecture brute (§2).

**Ce que ça élimine (écritures sur C:) :**
- Aucune écriture du binaire ni des résultats sur le volume cible → pas d'entrées
  `$MFT` / `$LogFile` / `$UsnJrnl` liées à l'outil ou à sa sortie sur C:.
- Combiné à la lecture brute : plus de VSS, plus de symlink, plus de fichiers temporaires sur C:.

**Ce que ça n'élimine PAS (traces d'exécution inhérentes, sur C:) — à DOCUMENTER, pas à masquer :**
| Trace | Emplacement | Cause |
|---|---|---|
| `WAC.EXE-XXXXXXXX.pf` | `C:\Windows\Prefetch` | exécution (si Prefetch actif), quelle que soit l'origine USB |
| Entrée AmCache | `Amcache.hve` | premier lancement de l'exécutable |
| Entrée ShimCache | `SYSTEM` (au shutdown) | exécution enregistrée par AppCompat |
| Enrôlement du périphérique USB | `SYSTEM\...\USBSTOR`, `MountedDevices`, `SetupApi.dev.log`, journaux `Microsoft-Windows-Partition/Diagnostic` | branchement de la clé |
| Attribution de lettre de lecteur | `SYSTEM\MountedDevices` | montage du volume USB |

**Recommandations :**
- **Écrire la sortie et tout fichier temporaire sur la clé** (`conf._outputDir` sur
  le volume USB), jamais sur `%TEMP%`/C:.
- **Documenter l'empreinte de l'outil** : hash du binaire, **numéro de série de la
  clé USB**, VID/PID, horodatage de branchement et d'exécution → permet à
  l'examinateur de **distinguer les artefacts de l'investigateur** de l'activité du
  suspect (§ ordre de volatilité, RFC 3227).
- Envisager une clé en **lecture seule matérielle** pour le binaire (partition
  distincte inscriptible pour la sortie) afin de garantir l'intégrité de l'outil.
- Rappel : l'objectif reste **minimiser + documenter**, jamais effacer.

---

## 6. Tests de validation

- [ ] Comparer les hashs des ruches extraites en **brut** vs extraites en **VSS**
      (doivent correspondre hors zones dirty/logs).
- [ ] Vérifier via `Get-WinEvent`/Event Viewer qu'**aucun** événement
      `VolumeSnapshot-Driver` / `VSS` n'est généré pendant la collecte brute.
- [ ] Vérifier via un outil `$UsnJrnl` (ex. `MFTECmd`, `UsnJrnl2Csv`) l'absence
      de nouvelles entrées liées à la collecte (hors fichiers de sortie).
- [ ] Tester sur ruche **fragmentée** (volume rempli/défragmenté artificiellement).
- [ ] Tester sur volume **BitLocker** déverrouillé.
- [ ] Non-régression : sortie JSON identique entre les deux méthodes.

---

## 7. Horodatages : double sortie UTC + locale, et vérification de l'interprétation

### 7.1 Exigence de sortie (comportement WAC à conserver)
Pour **chaque date** de **chaque artefact**, produire **deux** valeurs :
- `<Champ>Utc` — l'horodatage en **UTC** ;
- `<Champ>` — le même horodatage en **heure locale**.

C'est déjà le comportement de WAC (ex. `lastWriteTime` / `lastWriteTimeUtc`,
`creationDate` / `creationDateUtc`) et il doit être **maintenu**.

### 7.2 ⚠️ Piège central : l'encodage natif n'est PAS toujours de l'UTC
La conversion correcte dépend du **format source** de l'horodatage. Convertir sans
vérifier l'encodage produit des dates **fausses** (décalées d'un ou deux fuseaux).
Il faut donc, **champ par champ**, identifier l'encodage avant toute conversion :

| Encodage source | Fuseau natif | Où on le rencontre | Conversion correcte |
|---|---|---|---|
| **Windows FILETIME** (64 bits, 100 ns depuis 1601) | **UTC** | `LastWriteTime` de clé de registre, `beef0026`, `VT_FILETIME` des SPS, la plupart des artefacts registre | brut = UTC ; local = appliquer le fuseau **suspect** |
| **FAT / DOS date-time** (32 bits) | **HEURE LOCALE** (de la machine qui a écrit) | données primaires des *file-entry shell items*, `beef0004` (create/access), `UsersFilesFolder` | brut = local ; UTC = appliquer l'**inverse** du fuseau suspect |
| **OLE VT_DATE** (double) | selon contexte (souvent local) | propriétés SPS `VT_DATE` | à trancher **cas par cas** |
| **Unix epoch** | UTC | rare | brut = UTC |

### 7.3 Bug actuel à corriger : le double décalage sur les dates FAT
Dans `idList.cpp`, `beef0004` (l.694-704) et `FileEntryShellItem` (l.2158-2162)
font, sur une valeur **FAT (donc locale)** :
```cpp
creationDateUtc = FatDateTime(...).to_filetime(); // FAT = heure LOCALE, mais nommée "...Utc"
FileTimeToLocalFileTime(&creationDateUtc, &creationDate); // re-décale une valeur déjà locale
```
Deux erreurs cumulées :
1. une valeur **locale** (FAT) est **étiquetée `...Utc`** → faux label ;
2. `FileTimeToLocalFileTime` applique un **second** décalage → `creationDate` est
   doublement offset.

À l'inverse, pour la `LastWriteTime` d'une **clé de registre** (vrai FILETIME UTC),
le `FileTimeToLocalFileTime` est **correct**.

➡️ Conclusion : **l'interprétation UTC/local doit être décidée par champ**, jamais
appliquée uniformément. Pour les dates FAT : le brut EST l'heure locale ; l'UTC se
calcule en **retirant** le biais du fuseau (et non en ajoutant).

### 7.4 Fuseau de référence : celui du suspect, pas de l'analyste
`FileTimeToLocalFileTime` (et `time_to_wstring`) utilisent le fuseau de la **machine
d'analyse**. En contexte judiciaire, la conversion doit s'appuyer sur le fuseau de
la **machine investiguée**, lu **hors ligne** dans la ruche SYSTEM collectée :

```
SYSTEM\ControlSet00X\Control\TimeZoneInformation
  → Bias, StandardBias, DaylightBias, ActiveTimeBias, StandardName/DaylightName
```
Recommandation : convertir **explicitement** avec ce biais plutôt que de dépendre du
fuseau de l'OS d'analyse. C'est cohérent avec la lecture brute : l'information de
fuseau provient de la même ruche SYSTEM extraite.

### 7.5 Format de sortie enrichi (recommandé)
Pour la traçabilité probante, idéalement documenter l'encodage et la source du fuseau :
```json
{
  "CreatedUtc":   "2026-03-02T14:05:11Z",
  "CreatedLocal": "2026-03-02T15:05:11+01:00",
  "SourceEncoding": "FAT_DOS",          // FILETIME | FAT_DOS | VT_DATE | UNIX
  "TZSource": "suspect(TimeZoneInformation)"  // suspect | analyst | raw
}
```
A minima : conserver `Utc` + local, **mais avec l'encodage correctement interprété**.

---

## 8. Audit systématique des artefacts (horodatage + traces)

Deux vérifications transverses à mener sur **tous** les modules `*.hpp` :

1. **Horodatage** — pour chaque champ date : quel encodage natif ? interprété
   correctement (cf. §7) ? double décalage éventuel ? fuseau suspect utilisé ?
2. **Traces** — le module lit-il un fichier **en direct** (hors jeu de ruches/artefacts
   déjà extraits en lecture brute) ? Si oui, il rouvre un chemin FS → empreinte à
   supprimer. Objectif : **toute** lecture passe par les données déjà collectées
   en brut (§2), aucune ouverture live résiduelle.

### Matrice d'audit (à compléter lors de la revue)
| Module | Champs date | Encodage natif | Interprétation actuelle | Correct ? | Lit un fichier live ? |
|---|---|---|---|---|---|
| `reg_shellbags.hpp` | LastWriteTime (clé) | FILETIME (UTC) | UTC→local | ✅ | non (via mountpoint) |
| `idList.cpp` (beef0004) | Created/Accessed | FAT (local) | traité comme UTC + reconv. | ❌ double décalage | — |
| `idList.cpp` (file-entry) | Modification | FAT (local) | traité comme UTC + reconv. | ❌ à vérifier | — |
| `idList.cpp` (beef0026) | c/m/a time | FILETIME (UTC) | à vérifier | ⏳ | — |
| `reg_amcache_*.hpp` | | à vérifier | | ⏳ | ⏳ |
| `reg_shimcache.hpp` | | à vérifier | | ⏳ | ⏳ |
| `reg_userassists.hpp` | | à vérifier | | ⏳ | ⏳ |
| `reg_bams.hpp` | | à vérifier | | ⏳ | ⏳ |
| `reg_usbstors.hpp` | | à vérifier | | ⏳ | ⏳ |
| `reg_mounted_devices.hpp` | | à vérifier | | ⏳ | ⏳ |
| `prefetchs.hpp` | | à vérifier | | ⏳ | ⏳ (fichiers .pf live) |
| `jumplist_*.hpp` | | à vérifier | | ⏳ | ⏳ (fichiers live) |
| `recent_docs.hpp` | | à vérifier | | ⏳ | ⏳ |
| `events.hpp` | | à vérifier | | ⏳ | ⏳ (EVTX live) |
| `schedulesTasks.hpp` | | à vérifier | | ⏳ | ⏳ |
| `sessions.hpp` / `users.hpp` | | à vérifier | | ⏳ | ⏳ |

> Légende : ✅ correct · ❌ bug confirmé · ⏳ à auditer.
> Étendre la liste à tous les `*.hpp` du projet (`grep -l OROpenHive\|CreateFile *.hpp`).

### Règle de sortie unifiée
Centraliser la conversion dans une seule fonction (ex. `emit_date(champ, valeurBrute,
encodage, biaisSuspect)`) qui émet le couple UTC/local **selon l'encodage**, afin
d'éliminer les traitements ad hoc dispersés (source des bugs de double décalage).

---

## 9. Collecte "live" vs offline : réduire l'empreinte d'exécution

> Précision : WAC n'utilise **pas** WSH (Windows Script Host). Ce qui laisse des
> traces d'exécution, c'est la **phase de collecte live** (`main.cpp:235-310`,
> avant le snapshot), qui interroge le système en cours d'exécution via **COM
> (Task Scheduler)**, des **API Win32** et des **lectures de registre live**.

### 9.1 Sources de traces de la collecte live
| Mécanisme | Où | Trace générée |
|---|---|---|
| COM Task Scheduler (`CoCreateInstance(CLSID_TaskScheduler)`) | `schedulesTasks.hpp` | sollicitation du service *Schedule*, journaux `TaskScheduler/Operational` |
| `CreateToolhelp32Snapshot` + `OpenProcess(PROCESS_ALL_ACCESS)` + `OpenProcessToken(TOKEN_ALL_ACCESS)` | `processes.hpp` | accès processus à privilège **maximal** → Sysmon EID 10 (ProcessAccess), alertes EDR, échecs sur processus protégés |
| `OpenSCManager` + `EnumServicesStatusExW` | `services.hpp` | accès SCM |
| `RegOpenKeyExW(HKLM…)` | `users.hpp` | lecture de la ruche **vivante** (incohérent avec l'approche offline) |
| API Event Log live | `events.hpp` | requêtes sur le service EventLog |
| COM init (`CoInitializeSecurity`) | `com.hpp` | support COM ; risque WMI-Activity/WmiPrvSE si étendu |

### 9.2 Principe : classer chaque artefact volatile vs persistant
**Règle** : tout artefact **persistant** (présent sur disque) doit être lu **hors
ligne** depuis les ruches/fichiers extraits en brut (§2). On ne conserve en **live**
que l'**irréductiblement volatile** (état mémoire perdu à l'extinction).

| Collecteur (`main.cpp`) | Volatile ? | Source offline | Recommandation |
|---|---|---|---|
| `systemInfo` (l.235) | partiel | `SYSTEM` / `SOFTWARE` (version OS, nom machine, install date, TZ) | offline ; garder live **uniquement** `GetSystemTime` pour horodater l'écart d'horloge à l'acquisition |
| `scheduledTasks` (l.246) | **non** | `\Windows\System32\Tasks\*` (XML) + `SOFTWARE\...\Schedule\TaskCache` | **supprimer le COM Task Scheduler** → parser XML + registre offline |
| `sessions` (l.258) | **oui** | (logons : `Security.evtx` offline) | live, ou dériver des EVTX offline |
| `processes` (l.270) | **oui** | — | live mais **réduire l'access mask** (§9.3) ; idéal : dump RAM → Volatility offline |
| `services` (l.283) | config : **non** | `SYSTEM\CurrentControlSet\Services` | config offline ; état *running* live seulement si requis |
| `users` (l.296) | **non** | `SOFTWARE\...\ProfileList` + `SAM` | **remplacer `RegOpenKeyEx` live par `OROpenHive`** sur ruches extraites |
| `events` (l.310) | **non** | `\Windows\System32\winevt\Logs\*.evtx` | extraire les EVTX en brut et **parser offline** (pas l'API EvtQuery live) |

### 9.3 Pour l'irréductiblement volatile : minimiser
1. **Réduire les droits demandés** : `PROCESS_QUERY_LIMITED_INFORMATION` au lieu de
   `PROCESS_ALL_ACCESS`, `TOKEN_QUERY` au lieu de `TOKEN_ALL_ACCESS`. Suffisant pour
   chemin image / PID / temps / utilisateur du token, et **beaucoup moins bruyant**
   (évite les masques d'accès dangereux repérés par Sysmon/EDR, et les échecs UAC).
2. **Préférer l'API Win32 directe à WMI** (WMI journalise `WMI-Activity/Operational`
   et fait apparaître `WmiPrvSE.exe`).
3. **Meilleure option forensique** : capturer une **image mémoire** complète et
   parser les artefacts volatils **hors ligne avec Volatility3** (processus, modules,
   connexions réseau, code injecté, processus cachés) — l'analyse quitte la machine
   vivante et va bien au-delà de ce que fournit Toolhelp.

### 9.4 Conséquence : COM devient supprimable — VÉRIFIÉ (2026-09-15)

Audit effectué : **WAC n'utilise ni WMI ni WSH**. Aucun `IWbem*` dans le code.
L'API réelle de chaque collecteur live :

| Collecteur | API réelle | Passe par COM ? |
|---|---|---|
| `processes` | `CreateToolhelp32Snapshot` | non |
| `sessions` | `LsaGetLogonSessionData` | non |
| `services` | `OpenSCManager` | non |
| `users` | `NetUserEnum` | non |
| `systemInfo` | `GetComputerNameExW` | non |
| `scheduledTasks` | `CoCreateInstance(CLSID_TaskScheduler)` | **oui — le seul** |

(`trans_id.cpp` n'appelle que `CLSIDFromString`, une conversion de chaîne.)

**Conséquence.** `scheduledTasks` est le seul consommateur de COM : le basculer
hors ligne permet de supprimer `com.connect()` / `com.clear()` **entièrement**.
Le garder en live ne mutualise rien — les traces ne se mutualisent pas, elles se
cumulent, chaque API laissant la sienne (`CreateToolhelp32Snapshot` ouvre des
handles, `OpenSCManager` peut produire des 7036, taskschd journalise dans son
propre canal). Retirer COM retire une catégorie entière de traces sans rien
changer aux autres collecteurs.

### 9.4bis Plan de bascule de `scheduledTasks` (à faire AVEC la suppression de COM)

Décidé le 2026-09-15 : bascule **complète**, pas par étapes. Par étapes, COM
resterait initialisé pour lire les définitions, et le gain principal — sa
suppression — ne serait pas obtenu.

Correspondance champ par champ :

| Champ émis aujourd'hui | Source hors ligne |
|---|---|
| `Name`, `Description`, `Author`, `Enabled`, `RunAs`, `RunAsSID`, `Actions`, `Triggers` | XML sous `\Windows\System32\Tasks\` (un fichier par tâche ; l'arborescence donne `Path`) |
| `LastRun`, `LastTaskResult` | valeur binaire `DynamicInfo` sous `SOFTWARE\…\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}` |
| `State` | mixte : « activé/désactivé » est dans le XML, « en cours d'exécution » est volatil |
| `NextRun`, `NumberOfMissedRuns` | **non stockés** : calculés à chaud par le planificateur |

`TaskCache\Tree\<chemin>` fournit le GUID et l'index de chaque tâche, ce qui
permet de recouper définition (XML) et historique (`DynamicInfo`).

Perte assumée : `NextRun` et `NumberOfMissedRuns`. Ce sont des **projections**,
pas des traces d'activité passée : aucune valeur probante.

Prérequis techniques :
1. **extraction brute récursive** — `\Windows\System32\Tasks\` est une
   arborescence, or `ExtractDirectoryRaw` ne descend pas dans les sous-dossiers ;
2. **lecteur XML minimal maison** — MSXML passerait par COM, ce qui annulerait le
   bénéfice. Faisable : ces fichiers ont une structure étroite et stable
   (`<RegistrationInfo>`, `<Triggers>`, `<Actions>`, `<Principals>`) ;
3. le défaut `$INDEX_ALLOCATION` (§14.10) doit être réglé d'abord : `Tasks\`
   contient des sous-dossiers à nombreuses entrées, soit exactement le cas qui
   échoue aujourd'hui.

### 9.4ter Plan de bascule hors ligne — TOUS les collecteurs (2026-09-15)

Objectif : ne garder en live que ce qui est **irréductiblement** volatil. Pour
chaque collecteur, la source hors ligne et la perte assumée.

#### `scheduledTasks` → voir §9.4bis (déclencheur de la suppression de COM)

#### `services` — `SYSTEM\CurrentControlSet\Services\<nom>`

| Champ | Valeur du registre |
|---|---|
| `Binary` | `ImagePath` |
| `StartType` | `Start` (0 Boot, 1 System, 2 Auto, 3 Manual, 4 Disabled) |
| `Type` | `Type` (1 pilote noyau, 2 pilote FS, 16 processus propre, 32 partagé) |
| `Owner` | `ObjectName` (LocalSystem, NT AUTHORITY\…) |
| `DisplayName` | `DisplayName` (peut être une référence MUI `@dll,-id`) |

**Perte : `Status` et `ProcessId`**, tous deux volatils. À noter : savoir qu'un
service tourne *au moment* de la collecte est une information réelle. La
définition reste le plus probant (`ImagePath`, `Start`, `ObjectName` révèlent la
persistance), mais la bascule n'est pas neutre ici — c'est le seul cas où
supprimer la trace coûte une donnée qui en est une. Un recoupement partiel est
possible via `processes` (déjà live et sans COM).

#### `systemInfo` — registre

| Champ | Source |
|---|---|
| `ComputerName` | `SYSTEM\…\Control\ComputerName\ComputerName` |
| `DomainName` | `SYSTEM\…\Services\Tcpip\Parameters\Domain` / `NV Domain` |
| `OsName` | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName` |
| `Version` | `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentBuild` |
| `OsArchitecture` | `SYSTEM\…\Session Manager\Environment\PROCESSOR_ARCHITECTURE` |
| fuseau, biais | **déjà fait** via `loadSuspectTimeZone()` (§14.5) |

**Perte : aucune.** `LocalDateTime` et `LastBootUpTime` restent live, mais ce sont
des mesures de l'instant de collecte, pas des artefacts du système — et elles ne
laissent aucune trace (`GetSystemTime`, `GetTickCount64`).

#### `users` — ruche SAM

`SAM\SAM\Domains\Account\Users\<RID>`, valeurs binaires `F` et `V` :
- `F` : dernière connexion, dernier changement de mot de passe, expiration,
  dernier échec, compteur de connexions, indicateurs de compte (désactivé,
  verrouillé, mot de passe jamais expiré) ;
- `V` : nom de compte, nom complet, commentaire, répertoire personnel.

**Gain, pas perte** : SAM contient **plus** que `NetUserEnum` — notamment les
dates de connexion et les compteurs d'échec, absents de l'API.
Prérequis : ajouter `\Windows\System32\config\SAM` à `ExtractHivesRaw()`, qui
ne l'extrait pas aujourd'hui.

#### Restent live, définitivement

`processes` (`CreateToolhelp32Snapshot`) et `sessions` (`LsaGetLogonSessionData`) :
leur objet **est** l'état instantané, il n'existe nulle part sur disque. Aucun
des deux ne passe par COM, donc aucun ne s'oppose à sa suppression.

#### Ordre d'exécution conseillé

1. `$INDEX_ALLOCATION` (§14.10) — prérequis technique de l'extraction récursive ;
2. `systemInfo` — le plus simple, aucune perte, valide l'approche ;
3. `services` — registre seul, pas de XML ; trancher d'abord le sort de `Status` ;
4. `scheduledTasks` + suppression de COM — le gain principal ;
5. `users` / SAM — le plus complexe, et le seul qui enrichisse la sortie.

### 9.5 Design cible : "offline-first"
Inverser l'ordre de WAC : **extraire d'abord** en brut (§2) les ruches **et** les
fichiers (`*.evtx`, `Tasks\*.xml`, Prefetch, Jumplists), **puis tout parser hors
ligne**. Ne garder d'appels live que pour l'ensemble volatile (processus, réseau,
sessions, modules chargés) — idéalement lui-même capturé via image RAM.

---

## 10. Journaux d'événements : parseur EVTX C++ embarqué → JSON (remplacer l'API lente)

> **Contrainte projet** : 100 % C++, **tout embarqué dans l'exe** (bibliothèques
> liées **statiquement**, runtime `/MT`), **aucune dépendance externe ni Python**.
> **La conversion EVTX → JSON de WAC doit être conservée** : c'est le différenciateur
> (n'avoir *que* du JSON à analyser). La cible n'est donc PAS « copier les `.evtx` »
> mais **remplacer le moteur de lecture**.

### 10.1 Diagnostic de la lenteur (20 min Win11 vs 2 min Win10)
`events.hpp` utilise le chemin le plus lent de l'API `wevtapi` :
- **`EvtNext(hQuery, 1, ...)`** (l.465) : **un event par appel** → un aller-retour
  IPC/RPC vers le service EventLog **par event**.
- **`EvtCreateRenderContext` dans la boucle** (l.203, 244) : contexte de rendu
  recréé **à chaque event**.
- **`EvtQuery` + `EvtRender`** : passage par le **service EventLog** + désérialisation
  côté service — chemin qui s'est fortement alourdi sous Win11 (plus de canaux, logs
  ETW plus volumineux, contrôles de sécurité plus lourds). La lenteur est
  **intrinsèque à ce chemin API**, multipliée par les 3 points ci-dessus.

### 10.2 Cible : découpler acquisition et conversion
Deux étapes distinctes, **le JSON restant l'unique sortie** :

1. **Acquisition** des `.evtx` bruts depuis `C:\Windows\System32\winevt\Logs\*.evtx`
   via la **lecture brute NTFS** (§2) — lecture seule, **sans le service EventLog**,
   sans trace ni verrou. Copier tout le dossier = **tous** les canaux (classiques +
   Applications-and-Services) en une passe, sans énumération `EvtNextChannelPath`.
2. **Conversion EVTX → JSON par un parseur C++ embarqué** (§10.4), qui **remplace**
   `EvtQuery`/`EvtRender`. C'est lui qui produit le JSON — la copie ne le fait pas,
   le parseur si. Même sortie qu'aujourd'hui, mais **hors service** et **offline**.

**La copie brute ne fait pas perdre le JSON** : le JSON n'a jamais été produit par le
service, mais par le code de WAC. On déplace simplement la *source des octets*
(fichier brut au lieu de handles d'API) et le *moteur de décodage* (notre parseur au
lieu d'`EvtRender`).

**Gains :**
- **Performance** : lecture de fichiers (quelques centaines de Mo) + parsing binaire
  linéaire → **secondes à ~1-2 min**, **identique Win10/Win11** (service hors boucle).
- **Empreinte** : nulle (plus d'`EvtQuery`, aucune interaction service).
- **Différenciateur renforcé** : le même moteur parse aussi les `.evtx` d'une **image
  disque** ou d'une collecte antérieure → analyse JSON **sans machine vivante**.

### 10.3 Parité de sortie JSON (rassurant)
L'`events.hpp` actuel appelle `EvtRender` avec **`EvtRenderEventValues`** (contexte
`System` puis `Values`) : il extrait déjà les **valeurs structurées** (`System` +
`EventData`), **pas** le message formaté (`EvtFormatMessage`/DLL de providers n'est
pas utilisé). Donc un parseur **Binary XML** produit **exactement les mêmes champs** :
aucune régression de contenu JSON. (Le message humain resterait de toute façon
résoluble offline plus tard si besoin, via les DLL de providers de l'image.)

### 10.4 Le parseur EVTX C++ embarqué
**Option A — parseur maison (recommandée, cohérente avec WAC)** : WAC hand-roll déjà
tous ses parseurs binaires (`idList.cpp`, shellbags, SPS…). Un parseur EVTX/BinXML
s'inscrit dans le même style, **zéro dépendance, zéro souci de licence, exe unique**.

Structure à implémenter :
- **En-tête fichier** (4 Ko) : signature `ElfFile\0`, premier/dernier n° de chunk,
  prochain record id, version, taille en-tête, checksum.
- **Chunks de 64 Ko** : signature `ElfChnk\0`, n° de records, offset dernier record,
  **table de noms** (hash, à 0x80) et **table de templates** (caches *par chunk*
  référencés par offset — indispensables au BinXML).
- **Record** : magic `0x00002a2a`, taille, record id (8 o), FILETIME (8 o), puis
  fragment **Binary XML**, puis copie de taille.
- **Binary XML (tokens)** : `0x0F` FragmentHeader, `0x01` OpenStartElement, `0x06`
  Attribute, `0x02` CloseStartElement, `0x04` EndElement, `0x05` Value, `0x0C`
  TemplateInstance, `0x0D`/`0x0E` Substitution (normale/optionnelle), `0x00` EOF.
  Une instance de template porte un **tableau de substitutions** (count, puis
  `[taille,type]`, puis valeurs).
- **Types de valeurs** → JSON : `0x01` wstring, `0x04..0x0F` entiers, `0x11`
  FILETIME (→ UTC + local, cf. §7), `0x13` SID (→ chaîne S-1-…), `0x21` BinXml
  imbriqué, `0x0E` binaire (→ hex), etc.
- **Sérialisation** : `<System>` et `<EventData>`/`<UserData>` → objets JSON, en
  réutilisant les helpers existants (`time_to_wstring`, `guid_to_wstring`,
  conversion SID de `users.hpp`).

**Option B — libevtx (libyal) liée statiquement** : bibliothèque **C** éprouvée,
compilable en `.lib` et **embarquée** dans l'exe (compatible full-C++/exe unique).
⚠️ **Licence LGPLv3** : le *linkage statique* dans un exe propriétaire impose des
obligations (permettre le re-link). À arbitrer selon la distribution visée ;
l'option A évite ce point.

> Référence de **spécification** (documentation uniquement, pas une dépendance) :
> *EVTX / Binary XML format* de Joachim Metz (libyal). Validation croisée possible
> avec `EvtxECmd`. Aucun composant Python n'est embarqué ni requis.

### 10.4bis Panorama des bibliothèques EVTX→JSON (état des lieux)
Vérifié : **aucune bibliothèque C++ ne convertit EVTX→JSON en drop-in embarquable**.
- Celles qui sortent du **JSON** sont en **Rust** (`omerbenamram/evtx`, la référence,
  `evtx_dump`), **Go** (`velocidex/evtx`) ou **Python** (`python-evtx`,
  `evtx_dump_json.py`) → **incompatibles** avec « full C++ / tout dans l'exe / pas de
  Python » (le Rust en FFI staticlib impose la toolchain Rust).
- La seule cleanly embarquable est **libevtx** (C, `.lib` statique), mais elle produit
  du **XML**, **pas de JSON** : la couche JSON reste **à écrire** de toute façon, et
  elle est **LGPLv3** (linkage statique = obligation de re-link).

→ Que l'on parte de zéro (Option A) ou de libevtx (Option B), **l'émetteur JSON est
toujours du code WAC**. Vu la contrainte de licence et le style hand-rolled du projet,
**l'Option A (parseur maison)** est privilégiée.

### 10.5 Points de vigilance
- **Events bufferisés (dirty)** : le service garde en mémoire les derniers events
  avant flush disque. L'acquisition brute peut manquer la **toute fin** de chaque
  canal → acceptable, **à documenter** (forcer un flush = trace, à éviter).
- **Dernier chunk partiel / CRC** : tolérer un chunk incomplet → **carving
  permissif** des records pour la complétude forensique.
- **Tables par chunk** : templates et noms sont locaux au chunk → réinitialiser les
  caches à chaque chunk (piège classique du BinXML).

### 10.6 Repli immédiat (avant que le parseur soit prêt)
Deux corrections dans `events.hpp` réduisent déjà fortement le temps **sans** changer
d'architecture :
1. **Batcher `EvtNext`** : 512-1024 events par appel au lieu de `EvtNext(hQuery, 1, …)`.
2. **Hisser `EvtCreateRenderContext` hors des boucles** : le créer **une fois**, le réutiliser.

Ce n'est qu'un palliatif : le parseur embarqué (§10.4) reste la cible (perf + offline + empreinte).

---

## 11. Références

- Microsoft — *File System Forensic* : structure NTFS ($MFT, $DATA runs).
- The Sleuth Kit — `tsk_fs_file_read` (option B).
- libyal / libfsntfs (option C).
- RFC 3227 — *Guidelines for Evidence Collection and Archiving* (ordre de volatilité).
- ISO/IEC 27037 — identification, collecte et préservation de la preuve numérique.

---

## 11. Sérialisation JSON centralisée (`json.h`) — 2026-09-14

### Le vrai problème n'était pas l'échappement
Chaque artefact fabriquait son JSON **à la main** par concaténation de chaînes.
Conséquences mesurées sur les 17 sorties : **3 fichiers invalides**
(`ScheduledTasks` échappement oublié, `Sessions` virgule finale,
`mounted_device` binaire brut), des **nombres émis comme chaînes**
(`"SessionId":"320862"`), une indentation gérée à la main, et surtout des
**valeurs stockées pré-échappées en mémoire** — donc des chemins inutilisables
pour les I/O fichier (symptôme révélateur : `prefetchs.hpp` devait *dé-doubler*
les `\\` avant `fileToHash`, et `schedulesTasks` gardait un champ nommé
`escapedPath` en doublon de `pPath`).

### Solution : `WAC/json.h`
Writer JSON en `wstring`, autonome (aucune dépendance, testable sous Linux) :
- `Json::obj()` / `arr()` / `str()` / `num()` / `boolean()` / `null()`,
  `add(clé, valeur)`, `push(valeur)`, `dump(niveau)` ;
- **échappement centralisé** (`\`, `"`, contrôles < 0x20 en `\uXXXX`) appliqué
  **une seule fois**, à la sérialisation ;
- **virgule finale structurellement impossible** ;
- **indentation hiérarchique** par niveau d'imbrication (lisibilité directe) ;
- **types respectés** : nombres et booléens non guillemetés.

**Règle d'architecture** : les valeurs sont stockées **BRUTES** en mémoire (vrais
chemins, directement exploitables) ; l'échappement n'existe qu'au `dump()`.
Conséquence : tout `replaceAll(x, L"\\", L"\\\\")` à l'affectation doit être
**supprimé** lors de la migration d'un artefact (sinon double-échappement).

### Vérification automatique
`vmtest/check-json.py` (intégré à `run-wac-test.sh`) contrôle à chaque cycle :
1. la **validité JSON** de chaque fichier ;
2. la **cohérence des chemins** — un chemin issu d'un double échappement apparaît,
   après parsing, avec ses barres obliques inverses doublées.

**Le critère naïf « toute double barre est une faute » est faux.** La première
version signalait 16 valeurs dans `events.json` qui étaient parfaitement
correctes : du contenu de script PowerShell journalisé, où `'TIP\\(?:'` est une
expression régulière dont `\\` est l'échappement PowerShell d'un backslash
littéral — la donnée source contient réellement deux caractères.

Le contrôle ne cherche donc plus une double barre n'importe où, mais des **motifs
de chemin certainement fautifs** :

| Motif | Exemple fautif |
|---|---|
| `[A-Za-z]:\\\\` | `C:\\\\Windows` (lettre de lecteur) |
| `^\\\\\\\\[A-Za-z0-9]` | `\\\\\\\\serveur` (UNC déjà doublé) |
| `\\\\\\\\(Device\|REGISTRY\|SystemRoot\|??)\\\\` | `\\\\\\\\Device\\\\Harddisk0` |

Le détecteur est lui-même testé dans les deux sens : il doit attraper
`C:\\\\Windows\\\\System32` et laisser passer un chemin simple, un chemin UNC, un
long-path `\\?\` et une regex contenant `\\\\`. **Un détecteur non testé dans le
sens « ne doit pas déclencher » finit par être ignoré**, ce qui est plus nuisible
que son absence.

### État : migration terminée (2026-09-15)

| | avant | après |
|---|---|---|
| JSON valides | 14 / 17 | **22 / 22** |
| double-échappement | 3 fichiers | **0** |
| artefacts sérialisés par `json.h` | 0 | **24 / 24** |
| `std::wofstream` hors `writeJsonFile` | 24 | **0** |

Tous les artefacts passent désormais par `Json` + `writeJsonFile()`. Il ne reste
aucune construction de JSON par concaténation, aucun `replaceAll(x, L"\\", L"\\\\")`
à l'affectation, aucune écriture de fichier hors du point central.

### Défauts de données trouvés *pendant* la migration

La conversion a servi de revue ligne à ligne. Elle a mis au jour des défauts qui
produisaient du JSON **valide mais faux** — donc invisibles au contrôle de syntaxe :

| Fichier | Défaut | Conséquence forensique |
|---|---|---|
| `idList` (`Beef0004`) | date d'accès publiée sous la clé `CreatedDate` | **preuve fausse** : date de création erronée |
| `idList` (`get_value`) | position avancée avec la longueur de la chaîne *échappée* | toute valeur contenant `\` décalait le parsing des propriétés suivantes |
| `idList` (`UnknownShellItem`) | chaîne construite mais jamais affectée | shell items inconnus **silencieusement perdus** |
| `events` (`EvtVarTypeFileTime`) | `(DWORD)data->FileTimeVal` — 32 bits hauts jetés | **toutes les dates d'événements fausses** |
| `events` | `L"..." + EvtSystemEventRecordId` — arithmétique de pointeur sur l'énumération `winevt.h` (=9) | log tronqué de 9 caractères, ID jamais affiché |
| `events` | `free(bufferMessage)` dans la branche succès *et* en tête de boucle | double libération possible |
| `services` | `free`/`CloseServiceHandle` placés **après** les `return` | fuite systématique du buffer d'énumération |
| `services` | `serviceType` parsé mais jamais émis | information collectée puis perdue |
| `processes` | `processThreadCount` parsé mais jamais émis | idem |
| `sessions`, `events` | `ConvertSidToStringSid[W]` sans `LocalFree` | fuite par session / par événement |
| `system` | flux jamais vérifié | `OperatingSystem.json` silencieusement non écrit |
| `prefetchs`, `recent_docs`, `jumplist_*` | `directory_iterator` sur répertoire absent | **exception non rattrapée : arrêt de toute la collecte** |
| `reg_bams` | `Bams::to_json()` défini dans le `.h` | rupture de la convention `.h`/`.cpp` (§12) |
| `com` | classe entièrement définie dans le `.h` | idem ; scindée en `com.h` + `com.cpp` |

Ce dernier point est le plus grave : depuis la suppression de VSS, `out\hives\Windows\Prefetch`
n'existe pas, `directory_iterator` levait `filesystem_error`, et WAC **s'arrêtait
avant** `jumplist_*`, `recent_docs` et `events`. Les JSON déjà écrits étaient
valides, donc `check-json.py` ne signalait rien : la collecte était tronquée en
silence. Corrigé par `listFilesByExtension()` (`tools.h`), qui rend une liste vide
sur répertoire absent ou illisible — le cas nominal en collecte.

### Leçon sur le harnais de test

`check-json.py` valide la **syntaxe** et la **cohérence des chemins**. Il ne dit
rien de l'**exactitude** ni de la **complétude**. Un JSON valide et une sortie
sans erreur ne prouvent pas que la collecte est allée au bout.

`run-wac-test.sh` contrôle donc désormais aussi la **terminaison** : code de
retour de WAC et recherche de `terminate called` / `Unhandled exception` dans le
log, avec un avertissement explicite « les JSON ci-dessus sont PARTIELS ».

Reste à ajouter (voir §14) : un contrôle de **non-régression du contenu**, par
comparaison à un instantané de référence — seul moyen de détecter une dérive de
valeurs, que ni la syntaxe ni la terminaison ne révèlent.

### Note sur `events`
`events` est migré vers `json.h` bien qu'il doive être remplacé par le parseur
EVTX embarqué (§10) : la couche de sérialisation est indépendante de la source
d'acquisition, le travail resservira tel quel. Le typage JSON réel (nombres,
booléens, tableaux, `null`) remplace les fragments de chaîne pré-échappés qui
étaient l'origine du double-échappement résiduel.

---

---

## 12. Normalisation de la structure : scission `.hpp` → `.h` + `.cpp` (2026-09-14)

### Pourquoi — et la bonne raison
Les 23 `.hpp` n'étaient pas des en-têtes mais des **implémentations complètes**
(classes avec tous les corps de méthodes) incluses dans `main.cpp` : **6828 lignes
compilées dans UNE seule unité de traduction**. Toute modification recompilait tout.

⚠️ *Précision technique* : les méthodes définies **dans** le corps d'une classe sont
implicitement `inline`, donc il n'y avait **pas** de risque de symbole dupliqué pour
elles. Le risque réel ne concernait que les **fonctions libres** définies au niveau
fichier — et il s'est effectivement matérialisé sur `asciiart()` pendant la
migration. Le bénéfice principal de la scission est donc la **compilation
incrémentale**, la **lisibilité** et la possibilité de **tester un module isolément**.

### Convention retenue : `.h` + `.cpp`
Pas d'imposition du standard C++ sur l'extension des en-têtes ; `.h` est le choix le
plus répandu (Google, LLVM, Qt) et surtout **c'était déjà la norme du projet** pour
ses 6 modules correctement scindés (`tools`, `idList`, `trans_id`, `raw_hive`,
`hive_recover`, `quickdigest5`). `.hpp` signale ailleurs « en-tête C++ uniquement »
(convention Boost) — inutile ici.

### Résultat
| | avant | après |
|---|---|---|
| `.hpp` header-only | 23 (6828 lignes) | **0** |
| unités de compilation | 7 | **34** |
| JSON produits / valides | 17 / 17 | **17 / 17** (zéro régression) |

Restent en en-tête, à juste titre : `raw_collect.h` (une seule fonction `inline`) et
`com.h` (méthodes définies dans la classe, donc implicitement `inline`).

### Points appris (à reproduire pour tout futur module)
1. **Chaque en-tête doit être auto-suffisant.** Les `.hpp` s'appuyaient sur l'ordre
   d'inclusion de `main.cpp`. Includes à ajouter après scission :
   `quickdigest5.h` (shimcache, processes, services), `<sddl.h>` (events),
   `<sys/stat.h>` (jumplist_*, recent_docs), `<algorithm>` (oleparser).
2. **`#pragma once` obligatoire** : les en-têtes sont désormais inclus par plusieurs
   unités (les `.hpp` d'origine n'en avaient aucun).
3. **Code mort détecté** : `ReadLnkFile.cpp` n'était compilé par **aucun** des deux
   builds et ne compile pas — référencé nulle part. À supprimer.
4. Le build `build-windows.sh` **découvre désormais les `.cpp` automatiquement**
   (plus de liste à maintenir) ; `WAC.vcxproj`/`.filters` régénérés.

### Suite prévue
Étapes 2 à 4 du plan : finir la migration JSON des artefacts restants, puis le
renommage (conventions C++), puis la reprise des commentaires de documentation.

---

## 13. Gestion mémoire : passage au RAII (2026-09-14)

### Ce que l'audit a révélé
Le code *paraissait* gérer sa mémoire — des méthodes `clear()` partout, appelées
consciencieusement depuis `main.cpp` avec le commentaire `// free memory`. En
réalité **rien n'était libéré**, et les JSON produits étant corrects, aucun test
fonctionnel ne pouvait le révéler.

| Défaut | Portée | Conséquence |
|---|---|---|
| **24 `clear()` dans 19 fichiers** écrits `for (X temp : conteneur) temp.clear();` | tout le projet | itère **par valeur** → copie chaque élément **et** opère sur la copie : l'original n'est jamais libéré |
| **50 `new` / 3 `delete`** dans `idList` | shell items, extension blocks, `IdList` | fuite de quasi tout ce qui est parsé |
| **Aucun destructeur virtuel** sur `IShellItem` / `IExtensionBlock` / `UserPropertyViewDelegate`, alors que `delete` était appelé sur ces pointeurs de base | `idList.h` l. 326, 604, 606, 941 | **comportement indéfini** : le destructeur dérivé n'est jamais exécuté — les rares libérations existantes étaient elles-mêmes fausses |
| `makeShellItem` (ex-`getShellItem`) pouvait **atteindre sa fin sans `return`** | type de shell item non reconnu | valeur de retour indéfinie |
| Copies profondes implicites : `RecentDoc temp = *it;`, `push_back(mruApp)` | jumplists, MRU, shellbags | duplication complète (avec `vector<IdList>` et tous les shell items) à chaque itération |

### Corrections
- Pointeurs bruts → **`std::unique_ptr`** (`IShellItem`, `IExtensionBlock`, `IdList`,
  `SPS`, `UserPropertyViewDelegate`) : `idList` passe à **0 `new` / 0 `delete`**.
- **Destructeurs virtuels** ajoutés sur les 3 interfaces de base.
- Fabrique convertie en valeur de retour :
  `void getShellItem(buf, IShellItem** p, …)` → `std::unique_ptr<IShellItem> makeShellItem(buf, …)`,
  avec `return nullptr` explicite sur le chemin « type inconnu ».
- **54 `clear()` vides supprimés** d'`idList.h` (~150 lignes de code mort) ; les
  `clear()` des conteneurs réimplémentés en `conteneur.clear()` — ils libèrent enfin.
- Copies remplacées par des références / `std::move`.
- 3 `SPS*` alloués puis `delete` → objets **sur la pile** (plus d'allocation).
- `NULL` → `nullptr` (obligatoire à travers `make_unique`, et bonne pratique).

### Méthode utile à réutiliser
Tant qu'un type reste implicitement copiable, une copie interdite remonte sous forme
de `static assertion failed` dans `stl_uninitialized.h`, avec une chaîne de templates
illisible pointant la *définition* de la struct. En déclarant explicitement
l'intention :
```cpp
RecentDoc(const RecentDoc&) = delete;
RecentDoc& operator=(const RecentDoc&) = delete;
RecentDoc(RecentDoc&&) = default;
RecentDoc& operator=(RecentDoc&&) = default;
```
le compilateur pointe **le site fautif exact**. À appliquer à tout type détenant des
ressources : ça documente le contrat *et* rend les erreurs exploitables.

### À traiter dans la passe « conventions de nommage »
`struct MruApps { std::vector<MruApp> MruApps; }` et `struct Mrus { std::vector<Mru> Mrus; }`
déclarent un **membre du même nom que leur classe** (légal faute de constructeur
déclaré, mais très trompeur : dans `MruApps::clear()`, `MruApps` désigne le membre).

### Validation
Build vert et **18/18 JSON valides, 0 double-échappement — aucune régression**.

---

## 14. Chantiers restants (au 2026-09-15)

Par ordre de valeur forensique décroissante.

**État de la migration hors ligne : terminée.** Le §9.4ter est soldé (§14.13,
§14.14, §14.15). Ne subsistent en collecte live que les trois lectures dont
l'objet *est* l'instant de la collecte, et dont aucune ruche ne peut rendre
compte :

| Collecteur | Source live | Pourquoi elle ne peut pas basculer |
|---|---|---|
| `processes` | `CreateToolhelp32Snapshot` + `WTSEnumerateProcessesExW` | l'état instantané n'existe nulle part sur disque |
| `sessions` | `LsaEnumerateLogonSessions` | idem |
| `events` | `wevtapi` | les EVTX *sont* des fichiers : reste à basculer, cf. §14.3 |

Deux lectures ponctuelles du registre vivant subsistent également, chacune parce
qu'elle est un **prérequis** de la lecture hors ligne : `loadSystemDrive()`
(quelle lettre de volume extraire) et `loadProfileList()` (où trouver les ruches
par utilisateur). Aucune n'ouvre de handle ni ne passe par RPC.

`events` est donc le dernier collecteur qui pourrait devenir hors ligne, et c'est
aussi le plus lent (§14.3).

### 14.1 Collecteurs de fichiers sans source de données — traité, à valider
`prefetchs`, `jumplist_automatic`, `jumplist_custom`, `recent_docs` ne rendaient
plus **aucune donnée** : ils lisent sous `conf.mountpoint`, qui pointait sur le
snapshot VSS et ne contenait plus que les ruches extraites.

Ils ne plantaient plus (§11), mais un artefact vide n'est pas un artefact absent :
**à l'analyse, « 0 entrée » est indiscernable de « pas de trace »**. C'est un
risque d'interprétation, pas seulement une fonctionnalité manquante.

**Implémenté** (`raw_hive.{h,cpp}`, `raw_collect.{h,cpp}`) :

| Ajout | Rôle |
|---|---|
| `RawDirEntry` | nom, index MFT, taille, type d'une entrée de répertoire |
| `ListDirectoryRaw` | énumère un répertoire NTFS en brut |
| `ExtractDirectoryRaw` | extrait les fichiers d'un répertoire, filtrés par extension |
| `ExtractFileArtefactsRaw` | orchestre Prefetch + `Recent` de chaque profil |

Les fichiers sont écrits sous **leur chemin d'origine relatif au volume**, si bien
que les collecteurs les trouvent sans aucune modification.

Deux pièges du format traités au passage :
- `parseIndexNode` écarte l'espace de noms 2 (**nom court 8.3**) : NTFS enregistre
  souvent deux entrées pour un même fichier (DOS et Win32), ce qui aurait extrait
  chaque fichier deux fois, sous deux noms différents ;
- le drapeau « répertoire » dans une clé `$FILE_NAME` est `0x10000000`, et non le
  `FILE_ATTRIBUTE_DIRECTORY` habituel (`0x10`).

Un répertoire absent n'est **pas** une erreur (tous les profils n'ont pas tous les
dossiers) : il rend 0 fichier. Le décompte est journalisé par répertoire, même à
zéro, pour que le rapport distingue « dossier vide » de « dossier non collecté ».

**Reste à valider en VM** : que `prefetchs.json` et `jumplistAutomaticDestinations.json`
passent de 0 à un nombre non nul. Cette validation exercera aussi le durcissement
d'`oleparser` (§14.8), aujourd'hui couvert par aucun test.

### 14.2 Contrôle de non-régression du contenu
Voir §11 « Leçon sur le harnais ». Figer les JSON d'un run de référence et
comparer à chaque itération. Ne prouve pas l'exactitude absolue, mais détecte
toute dérive introduite par une modification — le risque principal sur un
refactor de cette ampleur. Complément : comparer à un outil du domaine
(ShellBags Explorer, Registry Explorer) sur les mêmes ruches extraites.

### 14.3 Parseur EVTX C++ embarqué (§10) — DERNIER COLLECTEUR À BASCULER
Traite la lenteur Win11 (20 min contre 2 min sous Win10) et supprime la
dépendance à `wevtapi`. `events` est déjà sur `json.h`, donc seule la couche
d'acquisition est à écrire.

Depuis que §9.4ter est soldé, c'est le seul collecteur pour lequel une source
hors ligne existe sans être exploitée : les journaux **sont** des fichiers, sous
`\Windows\System32\winevt\Logs\*.evtx`. Les extraire en brut, comme les ruches,
et les analyser supprimerait la dernière sollicitation d'un service du système
examiné — le service EventLog, qui peut inscrire ses propres entrées pendant
qu'on le lit (cf. `Footprint::EVENTLOG`).

Deux bénéfices qui se cumulent, rare dans cette migration : moins d'empreinte
**et** la fin des vingt minutes d'attente.

Un troisième s'y ajoute, et c'est un problème d'EMPREINTE autant que de
performance : la **mémoire**.

Mesuré sur la VM de test, le jeu de travail de WAC monte à **473 Mo** pendant la
lecture des 88 000 événements, puis à **1,44 Go** au moment d'écrire le JSON —
l'arbre `Json` complet est en mémoire, et sa sérialisation en construit une
seconde représentation sous forme de chaîne avant l'écriture.

Pourquoi cela dépasse la simple performance : **1,44 Go de pression mémoire sur
une machine que l'on examine peut provoquer de la pagination**, donc des
écritures dans `pagefile.sys` — c'est-à-dire une modification du disque de la
cible, précisément ce que toute cette migration cherche à éviter. Sur une machine
modeste ou déjà chargée, le risque n'est pas théorique.

Deux corrections indépendantes :
1. un parseur EVTX **en flux**, qui émettrait chaque enregistrement au fil de la
   lecture, ramènerait la lecture à la taille d'un chunk (64 Kio) ;
2. une **écriture JSON en flux** pour les gros tableaux, qui éviterait de
   matérialiser le document entier puis sa sérialisation. Utile pour `events`,
   mais aussi pour `prefetchs` (4,5 Mo) et `amcache`.

La seconde vaut d'être faite même si la première tarde : elle est locale à
`json.h` et bénéficie à tous les artefacts volumineux.

Le format est le morceau le plus lourd du projet : en-tête de fichier, chunks de
64 Kio avec leur propre table de hachage, enregistrements en BinXML, et surtout
le système de *templates* — un enregistrement référence une définition de
structure placée ailleurs dans le chunk, avec substitution de valeurs typées.
Références : la spec libyal (libevtx) et l'implémentation de référence
`python-evtx`.

### 14.4 Complétude des formats

**Liste de travail, tirée des avertissements du compilateur.** Depuis
l'activation de `-Wall` (§14.16), les champs décodés mais non exploités se
signalent d'eux-mêmes à chaque build. Ils sont **volontairement conservés** :
les supprimer effacerait la trace du travail restant.

| Fichier | Champ lu et non émis | Ce qu'il apporterait |
|---|---|---|
| `prefetchs.cpp` | `nb_entries`, `start` | nombre d'entrées de la section « file metrics » — permet de vérifier que tout a été lu |
| `prefetchs.cpp` | `trace_offset`, `nb_traces` | chaînes de trace : ordre de chargement des fichiers au démarrage du programme |
| `prefetchs.cpp` | `volume_size`, `numChar`, `fileRefSize` | bornes de section, utiles au contrôle d'intégrité |
| `recent_docs.cpp` | `labeloffsetunicode` | libellé Unicode d'un bloc, aujourd'hui lu en ANSI seulement |
| `idList.cpp` | `wstring2Size`, deux `size` | bornes de chaînes dans les shell items |

À traiter avec la même méthode que la signature Prefetch (§14.17) : soit le champ
devient une donnée émise, soit il sert de **contrôle d'intégrité** du décodage —
et dans les deux cas l'avertissement disparaît pour la bonne raison.
Blocs `beef00XX` manquants et tables `trans_id` à compléter. La migration a
rendu les cas inconnus **visibles** (`UnknownShellItem` n'est plus perdu
silencieusement) : les logs de collecte listent maintenant ce qui n'est pas
décodé, ce qui donne enfin une liste de travail fondée sur des données réelles
plutôt que sur la spec.

### 14.5 Horodatages — traité (2026-09-15)

**Format ISO 8601.** Les dates étaient émises en « 15/9/2026 5h43m32s » : ni
triable, ni corrélable, ambigu sur jour/mois, et surtout **muet sur le fuseau**.
Désormais `2026-09-15T05:43:32Z` (UTC) et `2026-09-15T07:43:32+02:00` (locale) :
la date porte son propre fuseau, plus besoin d'une convention externe pour la
lire.

**Deux fonctions, pas un drapeau.** `timeToIso8601Utc` / `timeToIso8601Local` /
`localTimeToIso8601Utc`, sans valeur par défaut : le suffixe doit dire la vérité
sur la valeur, et seul l'appelant sait ce qu'il détient. Un paramètre à défaut
produirait des dates faussement étiquetées en cas d'oubli.

**Ce que la migration a révélé.** Vouloir automatiser le remplacement a obligé à
vérifier, champ par champ, si la valeur était UTC ou locale — et a mis au jour
**deux doubles décalages symétriques**, tous deux corrigés :

| Artefact | Encodage natif | Ce que faisait le code | Erreur produite |
|---|---|---|---|
| `idList` — dates FAT (4 sites : `Beef0004`, `FileEntryShellItem`, `UsersFilesFolder`, shell item) | **locale** (spec FAT) | affectait au champ `*Utc` puis `FileTimeToLocalFileTime` | clé `*Utc` = heure locale étiquetée UTC ; clé locale = **+2 h** |
| `recent_docs` — `.lnk` offsets 28/36/44 | **UTC** (MS-SHLLINK 2.1) | affectait au champ local puis `LocalFileTimeToFileTime` | clé locale = UTC non converti ; clé `*Utc` = **−2 h** |

Vérifié empiriquement sur `C:\Windows` dans `shellbags.json` : avant, local
`9h21m18s` / UTC `7h21m18s` ; après, local `07:21:18+02:00` / UTC `05:21:18Z`.
Les deux valeurs reculent de 2 h — l'ancienne « UTC » était l'heure locale.

**La convention de nommage ne suffit pas.** Quatre familles de cas portaient un
nom sans `Utc` alors que la valeur *était* UTC : horodatages d'événements,
`VT_FILETIME` d'un property store, `Filetime1/2` de shell items. Un remplacement
mécanique sur le nom aurait décalé de 2 h les 75 000 horodatages du journal
d'événements. Traités à la main. `VT_DATE` est l'inverse : locale par convention
OLE.

La troncature 32 bits d'`EvtVarTypeFileTime` (§11) relevait du même chantier.

**Fuseau du suspect (2026-09-15).** La source d'autorité est désormais
`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`, et non
`GetTimeZoneInformation()`. La distinction compte : les artefacts qui stockent
une heure locale (dates FAT, Amcache, BAM, shimcache, USBSTOR, UserAssist) ne
sont interprétables qu'avec le fuseau **de la machine examinée**. L'API rend
celui de la machine d'exécution : identique en collecte live, faux dès qu'on
analyse une image montée ailleurs.

`loadSuspectTimeZone()` (tools) renseigne `conf.timeZone` dès l'ouverture de
`CurrentControlSet` ; tous les horodatages locaux formatés ensuite portent le
décalage du suspect. `localUtcOffsetString()` **ne met pas la valeur en cache** :
un cache figerait le décalage de la machine de collecte pour toute l'exécution.
En cas d'échec de lecture, repli sur l'API — correct en collecte live, et signalé.

`ActiveTimeBias` est privilégié sur `Bias` car il inclut le biais saisonnier
effectif. Si seul `Bias` est disponible, l'heure d'été n'est pas prise en compte
et c'est journalisé : on ne peut pas savoir lequel des deux s'appliquait au
moment de chaque artefact.

`investigation.json` publie les **deux** fuseaux — `SuspectTimeZone` et
`CollectionHostTimeZone` — plus un `TimeZoneMismatch` quand ils divergent. Une
divergence est un signal en soi : image analysée sur une autre machine, ou fuseau
modifié depuis la collecte. Relevé mesuré sur la VM :

```json
"SuspectTimeZone": { "KeyName": "Romance Standard Time",
                     "UtcOffsetMinutes": 120,
                     "Source": "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation" }
```

⚠️ **Limite de validation.** En collecte live les deux fuseaux coïncident (120 et
120 sur la VM), donc la branche « divergence » — et l'usage effectif du fuseau de
la ruche pour formater les dates — **n'est pas prouvée par ce test**. Il faudrait
analyser la ruche d'une machine d'un autre fuseau. La lecture depuis la ruche est
en revanche bien vérifiée : `KeyName` remonte de la ruche, pas de l'API.

Note : `StandardName` / `DaylightName` valent `@tzres.dll,-302` — des références
de ressource MUI, pas des noms lisibles. Valeurs conservées telles quelles par
fidélité à la source ; `KeyName` est le champ exploitable, et il est stable quelle
que soit la langue du système.

### 14.6 Artefacts absents vs artefacts vides
`Usbstor.json` n'est pas écrit quand `getData()` échoue — sur la VM de test, la
clé `SYSTEM\CurrentControlSet\Enum\USBSTOR` n'existe pas (aucun périphérique de
masse jamais branché). L'échec est légitime et tracé à l'écran comme dans le log,
mais **le fichier manquant ne distingue pas « échec de lecture » de « rien à
collecter »** — même risque d'interprétation qu'en §14.1.

Piste : toujours écrire le fichier, avec un statut de collecte explicite
(`"CollectionStatus": "KeyNotFound"` / `"OK"`), afin que l'analyste lise la raison
plutôt que de devoir l'inférer d'une absence.

Le cas du **Prefetcher désactivé** illustre pourquoi ça compte. Windows 11 met
souvent `EnablePrefetcher` à 0 quand le disque système est vu comme SSD
(`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`).
Un `prefetchs.json` vide signifie alors « fonction coupée », pas « rien n'a été
exécuté » — et **la désactivation elle-même est un fait à relever**, éventuellement
délibéré. Un tableau vide fait perdre les deux informations.

### 14.7 Ordre des phases de collecte (à trancher)
Dans `main.cpp`, les journaux d'événements sont traités **avant** l'extraction
brute. Avec `--events` sous Windows 11 (§10), la capture du disque est donc
repoussée d'une vingtaine de minutes, et une interruption pendant cette phase ne
laisse **aucune ruche**.

L'ordre de volatilité (RFC 3227) plaiderait pour : volatile d'abord (processus,
sessions, COM/WMI) → **figer le disque en brut** (ruches + fichiers) → parsing
hors ligne (registre, prefetch, jumplists) → événements en dernier, puisqu'ils
sont sur disque et donc les moins volatils.

Décision de méthodologie de collecte : à valider avant modification.

### 14.8 Durcissement d'`oleparser` (à valider)
Les fichiers analysés viennent d'une machine suspecte : ils ne sont pas de
confiance. Corrigé dans `oleparser` : tailles de secteur validées (l'exposant
venait du fichier et n'était pas contrôlé — `pow(2, 15)` tronqué en `short`
donnait −32768, puis servait à calculer tous les offsets), indices de secteur
bornés, chaînes cycliques détectées, test `i > size()` corrigé en `i >= size()`.
Le parcours de chaîne, écrit trois fois avec ses propres trous à chaque copie, est
centralisé dans `sectorChain()`.

Non couvert par les tests aujourd'hui : `oleparser` n'est exercé que par
`jumplist_automatic`, qui n'avait pas de données (§14.1).

### 14.9 Conventions de nommage, puis documentation
Demandées en dernier. `camelCase` pour fonctions et variables, suppression de la
notation hongroise (`pName`, `szValue`, `lpsid_`), `struct MruApps { vector<MruApp> MruApps; }`
à renommer, clé `"Star-system"` (champ `filesystem`, probable rechercher-remplacer
manqué) à trancher. Puis reprise de tous les commentaires de documentation.

### 14.10 ✅ RÉSOLU : `$INDEX_ALLOCATION` éclaté dans `$ATTRIBUTE_LIST` (2026-09-15)

**Symptôme** (système réel). `\Users\<nom>\AppData\Roaming\Microsoft\Windows\Recent`
rendait **0 entrée** alors qu'il contient des `.lnk`, et ses sous-dossiers
`AutomaticDestinations` / `CustomDestinations` n'étaient pas résolus — puisqu'ils
sont énumérés depuis l'index de `Recent`.

**Cause.** `$INDEX_ALLOCATION` peut être ÉCLATÉ dans un `$ATTRIBUTE_LIST`, comme
le `$DATA` de la ruche SOFTWARE (§14.x). `findAttr(rec, 0xA0)` ne cherchait que
dans l'enregistrement de base : l'attribut restait introuvable, et la boucle de
lecture des blocs était simplement sautée. `listDir` rendait donc `true` — car
`$INDEX_ROOT` existe bien, résident, réduit à un nœud séparateur — avec zéro
entrée. Un dossier `Recent`, constamment créé/supprimé, est un candidat idéal à
ce niveau de fragmentation.

**Correction.** `collectRunsFromAttributeList()` est généralisée à n'importe quel
type d'attribut (paramètre `typeCherche`), et la lecture des blocs `INDX` est
factorisée dans `lireBlocsIndex()`, partagée par les deux chemins d'accès :
enregistrement de base, ou `$ATTRIBUTE_LIST`. Vérifié sur la cible réelle :
`raw_hive_test --list` liste désormais les `.lnk`.

**Ce qui a fait avancer le diagnostic — et ce qui l'a retardé.**

Ma première hypothèse était « `$INDEX_ALLOCATION` mal lu », fondée sur la seule
comparaison entre `Office\Recent` (18 entrées, index résident) et
`Windows\Recent` (0). Elle était **fausse**, et deux éléments l'ont invalidée :

1. le **diagnostic par répertoire** ajouté à `ExtractDirectoryRaw` — distinguer
   « chemin non résolu » de « 0 entrée » a montré que l'index était *lisible*,
   donc que le code de lecture n'était pas en cause ;
2. un **contre-exemple volumineux** : `\Windows\Prefetch` sort 302 entrées, ce qui
   prouve que `$INDEX_ALLOCATION` fonctionne. Sans ce cas, la fausse piste aurait
   pu être suivie longtemps.

Leçon reproductible : face à « 0 élément », établir d'abord **lequel des trois
cas** s'applique (absent / vide / filtré), puis chercher un contre-exemple du même
type qui, lui, fonctionne. Comparer deux cas qui diffèrent par plusieurs
dimensions à la fois (ici taille ET mode de stockage de l'attribut) mène à la
mauvaise conclusion.

**Reste à confirmer** : que `jumplistAutomaticDestinations`, `jumplistCustomDestinations`
et `recentdocs` remontent bien des données sur une collecte complète.


### 14.11 ✅ `trans_id` : tables indexées et alignées sur libyal (2026-09-15)

**Performance.** `trans_guid_to_wstring` était une cascade de **20 356
comparaisons de `std::wstring`**, appelée pour chaque GUID des shellbags, MRU et
IdList — des millions de comparaisons sur un poste réel. `from_appId` en faisait
783. Converties en tables indexées (`std::unordered_map` construit une seule
fois) : la recherche devient immédiate.

**Défauts trouvés en convertissant :**

| Défaut | Effet |
|---|---|
| `{D5CDD505-…}` écrit en MAJUSCULES, alors que `guid` est passé en minuscules juste avant | entrée **inatteignable** ; ce FMTID n'était jamais traduit |
| 3 487 clés dupliquées | dans une cascade de `if`, seul le premier gagne : les libellés plus précis étaient inaccessibles |
| `from_appId` ne normalisait pas la casse | un AppID issu d'un nom de fichier pouvait ne pas correspondre |

**Choix du libellé en cas de doublon.** Deux tentatives ont échoué avant d'aboutir :
privilégier le module a fait perdre le nom de classe sur 657 entrées ; privilégier
le nom a fait ressortir des libellés purement génériques (« CLSID » seul) au
détriment d'un chemin qui, lui, identifie le composant. Le critère retenu classe
par **pouvoir d'identification** : nom + module, puis nom seul, puis chemin seul,
le libellé générique en dernier recours.

**Alignement sur une source de référence.** Plutôt qu'une heuristique, les noms
proviennent désormais de **libyal/libfwsi** (`libfwsi_shell_folder_identifier.c`,
`libfwsi_known_folder_identifier.c`) — bibliothèque du domaine, maintenue et
citable, ce qui est préférable pour un outil d'expertise. Les GUID y sont stockés
en binaire (data1/2/3 little-endian) et ont été reconvertis ; la conversion a été
contrôlée sur un identifiant connu (`3D Objects`).

Résultat : **343 identifiants de référence**, dont 148 libellés corrigés et
36 ajoutés (16 603 → 16 639 entrées).

Corrections notables apportées par la référence :

| GUID | Avant | Après |
|---|---|---|
| `{b98a2bea-…}` | Windows 7 File Recovery | **Backup And Restore** (nom actuel du composant) |
| `{c57a6066-…}` | AppSuggestedLocations | **Application Suggested Locations** |
| `{d4480a50-…}` | CLSID Add Network Place | **Add Network Place** (préfixe parasite retiré) |
| `{0cd7a5c0-…}` | Cabinet Shell Folder | **Cabinet File** |

Le module d'implémentation relevé de notre côté est **conservé** en complément du
nom (`Backup And Restore (C:\Windows\System32\shdocvw.dll)`) : savoir quel
composant sert un CLSID est une information forensique que libyal ne fournit pas.

**Limite assumée.** 14 entrées restent génériques et 637 réduites à un chemin de
module, faute d'alternative dans les données. Les 3 487 conflits n'ont pas été
vérifiés un par un — ce serait des milliers de recherches, et les sources se
contredisent sur les CLSID non documentés. Seuls les identifiants couverts par
libyal font autorité ; les autres reposent sur le critère ci-dessus.

### 14.12 Progression : tous les artefacts

Tous les collecteurs affichent leur avancement, sauf `system` qui ne boucle sur
rien (collecte unique et instantanée). La limitation de fréquence est faite **par
le temps** (150 ms) et non par un pas fixe : un pas en nombre d'éléments ne peut
pas convenir à la fois aux quelques dizaines de shellbags de plusieurs secondes
chacun et aux milliers d'entrées amcache instantanées.

### 14.13 ✅ `scheduledTasks` hors ligne et SUPPRESSION DE COM (2026-09-15)

**Fait.** `scheduledTasks` ne passe plus par le Task Scheduler COM. Il lit :
- les **définitions** dans les XML de `\Windows\System32\Tasks\`, extraits en brut
  (`ExtractDirectoryTreeRaw`, nouvelle extraction récursive) ;
- l'**historique** (`LastRun`, `LastTaskResult`) dans `DynamicInfo` sous
  `SOFTWARE\…\Schedule\TaskCache\Tasks\{GUID}`, relié par `TaskCache\Tree`.

**COM est entièrement supprimé** : `com.h`/`com.cpp` effacés, `CoInitializeEx` /
`CoInitializeSecurity` retirés, `-ltaskschd` retiré du lien. Disparaissent avec
lui la sollicitation du service Schedule, les entrées dans
`Microsoft-Windows-TaskScheduler/Operational`, et le parcours COM tâche par tâche.

`ole32`, `oleaut32` et `propsys` restent liés : `CLSIDFromString`,
`VariantTimeToSystemTime` et `PSGetNameFromPropertyKey` sont des fonctions
utilitaires (conversion, lecture d'un schéma de propriétés), non des activations
de composants — elles n'exigent pas `CoInitializeEx`.

**Résultat mesuré en VM : 252 tâches contre 194 via COM, aucune perte.**
Les 58 de plus sont des tâches système que l'énumération COM ne remontait pas.

**Nouveau module** : `xml_light.{h,cpp}`, lecteur XML minimal et autonome. MSXML
aurait été plus simple mais c'est un composant COM : l'utiliser aurait annulé le
bénéfice recherché. Le périmètre est assumé et documenté (pas de namespaces
dynamiques, pas de DTD) ; l'analyse est défensive, car les fichiers viennent
d'une machine suspecte.

**Deux pièges rencontrés, tous deux liés à la CASSE :**

1. En comparant l'ancien et le nouveau JSON, 9 tâches semblaient **perdues**
   (dossier `\Microsoft\Windows\input\`). Faux : l'index NTFS porte `Input`, COM
   renvoyait `input`. Ma comparaison était sensible à la casse. Leçon : comparer
   des chemins Windows sans normaliser la casse produit de fausses régressions.

2. Mais cette même différence causait un **vrai** défaut : le rattachement de
   l'historique se fait par chemin, et `historiques.find(t.path)` échouait en
   silence — la tâche ressortait sans `LastRun`, ce qui se lit à tort comme
   « jamais exécutée ». Corrigé par une comparaison en minuscules ; l'historique
   de 2 tâches supplémentaires est ainsi récupéré.

Le second cas est le plus instructif : la donnée était présente, collectée, et
simplement pas reliée. Aucun contrôle de syntaxe ne pouvait le voir.

**Perte assumée** : `NextRun` et `NumberOfMissedRuns`, que le planificateur
calcule à chaud et ne stocke pas. Ce sont des projections, sans valeur probante.
Les champs restent émis, vides, pour ne pas casser le schéma de sortie.

**Gains annexes** : `RegistrationDate` et `SourceXml` (chemin du XML d'origine,
pour la traçabilité) sont désormais publiés, ainsi que `WorkingDirectory` et
`StartBoundary` des déclencheurs, absents de la version COM.

**Défauts corrigés dans `to_FriendlyName`** au passage (elle reste utilisée par
les property stores) : `PWSTR out` non initialisé mais testé, retour de
`PSGetNameFromPropertyKey` ignoré, chaîne allouée jamais libérée (fuite par
propriété lue), retour de `CLSIDFromString` non vérifié sur un GUID malformé.

### 14.14 ✅ `systemInfo`, `services` et `users` hors ligne — §9.4ter achevé (2026-09-15)

La bascule prévue au §9.4ter est terminée. Il ne reste en live que `processes`
et `sessions`, dont l'objet *est* l'état instantané, et `events`, dont la source
hors ligne existe mais n'est pas encore exploitée (§14.3).

#### `systemInfo`

Sources : `SYSTEM\CurrentControlSet\{Control\ComputerName, Services\Tcpip\Parameters,
Control\Session Manager\Environment}` et `SOFTWARE\Microsoft\Windows NT\CurrentVersion`.

Disparaissent : `GetComputerNameExW` (résolution DNS du nom de domaine),
`RtlGetVersion`, et surtout **le chargement de `winbrand.dll`** dans le processus
de collecte — le seul de ces appels qui modifiait l'état du système examiné.

Trois corrections sont venues avec la bascule :

1. **Piège `ProductName`.** Sous Windows 11, cette valeur annonce toujours
   « Windows 10 » ; Microsoft ne l'a jamais mise à jour. Le seul discriminant
   fiable est `CurrentBuild >= 22000`. Sans correction, le rapport aurait nommé
   un OS faux, c'est-à-dire une **erreur de fait dans une pièce d'enquête**.
   `ProductNameRaw` conserve la valeur brute, et n'est émis que lorsqu'il diffère
   du libellé retenu — la correction reste ainsi vérifiable sans faire doublon.
2. **Champs sans source omis, pas émis vides.** Une clé présente mais vide se lit
   comme un échec de lecture : l'analyste ne peut pas distinguer « la ruche ne
   porte pas cette valeur » de « WAC n'a pas su la lire ».
3. **Heure d'été déduite.** La ruche ne stocke pas de drapeau : la comparaison
   `ActiveTimeBias` ≠ `Bias` le donne. `TimeZoneSource` dit laquelle des deux
   origines (ruche du suspect / machine d'exécution) a servi.

Champs ajoutés, tous issus des mêmes clés : `InstallDate` (source `InstallTime`
REG_QWORD, repli `InstallDate` temps Unix), `DisplayVersion`, `EditionId`,
`InstallationType`, `BuildLabEx`, `RegisteredOwner`, `RegisteredOrganization`,
`ProductId`, `SystemRoot`, `MachineGuid`, `NetbiosName`.

#### `services` — configuration hors ligne, état volatil complété

La décision réservée au §9.4ter (« le seul cas où supprimer la trace coûte une
donnée qui en est une ») se résout **sans compromis** : la configuration vient de
la ruche, l'état courant d'**une seule** énumération du SCM.

L'empreinte DIMINUE alors que la donnée AUGMENTE. Avant : un `OpenServiceW` +
`QueryServiceConfigW` par service, soit plusieurs centaines d'ouvertures de
handle — et de surcroît avec `SC_MANAGER_ALL_ACCESS` là où un droit de lecture
suffisait, ce qui faisait échouer la lecture sur les services protégés. Après :
un `EnumServicesStatusExW`, en lecture, et rien d'autre.

Ce que la ruche apporte en plus :

| Champ | Pourquoi il compte |
|---|---|
| `LastWriteTime` | instant de création ou de modification du service — aucune API du SCM ne le donne, et c'est souvent la donnée la plus parlante |
| pilotes | l'énumération filtrait sur `SERVICE_WIN32` et **excluait tous les pilotes**, alors qu'un pilote malveillant est un vecteur de persistance majeur |
| `ServiceDll` | pour un service hébergé dans `svchost.exe`, `ImagePath` ne nomme que svchost : la DLL est le code réellement exécuté |
| `FailureCommand` | commande relancée en cas d'échec, détournée comme persistance |
| `Description`, `Group`, `DependOnService`, `ErrorControl` | contexte de chargement |

`LiveStatusAvailable` accompagne `Status` : sans ce drapeau, « arrêté » et « état
non relevé » se confondraient.

##### Deux convertisseurs faux, corrigés

- **`serviceState_to_wstring` inversait le sens.** Il comparait `dwCurrentState`
  aux constantes `SERVICE_ACTIVE` (1), `SERVICE_INACTIVE` (2) et
  `SERVICE_STATE_ALL` (3) — qui ne sont pas des états mais des **filtres
  d'énumération**, d'un espace de valeurs différent. Un service `SERVICE_STOPPED`
  (1) était donc rapporté « SERVICE_ACTIVE », et un service `SERVICE_RUNNING` (4)
  « SERVICE_STATUS_UNKNOWN ». Le champ `Status` affirmait l'inverse de la réalité.
- **`serviceType_to_wstring` ignorait la nature de champ de bits.** Il comparait
  par égalité : un service interactif (0x110 = `WIN32_OWN_PROCESS |
  INTERACTIVE_PROCESS`) ne correspondait à aucune constante. Pire, le test
  `type == SERVICE_WIN32` (0x30 = OWN|SHARE) ne pouvait **jamais** correspondre à
  un service réel. Les drapeaux sont désormais décomposés et concaténés, les bits
  hors vocabulaire signalés en hexadécimal plutôt que perdus.

##### Résolution du chemin du binaire

`ImagePath` prend des formes qu'aucune API ne normalise hors ligne :
`\SystemRoot\System32\drivers\x.sys`, `\??\C:\…`, `system32\svchost.exe -k …`,
`"C:\Program Files\App\x.exe" /service`. La version d'origine coupait sur la
première occurrence de « -» ou « /», y compris **à l'intérieur du chemin** : un
binaire installé dans un dossier contenant un tiret voyait son chemin tronqué et
son MD5 jamais calculé. La coupure se fait désormais après l'extension, seul
repère fiable de la fin du chemin.

#### `users` — ruche SAM

`SAM\Domains\Account\Users\<RID hex>`, valeurs `F` (taille fixe : horodatages,
RID, drapeaux ACB, compteurs) et `V` (taille variable : nom, nom complet,
commentaire, via une table d'offsets relatifs à `0xCC`). Offsets alignés sur
RegRipper (`samparse.pl`) et creddump, qui concordent.

Les **empreintes de mots de passe** (`V`, offsets `0x9C` et `0xA8`) sont
délibérément ignorées : elles n'établissent aucun fait utile à l'enquête et leur
présence dans un fichier de sortie créerait un risque sans contrepartie.

Le SID complet est recomposé depuis le SID de machine — 12 derniers octets de la
valeur `V` de `SAM\Domains\Account` — et le RID. Un RID seul ne s'interprète pas
et ne se corrèle avec aucun autre artefact.

Ajouts par rapport à `NetUserEnum` : `AccountModified` (dernière écriture de la
clé du compte), `LastBadPassword`, `BadPasswordCount`, `LogonCount`,
`PasswordLastSet`, `AccountExpires`, `AccountFlags` décomposés, `Comment`.

##### Ce qui ne pouvait pas basculer, et pourquoi

`conf.profiles` — la liste SID → chemin de profil — est **un prérequis de
l'extraction elle-même** : sans elle, on ne sait pas où se trouvent les
`ntuser.dat` et `usrClass.dat` à extraire. Elle doit donc être connue avant
qu'aucune ruche ne soit disponible hors ligne.

Elle est désormais relevée par `loadProfileList()`, qui énumère la seule clé
`HKLM\SOFTWARE\…\ProfileList` dans le registre vivant. Cela remplace
`NetUserEnum` + `NetUserGetInfo` **par compte** — autant d'allers-retours RPC
vers LSASS pour obtenir la même liste de chemins.

Prérequis livré : `\Windows\System32\config\SAM` (et ses `.LOG1`/`.LOG2`) ajouté
à `ExtractHivesRaw()`.

#### Un quatrième double-décalage évité, détecté par le harness

`InstallDate` a d'abord été émis via `timeToIso8601Local(installDateUtc)` : la
valeur UTC était simplement **ré-étiquetée** `+02:00` sans être convertie. Le
contrôle croisé de `check-json.py` l'a relevé immédiatement — « `InstallDate` et
`InstallDateUtc` portent la même heure murale » —, exactement le défaut que ce
contrôle avait été écrit pour attraper (§14.5).

La correction a révélé un défaut **latent et général** : le motif
`FileTimeToLocalFileTime` + `timeToIso8601Local`, employé sur ~25 sites, applique
le décalage de la machine qui **exécute** WAC tout en apposant l'étiquette du
fuseau du **suspect**. Les deux coïncident en collecte live, mais divergent dès
qu'une image est analysée ailleurs : la valeur et son étiquette ne parleraient
plus du même fuseau.

Corrigé **à la source** plutôt que site par site : `utcVersLocalSuspect()`
remplace `FileTimeToLocalFileTime()` partout et tire son décalage de
`conf.timeZone`, la même source que `localUtcOffsetString()`. Un seul point de
vérité. `utcTimeToIso8601Local()` complète la famille de formatage.

*Réserve connue* : `sessions` s'exécute avant l'ouverture des ruches, donc avec
le repli sur la machine d'exécution. Sans effet en collecte live — le seul mode
supporté —, mais à revoir si l'analyse d'images montées devient un cas d'usage
(cf. §14.7, ordre des phases).

#### Nettoyage consécutif à la suppression de COM

Devenus morts et supprimés : `task_trigger_type`, `task_action_type`,
`task_state` (types de `taskschd.h`), `wstring_to_bstr`, `bstr_to_wstring`, et
les inclusions `<taskschd.h>`, `<comutil.h>`, `<comdef.h>`, `<Wbemidl.h>`.

`enMinuscules()` est remontée dans `tools` : `services` et `users` en ont besoin
pour le même motif que `scheduledTasks` — Windows ne s'accorde pas avec lui-même
sur la casse, et une correspondance sensible à la casse échoue **en silence**
(§14.13).

Deux empreintes d'audit corrigées : `Footprint::SCM` décrivait « ouverture de
handles », ce qui n'est plus la réalité ; `users` déclarait `Footprint::WMI`
alors qu'il passait par netapi32 — une empreinte fausse dans un journal d'audit
vaut moins que pas d'empreinte. `WMI` n'ayant plus d'emploi a été remplacée par
`COMPTES_LOCAUX`.

#### Champs vides retirés

`NextRun`, `NextRunUtc` et `NumberOfMissedRuns` étaient émis vides dans
`ScheduledTasks.json` « pour ne pas casser le schéma ». Un champ
systématiquement vide laisse présager un logiciel qui ne fonctionne pas : ces
projections ne sont plus émises du tout. La règle vaut pour la suite — une clé
absente dit « la donnée n'existe pas hors ligne », une clé vide dit « la lecture
a échoué », et les deux ne doivent pas se confondre.

#### Défauts trouvés en validant la bascule

La lecture hors ligne a fait remonter quatre défauts qui préexistaient ou que la
bascule aurait introduits. Aucun n'aurait provoqué d'erreur visible : tous
produisaient du JSON valide et faux.

**1. `getRegMultiSzValue` ne lisait que la première chaîne, répétée.** La boucle
relisait `donnees` à chaque tour sans jamais avancer le pointeur ; seul le
compteur de position progressait. Toute valeur `REG_MULTI_SZ` ressortait donc
comme sa première chaîne, dupliquée autant de fois qu'il y avait de caractères à
parcourir — `"DependOnService": ["RPCSS","RPCSS","RPCSS","RPCSS","RPCSS"]`. Le
défaut touchait aussi `HardwareId` dans `reg_usbstors`, donc l'identification des
périphériques USB, depuis l'origine. La borne est désormais calculée sur le
tampon, sans faire confiance à un `\0` final qu'une valeur tronquée n'aurait pas.

**2. `SERVICE_USER_*` ne sont pas des bits simples.** `SERVICE_USER_OWN_PROCESS`
vaut 0x50 et `SERVICE_USER_SHARE_PROCESS` 0x60 : ce sont des *combinaisons* de
`SERVICE_USER_SERVICE` (0x40) avec le bit « own » (0x10) ou « share » (0x20). Les
tester avec un `&` simple les faisait apparaître dès que le bit partagé était
posé — un service ordinaire de type 0x20 ressortait
`SERVICE_WIN32_SHARE_PROCESS|SERVICE_USER_SHARE_PROCESS`, ce qui est
contradictoire. Seuls les bits élémentaires sont désormais décodés ; le résidu
0x80 s'est révélé être `SERVICE_USERSERVICE_INSTANCE`, qui manquait à la table.

**3. Toutes les sous-clés de `Services` ne sont pas des services.** 44 entrées
sortaient sans `Type` ni `ImagePath` : ce sont des conteneurs de paramètres
(`WinSock2`, `Tcpip\Parameters`, `EventLog\…`). Les émettre remplissait
`services.json` d'entrées vides, qui se lisent comme des lectures échouées. La
présence de `Type`, obligatoire pour tout service enregistré, sert de critère ;
ce qui est écarté est journalisé.

**4. Références de ressource MUI.** La ruche stocke la plupart des noms affichés
sous la forme `@%SystemRoot%\system32\schedsvc.dll,-100` — un fichier et
l'identifiant d'une chaîne à l'intérieur. Seul `LoadStringW` la résout, donc en
chargeant ce module dans le processus de collecte : précisément ce que la bascule
supprimait pour `winbrand.dll`.

Le choix retenu n'est pas de résoudre, mais de **nommer honnêtement** : un texte
lisible va dans `DisplayName` / `Description` / `CurrentTimeZoneCaption`, une
référence non résolue dans `DisplayNameResource` / `DescriptionResource` /
`CurrentTimeZoneCaptionResource`. Présenter `@tzres.dll,-301` comme un nom de
fuseau afficherait un défaut de lecture à la place d'une donnée. Rien n'est
perdu : `Name` (nom interne du service) est l'identifiant qu'emploient les
journaux et les commandes, et `CurrentTimeZoneId` (« Romance Standard Time »)
suffit à interpréter les heures locales.

#### Piège de maintenance consigné

Les drapeaux de compte lus dans la valeur `F` du SAM sont les **ACB**, pas les
`UF_*` de `lmaccess.h`. Les deux espaces se ressemblent mais sont décalés :
`ACB_DISABLED` vaut 0x0001, `UF_ACCOUNTDISABLE` vaut 0x0002. Remplacer ces
valeurs par les constantes `UF_*` « pour faire propre » inverserait la lecture de
tous les comptes. Elles sont écrites en clair dans `users.cpp`, avec ce
commentaire en garde.

#### Dépendance supprimée

`netapi32` n'est plus lié : plus aucun appel `Net*` ne subsiste. Retiré de
`build-windows.sh` et, avec `taskschd.lib` et `comsupp.lib`, de `WAC.vcxproj`.

#### Effet de bord assumé sur `conf.profiles`

`loadProfileList()` énumère **tous** les profils de `ProfileList`, y compris ceux
des comptes de service (`S-1-5-18` → `…\config\systemprofile`, `S-1-5-19`,
`S-1-5-20`), que `NetUserEnum` ne rendait pas. Leurs `ntuser.dat` existent
réellement et sont désormais extraits et analysés.

C'est un gain — un attaquant qui s'exécute en SYSTEM laisse des traces dans ce
profil (shellbags, MRU, UserAssist) — au prix de trois ruches supplémentaires à
extraire et à parcourir.

#### Deux défauts révélés par les profils système

L'arrivée des profils de comptes de service dans `conf.profiles` a fait remonter
deux défauts qui ne pouvaient pas se manifester avant, `NetUserEnum` ne rendant
que les comptes ordinaires.

**`ProfileImagePath` est un `REG_EXPAND_SZ`.** Pour les comptes de service, il
vaut littéralement `%systemroot%\system32\config\systemprofile`. Sans
développement, le chemin ne désigne aucun fichier et l'extraction brute de leur
`ntuser.dat` échoue — sans message, l'extraction se contentant de rapporter un
succès *partiel* (`S_FALSE`) dont la cause restait invisible.
`loadProfileList()` développe désormais les variables, et journalise la valeur
avant et après.

**`replaceAll` pour retirer la lettre de lecteur.** Le passage du chemin absolu
au chemin relatif au volume se faisait par `replaceAll(chemin, "C:", "")`, ce qui
retire **toutes** les occurrences et non le seul préfixe. Remplacé par
`cheminRelatifAuVolume()`, qui ne retire la lettre qu'en tête et compare sans
tenir compte de la casse.

#### Qualification de `S_FALSE` dans le journal d'audit

`auditRecord()` traduisait tout code non nul par `getErrorMessage()`. Or
`S_FALSE` vaut 1, que la table Win32 rend « Fonction incorrecte » : un succès
partiel se lisait donc comme une panne dans `investigation.json`. Il est
désormais qualifié `PARTIEL`. Dans une pièce d'enquête, un résultat mal qualifié
vaut moins que pas de résultat.

### 14.15 ✅ `processes` : suppression d'`OpenProcess` (2026-09-15)

`processes` reste en collecte live — son objet *est* l'état instantané — mais la
façon de le lire était à la fois la plus intrusive possible et la moins
informative.

#### Ce qui était fait, et ce que ça coûtait

La version d'origine ouvrait un handle par processus avec `PROCESS_ALL_ACCESS`,
puis son jeton avec `TOKEN_ALL_ACCESS`, **alors que seul le SID du propriétaire
était lu**. Trois conséquences :

1. **Les processus protégés refusaient l'ouverture.** Sur la VM de test, 16
   processus sur 125 sortaient sans propriétaire : `System`, `Registry`, `smss`,
   `csrss` (×2), `wininit`, `services.exe`, `lsass.exe`, `MsMpEng.exe`,
   `NisSrv.exe`, `SecurityHealthService.exe`, `Memory Compression`, plusieurs
   `svchost`. C'est-à-dire exactement ceux dont l'usurpation compte le plus dans
   une investigation.
2. **L'échec du jeton emportait les modules.** Le constructeur faisait `return`
   avant l'appel à `ListProcessModules()`, si bien que ces 16 processus
   sortaient aussi sans **aucun** module — alors que l'instantané Toolhelp ne
   dépend pas du jeton. Les deux lectures sont indépendantes ; les enchaîner
   faisait perdre la seconde à chaque échec de la première.
3. **`ModulesMessage` portait l'erreur du jeton.** D'où le message
   « Impossible de créer un fichier déjà existant » sur ces mêmes processus :
   incompréhensible, et sans rapport avec les modules.

Demander un accès total en écriture et en injection sur chaque processus est par
ailleurs l'empreinte la plus lourde possible, et le motif que surveillent les
protections en place.

#### Ce qui est fait maintenant

Plus aucun `OpenProcess` ni `OpenProcessToken`. Le SID **et** la session
viennent d'un seul appel `WTSEnumerateProcessesExW`, qui les rend pour tous les
processus sans ouvrir de handle — y compris les protégés. Le service Terminal
Services est déjà sollicité par `sessions` : aucune empreinte nouvelle.

| | avant | après |
|---|---|---|
| handles de processus ouverts | 125 (`ALL_ACCESS`) | 0 |
| processus sans propriétaire | 16 | 1 (le processus Idle, qui n'a pas de jeton) |
| champ `SessionId` | absent | présent, corrélable avec `Sessions.json` |

`ModulesMessage` ne porte plus que l'erreur des modules — « Accès refusé » sur
les processus protégés, ce qui est le fait exact.

##### Déclaration manquante dans mingw-w64

`WTSEnumerateProcessesExW` est exporté par `wtsapi32.dll` depuis Vista et le
symbole est présent dans `libwtsapi32.a`, mais `wtsapi32.h` de mingw-w64 ne le
déclare pas — contrairement à `WTSEnumerateSessionsExW`, juste à côté. Le
prototype est donc repris tel qu'il est documenté, dans `processes.cpp`. Préféré
à un `GetProcAddress`, qui imposerait un `LoadLibrary` sur une DLL déjà liée.

#### Un faux grave, préexistant : les modules du PID 0

`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0)` ne désigne pas « le processus
0 » mais **le processus courant**. Le processus Idle se voyait donc attribuer les
25 modules de WAC lui-même, `C:\wactest\WAC.exe` en première position : le
rapport affirmait que le processus système avait chargé l'outil de collecte.

Le processus Idle n'a ni image ni module ; il est désormais traité à part, avec
la raison inscrite dans `ModulesMessage`. Le harnais rejette maintenant toute
sortie où un processus porte `WAC.exe` parmi ses modules, et toute sortie où un
processus autre que le PID 0 est sans propriétaire.

### 14.16 Passe `-Wall -Wextra` : code mort et un résultat ignoré (2026-09-15)

> Les §14.16 à §14.20 relèvent du barème permanent de qualité (code mort,
> mémoire, exactitude du décodage, nommage) et non de la migration hors ligne,
> achevée au §14.15. Ils sont consignés ici parce que c'est la revue des
> collecteurs basculés qui les a mis au jour.
>
> Ces six sections ont un point commun qui vaut d'être retenu : **aucun de ces
> défauts ne produisait d'erreur**. Le programme se terminait avec le code 0,
> les JSON étaient valides, les clés attendues étaient présentes. Seules les
> *valeurs* étaient fausses — un état de service inversé, un hash tronqué, vingt
> mille chemins vides, un SID lu dans de la mémoire libérée. C'est pourquoi les
> contrôles croisés du harnais ont été systématiquement étendus à chaque
> trouvaille : ils sont le seul filet capable de les revoir.

Le projet compilait sans `-Wall`. La passe a remonté **46 déclarations locales
inutilisées** réparties sur 15 fichiers (`nSubkeys`, `nValues`, `tailleTampon`,
`sousCle`, `nomValeur`… vestiges de boucles d'énumération remaniées). Supprimées
après vérification, une par une, qu'aucune ne portait d'effet de bord : la
suppression n'a été automatisée que pour les lignes de la forme `type nom = <0 |
NULL | L"" | {0} | false>;`, tout le reste étant traité à la main.

Deux cas n'étaient pas du code mort :

**`GetVolumeInformationW` dont le résultat était ignoré** (`getVolumeLetter`).
Sur un volume sans média — lecteur de carte vide, lecteur optique — l'appel
échoue et `serial_number` reste à zéro. On comparait donc un numéro de série nul,
si bien qu'une recherche de « 0 » aurait pu désigner un volume au hasard. L'échec
fait maintenant passer au volume suivant, avec trace au journal.

**Un commentaire `//` terminé par `\`** dans `tools.cpp` : GCC avertissait d'un
« multi-line comment ». Sans conséquence ici — la ligne suivante était vide —
mais toute insertion à cet endroit aurait été silencieusement commentée.

Laissés volontairement en place : les champs **lus dans un format binaire mais
non encore émis** (`idList.cpp` `wstring2Size` et deux `size`, `recent_docs.cpp`
`labeloffsetunicode`, plusieurs dans `prefetchs.cpp` : `nb_entries`,
`trace_offset`, `nb_traces`, `volume_size`). Ce ne sont pas des variables
oubliées mais des **parties de format décodées et non exploitées** : elles
relèvent du §14.4, pas du nettoyage. Les supprimer effacerait la trace du travail
restant.

`prefetchs.cpp` a pour cette raison été exclu de la passe automatique.

#### Deux défauts de parsing `.lnk` révélés par la passe

Parmi les « variables inutilisées » de `recent_docs.cpp` se cachaient deux
défauts de décodage bien réels.

**`arguments_size` lu au mauvais offset.** La ligne était

```cpp
arguments_size = *reinterpret_cast<unsigned short int*>(buffer + workingDirectory_offset);
```

— l'offset du **répertoire de travail** au lieu de celui des arguments. Or les
cinq champs StringData d'un `.lnk` se suivent, chacun donnant la position du
suivant par sa longueur : un seul décalage faux décale tout ce qui suit.
`iconLocation`, calculé à partir de cette taille, était donc lu au mauvais
endroit — valeur fausse, ou lecture hors du fichier.

**Les longueurs annoncées n'étaient pas utilisées du tout.** MS-SHLLINK §2.4 :
chaque champ StringData est un compteur de caractères sur deux octets suivi des
caractères, **sans terminateur nul**. Le code construisait la chaîne jusqu'au
premier zéro rencontré : correct par accident quand Windows en écrit un, sinon
la chaîne débordait sur le champ suivant. Sur un raccourci tronqué ou forgé, la
lecture sortait du tampon — et `parseLNK()` ne recevait même pas la taille du
fichier, donc **aucune** lecture ne pouvait être bornée.

Corrigé par un `lireStringData()` unique qui respecte le compteur et vérifie
chaque accès contre la taille du tampon, désormais passée en paramètre. Les cinq
champs se lisent en cinq lignes au lieu de quarante, chacun avançant le curseur.

#### Deux défauts de gestion mémoire dans `jumplist_custom`

**`CustomDestination::categorie` n'était jamais libéré.** Le pointeur était nu et
n'était rendu que par `CustomDestination::clear()` — que rien n'appelait, car
`JumplistCustoms::clear()` vide le vecteur, ce qui détruit les éléments sans
passer par cette méthode. Chaque Custom Destination fuyait donc sa catégorie
entière, avec son vecteur de `RecentDoc` et les listes d'ID qu'ils contiennent.
Remplacé par un `std::unique_ptr` : la propriété est portée par le type.

**`clear()` déréférençait un pointeur nul.** `categorie->clear()` était appelé
sans garde, alors que `toJson()`, juste au-dessus, teste explicitement
`if (categorie)` — le pointeur est nul dès qu'un Custom Destination ne porte pas
de `.lnk`.

`CustomDestinationCategory` déclare `toJson()` virtuelle sans destructeur
virtuel : ajouté également.

Dans `jumplist_automatic`, `catch (const std::exception e)` attrapait par
valeur, tronquant l'exception à sa classe de base.

### 14.17 Passe mémoire : quatre fuites, un double `delete[]`, un pointeur pendouillant (2026-09-15)

La règle « aucune fuite à l'exécution » du barème de qualité a été appliquée aux
collecteurs qui allouent des tampons de fichiers. Tous les défauts trouvés ont la
même forme : un pointeur nu libéré à la main **en un seul endroit**, alors que la
fonction peut sortir ailleurs.

#### `prefetchs.cpp` — le plus sérieux

Deux tampons nus, `buffer` (contenu brut du `.pf`) et `data` (contenu
décompressé), libérés en fin de fonction. Deux défauts distincts :

- **quatre sorties en erreur** (espace de travail de décompression, échec
  d'allocation, version non gérée, signature) rendaient la main sans rien
  libérer ;
- surtout, quand le Prefetch n'est **pas** compressé, le code faisait
  `data = buffer` — et la fin de la fonction exécutait `delete[] data` **puis**
  `delete[] buffer`, soit un **double `delete[]` sur le même bloc**, donc une
  corruption du tas. Le cas est rare sous Windows 10 et 11, où les Prefetch
  portent l'en-tête `MAM` compressé, mais un seul fichier non compressé suffit à
  compromettre la collecte entière.

Corrigé par deux `std::unique_ptr<BYTE[]>` ; `data` redevient une simple vue,
non propriétaire.

#### `jumplist_automatic.cpp` et `jumplist_custom.cpp`

Même motif : le tampon du fichier `.automaticDestinations-ms` n'était libéré
qu'à la toute fin, alors que **quatre `return` prématurés** quittent la fonction
avant — échec d'analyse OLE, `DestList` vide ou illisible. Or ces cas sont
fréquents sur une machine réelle, où beaucoup de jumplists sont vides ou
partiels : le contenu entier du fichier fuyait à chaque fois.

#### `sessions.cpp` — un SID lu après libération

Trois défauts imbriqués dans le même constructeur :

1. `PSECURITY_LOGON_SESSION_DATA data = new SECURITY_LOGON_SESSION_DATA();`
   — `LsaGetLogonSessionData` **alloue elle-même** la structure et écrase le
   pointeur. Le bloc issu de `new` était perdu à chaque session.
2. En cas d'échec de cet appel, `LsaFreeReturnBuffer(data)` aurait rendu à
   l'allocateur de LSA un bloc qu'il n'avait pas fourni.
3. **Le plus grave** : `sid = data->Sid;` copiait un *pointeur* vers la structure
   de LSA, libérée deux lignes plus bas. `toJson()` s'exécutant plus tard,
   `ConvertSidToStringSid` lisait de la mémoire déjà rendue. Le SID était juste
   **par hasard**, aussi longtemps que le bloc n'avait pas été réutilisé — un
   défaut qui aurait produit des SID faux de façon intermittente, c'est-à-dire
   le pire cas possible pour une pièce d'enquête.

Le membre est désormais un `std::wstring`, converti pendant que la structure de
LSA est encore valide.

#### `prefetchs.cpp` — signature jamais vérifiée et hash mal formé

La constante `0x41434353` (« SCCA ») était déclarée et **jamais comparée** au
champ lu. Tout fichier déposé dans `\Windows\Prefetch` était donc décodé comme un
Prefetch : les offsets lus au hasard produisaient soit des lectures hors du
tampon, soit des dates et des noms inventés dans le rapport. Une signature
absente n'est pas une erreur de collecte — c'est le constat que le fichier n'est
pas un Prefetch, et c'est en soi un fait à consigner.

Le **hash du chemin**, celui qui apparaît dans le nom du fichier
(`CMD.EXE-89305D47.pf`) et qui permet de rattacher un Prefetch au chemin
d'origine de l'exécutable, était construit en insérant quatre octets dans un flux
sans largeur imposée : un octet inférieur à `0x10` sortait sur **un seul
chiffre**. Le hash ne correspondait alors plus au nom du fichier et la
corrélation échouait en silence. Formaté en `%08X`. Une première affectation
depuis les octets bruts, juste au-dessus, était par ailleurs morte : écrasée
deux lignes plus loin.

**Mesuré sur le dernier run avant correction : 65 hash faux sur 270, soit 24 %.**
`CMD.EXE-0BD30981.pf` donnait `bd3981` — le zéro de tête *et* le zéro interne
perdus ; `DLLHOST.EXE-0D543808.pf` donnait `d54388`.

Le même défaut frappait le **numéro de série du volume**, formaté de la même
façon et comparé à celui rendu par `getVolumeLetter()`. Conséquence : sur tout
volume dont le premier octet est inférieur à `0x10`, la comparaison échouait et
`MountPoint` restait vide — le Prefetch perdait le lecteur d'origine de
l'exécutable. Les deux côtés de la comparaison utilisent désormais `%08X`, la
forme canonique et celle qu'emploie le nom de fichier.

**Contrôle croisé ajouté au harnais.** Le hash est décodé depuis l'en-tête
binaire, le nom du fichier est une donnée *indépendante* : s'ils divergent, le
décodage est faux. `check-json.py` rejette désormais toute sortie où un `Hash` ne
correspond pas au suffixe du nom de fichier. C'est ce contrôle qui a chiffré le
défaut — et le genre de contrôle qui manquait au §14.2.

#### `getVolumeLetter` — réécrite

Cette fonction, qui retrouve la lettre d'un volume à partir de son numéro de
série (utilisée par `prefetchs` pour restituer le point de montage), cumulait
quatre défauts :

1. **Comportement indéfini sur le chemin d'échec.** `return Names;` alors que
   `Names` valait `NULL` et que la fonction rend un `std::wstring` : construire
   une chaîne depuis un pointeur nul.
2. **La boucle de redimensionnement ne s'exécutait jamais.**
   `while (Success == ERROR_MORE_DATA)` comparait un `BOOL` (0 ou 1) au code 234.
   Si le tampon initial ne suffisait pas, la chaîne était construite à partir de
   mémoire **non initialisée**.
3. Le `return` au milieu de la boucle abandonnait le tampon **et** le handle de
   recherche de volumes, jamais fermé.
4. `GetVolumeInformationW` dont le résultat était ignoré (cf. §14.16).

Réécrite : tampon en `std::vector`, redimensionnement testé sur
`GetLastError() == ERROR_MORE_DATA`, handle fermé sur tous les chemins, échecs
journalisés.

#### `reg_mru_apps.cpp` — 1 Mo perdu par niveau de récursion

`LPBYTE donnees = new BYTE[MAX_DATA];` réservait 1 024 000 octets d'avance, alors
que `getRegBinaryValue()` alloue lui-même à la taille exacte de la valeur : le
tampon était donc remplacé sans avoir servi. Il fuyait de surcroît **entièrement**
sur les deux sorties en erreur de la fonction, qui ne libéraient rien — et
`parse()` est récursive, donc le coût se multiplie par le nombre de niveaux de
clés. Remplacé par `NULL`, avec libération sur les deux chemins d'erreur.

Même allocation d'avance inutile dans `reg_shellbags.cpp`, également récursif.
Celui-ci ne fuyait pas (aucune sortie prématurée), mais réservait 1 Mo par niveau.

Dans `oleparser.cpp`, le tampon de la table d'allocation est passé en
`unique_ptr` par précaution : la fonction lève des exceptions un peu partout
(« file corrupt … ») et un `throw` ajouté entre l'allocation et sa libération
manuelle fuirait sans bruit.

#### Ce qui a été vérifié et laissé tel quel

`reg_userassists.cpp`, `reg_bams.cpp`, `reg_shellbags.cpp`, `recent_docs.cpp` et
`jumplist_custom.cpp` (hors le cas ci-dessus) : allocations correctement
appairées, aucune sortie prématurée entre l'allocation et la libération.

### 14.18 Quinze libellés `trans_id` corrompus par une substitution de code (2026-09-15)

La recherche des formatages hexadécimaux défectueux a fait apparaître un défaut
d'une autre nature : **une substitution destinée au code avait été appliquée aux
données**. Quinze libellés de `trans_id.cpp` portaient un fragment de C++ à la
place d'une partie de leur nom :

| Libellé trouvé | Nom réel |
|---|---|
| `IID IDispatcstd::hex` | `IID IDispatchEx` |
| `IID IIE70Dispatcstd::hex` | `IID IIE70DispatchEx` |
| `IID _SEstd::hexception` | `IID _SEHException` |
| `IID _Soapstd::hexBinary` | `IID _SoapHexBinary` |
| `IID _AmbiguousMatcstd::hexception` | `IID _AmbiguousMatchException` |
| `IID IWsstd::hexec` | `IID IWshExec` |
| `CLSID std::hex Workshop Shell Extension` | `CLSID Hex Workshop Shell Extension` |
| `IID IVsDostd::coutlineProvider` | `IID IVsDocOutlineProvider` |
| `IID IWMEnstd::coutputStats` | `IID IWMEncOutputStats` |
| `CLSID …Access.Astd::coutputObjectType` | `CLSID …Access.AcOutputObjectType` |

Deux motifs : `hEx` → `std::hex` et `cOut` → `std::cout`, insensibles à la casse
et **sans limite de mot**. Un remplacement global de `hex` et `cout` a donc
frappé les chaînes de données au passage.

La restauration a dû être faite **au cas par cas** : la casse d'origine
(`HEx` dans `_SEHException`, `hEx` dans `IDispatchEx`, `Hex` dans
`Hex Workshop`) ne se déduit pas mécaniquement — seul le nom réel de l'interface
ou du produit la donne. Chacun a été vérifié comme nom existant dans les API
Microsoft correspondantes.

**Leçon de méthode.** Une substitution mécanique appliquée à un fichier qui
mélange code et données de référence doit être bornée aux zones de code, ou
vérifiée entrée par entrée. C'est la même famille de risque que le renommage qui
avait cassé `me32.taille` / `pe32.taille` (§14.9) — sauf qu'ici le défaut ne se
voyait pas à la compilation, seulement dans la sortie.

Aucun autre fragment de C++ ne subsiste dans les libellés : la vérification a
porté sur `std::*`, `wstring`, `printf`, `nullptr`, `size_t`, `reinterpret_cast`
et une dizaine d'autres motifs. Les seules correspondances restantes sont de
vrais noms de fichiers (`odbcconf.dll`, `printfilterpipelinesvc.exe`).

### 14.19 Nommage des clés JSON : une notion, une orthographe (2026-09-15)

Suite de la passe de nommage (§14.9), côté **sortie** cette fois. Trois
incohérences rendaient la même notion introuvable selon l'artefact consulté.

> ⚠️ **Ces renommages changent le schéma de sortie.** Tout consommateur des JSON
> (tableau de bord, script d'analyse) doit être mis à jour en conséquence. Le
> tableau ci-dessous donne la correspondance complète.
>
> | Avant | Après | Fichiers |
> |---|---|---|
> | `MD5`, `md5` | `Md5` | amcache, shimcache, services, processes |
> | `md5Source`, `md5Target` | `Md5Source`, `Md5Target` | recentdocs |
> | `ServiceDllMD5` | `ServiceDllMd5` | services |
> | `PID` | `ProcessId` | processes |
> | `PPId` | `ParentProcessId` | processes |
> | `Nom` | `Name` | processes |

**Le hash MD5 s'écrivait de six façons** : `MD5` (amcache, shimcache, services),
`md5` (processes), `Md5` (prefetchs), `md5Source` et `md5Target` (recentdocs),
`ServiceDllMD5`. Un analyste cherchant « le hash » devait connaître les six.
Harmonisé sur `Md5`, `Md5Source`, `Md5Target`, `ServiceDllMd5` — la forme déjà
employée par `prefetchs`.

**L'identifiant de processus s'écrivait `PID` et `PPId` dans le même objet**,
avec deux conventions de casse, tandis que `services.json` appelait `ProcessId`
la même notion. Harmonisé sur `ProcessId` et `ParentProcessId`, explicites et
cohérents avec `SessionId`.

**`Nom` était la seule clé en français de toute la sortie**, au milieu de `SID`,
`Owner`, `ProcessId`, `ThreadCount`. Renommée `Name`, comme dans
`services.json` et `users.json`. Une vérification systématique de toutes les
sorties confirme qu'il n'en reste aucune autre.

#### `Md5` n'est plus émis vide

Sept clés `Md5` étaient émises inconditionnellement : sans `--md5`, elles
sortaient vides dans tous les artefacts. Or un champ vide se lit comme un échec
de lecture, alors que ne pas calculer les empreintes est un **choix de
l'opérateur** — déjà consigné, avec la ligne de commande complète, dans
`investigation.json`. Le champ n'est désormais présent que lorsqu'une empreinte a
réellement été calculée.

`QuickDigest5::fileToHash` a été vérifié au passage : sur un fichier introuvable,
il rend une chaîne vide et non l'empreinte du vide
(`d41d8cd98f00b204e9800998ecf8427e`) — qui serait passée pour un hash valide.

#### Empreintes mémorisées par chemin (`services`)

Les services hébergés partagent tous le même binaire : près de 200 des 697
services de la VM de test pointent sur `svchost.exe`. Avec `--md5`, son empreinte
était recalculée autant de fois, et chaque calcul relit le fichier en entier.
Un cache par chemin (insensible à la casse, comme NTFS) ramène le travail au
nombre de binaires **distincts**. Le même principe est déjà appliqué à
l'extraction brute (`md5ParFichier`, `raw_collect.cpp`).

#### Laissé en l'état, volontairement

`GUID` (8 clés) et `Guid` (9 clés) coexistent sans dominante. Renommer les dix-
sept changerait le schéma sans gain comparable : contrairement au hash, aucune
recherche transversale ne porte sur « le GUID », et plusieurs de ces noms sont
repris de la spec MS-SHLLINK (`GuidBirthDroidFile`, `GuidDroidVolume`). Les
champs `EvtSystem*` reprennent les noms officiels du schéma EVTX et ne doivent
pas être normalisés.

Ce choix mérite d'être tranché par l'utilisateur avant une éventuelle bascule :
c'est un changement de schéma, pas une correction.

### 14.20 `prefetchs` : les chemins de fichiers n'étaient jamais résolus (2026-09-15)

Le plus lourd défaut de cette revue, en volume de données perdues.

Un Prefetch liste les fichiers chargés par le programme sous la forme
`\VOLUME{01dd42b110992896-8c10a5a9}\WINDOWS\SYSTEM32\NTDLL.DLL` : un identifiant
de volume, pas une lettre de lecteur. WAC doit le traduire pour que le chemin
soit exploitable. La traduction n'était conditionnée qu'à ceci :

```cpp
if (f.filename.substr(0, 35).compare(v.deviceName) == 0) {
```

`35` est codé en dur, alors que `deviceName` fait **34** caractères
(`\VOLUME{` + 25 + `}`). Les trente-cinq caractères comparés incluaient donc la
barre oblique suivante, et la comparaison **échouait systématiquement**.

Conséquences, mesurées sur la VM de test :

| | avant | après |
|---|---|---|
| chemins de fichiers résolus | **0 / 20 066** | 20 052 / 20 052 |
| Prefetch avec `FullPath` | 0 / 273 | 261 / 273 |
| Prefetch avec `Md5` (avec `--md5`) | 0 / 273 | 261 / 273 |

L'artefact ne rendait donc **aucun chemin réel**, et aucune empreinte : pour
l'analyste, la différence entre « ce programme a chargé vingt mille fichiers
quelque part » et « voici lesquels, et voici l'empreinte du binaire exécuté ».
Le `Md5` en dépendait directement, ce qui explique qu'il sortait toujours vide,
même avec `--md5` : le défaut se présentait comme une option qui ne marche pas.

Les `Dirs` du même volume n'ont jamais eu ce défaut : ils appellent `replaceAll`
sans comparer de longueur. C'est cette asymétrie — `Dirs` résolus, `FilesStrings`
vides dans la même sortie — qui rendait le défaut visible dès qu'on regardait le
JSON de près.

Corrigé en comparant sur la longueur réelle de `deviceName`, **sans tenir compte
de la casse** : l'en-tête Prefetch écrit en majuscules, les chaînes de volume pas
nécessairement. La recherche de l'exécutable parmi les fichiers chargés est
également devenue insensible à la casse.

**Contrôle croisé ajouté** : le harnais rejette désormais toute sortie où plus de
10 % des chemins de fichiers restent non résolus. Vérifié dans les deux sens — il
signale bien `20066/20066 non résolus` sur les résultats archivés d'avant la
correction.

Les douze Prefetch qui restent sans `FullPath` sont légitimes : leur volume n'est
plus monté au moment de la collecte.

#### Journal d'audit : l'écriture des résultats était omise

`Footprint::ECRITURE_USB` était définie et employée nulle part : le journal ne
mentionnait donc jamais l'écriture des résultats, **la seule écriture que WAC
effectue**. Un journal d'audit muet sur ce point laisse croire que rien n'a été
écrit. L'opération est désormais consignée, avant `auditWrite()` — sans quoi elle
manquerait au journal qu'elle décrit.

`Footprint::AUCUNE` a été supprimée : les lectures purement en mémoire portent
sur des COPIES extraites, déjà couvertes par `RUCHE_COPIE`. Les neuf empreintes
restantes sont toutes employées.

### 14.21 Les `(Undefined)` d'une collecte réelle : trois causes distinctes (2026-09-15)

Analyse demandée sur le scan de la machine `RAVENWOOD` (build du 14:04). Les
occurrences de « undefined » relevaient de trois situations sans rapport entre
elles — dont une seule était un défaut de décodage.

#### 1. `UndefinedLogonType` dans `Sessions.json` — LÉGITIME

Deux sessions sur onze. `0` est une valeur réelle de `SECURITY_LOGON_TYPE` :
LSA la rend pour la session SYSTEM (LUID `0x3E7`) et pour les sessions sans
ouverture interactive. Ce n'est pas un échec de lecture.

Mais « Undefined » seul *se lit* comme un défaut de l'outil — c'est bien ainsi
qu'il a été compris. Deux améliorations :

- le libellé dit désormais pourquoi : `UndefinedLogonType (aucune ouverture
  interactive)` ;
- un champ `WellKnownRole` nomme les sessions dont le LUID est réservé par
  Windows (`0x3E7` SYSTEM, `0x3E6` ANONYMOUS LOGON, `0x3E5` LOCAL SERVICE,
  `0x3E4` NETWORK SERVICE).

Le mapping est confirmé de façon croisée par les SID relevés indépendamment :
LUID 997 → `S-1-5-19` (LOCAL SERVICE), LUID 996 → `S-1-5-20` (NETWORK SERVICE).

C'est aussi ce scan qui a fourni le `$` de `RAVENWOOD$` : le compte machine,
attendu pour les sessions de service.

#### 2. `"SID": ""` sur 11 sessions sur 11 — DÉFAUT, déjà corrigé

Le scan ne portait **aucun** SID de session. C'est le pointeur pendouillant du
§14.17 : `sessions` conservait `data->Sid`, un pointeur vers la structure de LSA
libérée deux lignes plus bas, et `toJson()` le relisait plus tard.

Le défaut se présentait comme intermittent « par chance » ; sur cette machine il
était **systématique**. Après correction, en VM : 10 SID sur 11. Le onzième est
une session que LSA rend réellement sans SID ni type — la même que la `90743` du
scan réel.

#### 3. `(Undefined)` sur une propriété de shell item — DÉFAUT DE CONCEPTION

Douze occurrences, toutes la même clé :
`{FFAE9DB7-1C8D-43FF-818C-84403AA3732D}/100`, soit
**`System.SourcePackageFamilyName`** — le *package family name* de l'application
du Store dont provient l'élément
([doc Microsoft](https://learn.microsoft.com/en-us/windows/win32/properties/props-system-sourcepackagefamilyname),
`formatID` et `propID` vérifiés).

**La valeur, elle, était correctement extraite** — et elle est d'un intérêt
direct pour l'enquête :

| Valeur relevée | Application |
|---|---|
| `5319275A.WhatsAppDesktop_cv1g1gvanyjgm` | WhatsApp Desktop (4 occurrences) |
| `Microsoft.ZuneMusic_8wekyb3d8bbwe` | Lecteur multimédia / Groove |
| `Microsoft.XboxGamingOverlay_8wekyb3d8bbwe` | Xbox Game Bar |
| `MicrosoftWindows.Client.CBS_cw5n1h2txyewy` | composant Windows (Recherche/Démarrer) |

Un document récent portant `WhatsAppDesktop` dit que le fichier provient d'une
messagerie : c'est exactement le genre de fait qu'une collecte doit rendre
lisible.

##### Ce que le scan a révélé de plus grave

La même clé a été **résolue 11 fois et non résolue 12 fois dans la même
collecte** :

| Artefact | Phase | Résultat |
|---|---|---|
| `shellbags.json` | registre | 11 / 11 résolus |
| `recentdocs.json` | fichiers | 0 / 3 |
| `jumplistAutomaticDestinations.json` | fichiers | 0 / 9 |

Même code (`SPSValue`), même GUID, même PID — résultat différent selon la phase.
La cause est dans l'API employée : `PSGetNameFromPropertyKey` « ne réussit que
pour les propriétés enregistrées dans le schéma de propriétés »
([doc](https://learn.microsoft.com/en-us/windows/win32/api/propsys/nf-propsys-psgetnamefrompropertykey))
et passe par le property system, donc par COM. **Son résultat dépend de l'état
du processus, pas seulement de la clé demandée.** Cette propriété est de surcroît
marquée `IsInnate` et hors index, donc absente du schéma interrogeable sur
certaines machines.

Un commentaire du code affirmait que ces fonctions « n'exigent pas
`CoInitializeEx` ». C'était une hypothèse, et la collecte réelle la contredit :
le même artefact sortait nommé ou anonyme selon la phase où il était lu. Pour une
pièce d'enquête, c'est le défaut — pas le nom manquant.

##### Correction

1. **Table statique d'abord**, API en repli. Déterministe, sans COM, identique
   sur une image morte. C'est l'approche déjà retenue pour `trans_id` (§14.11) :
   chaque entrée porte la source qui l'atteste.
2. **Plus de `(Undefined)`**. Une propriété hors table ressort désormais sous sa
   **clé brute** (`{GUID}/PID`), qui est vérifiable et permet de compléter la
   table. Le libellé précédent se lisait comme un échec de l'outil alors que la
   donnée était parfaitement lue : seul son nom était inconnu.
3. Les cas hors table sont journalisés, ce qui fournit la liste de travail du
   §14.4 à partir de collectes réelles.

**À valider sur machine réelle** : la VM de test n'utilise aucune application du
Store, cette propriété n'y apparaît donc pas. C'est le même cas de figure que le
défaut `$ATTRIBUTE_LIST` (§14.10) — certains comportements ne se voient que sur
un système en usage.

##### Ce qui reste à faire

La table ne contient qu'une entrée : celle qui a été constatée et vérifiée. Les
propriétés courantes des shell items (`System.ItemNameDisplay`, `System.Size`,
`System.DateModified`, `System.ParsingName`, `System.ThumbnailCacheId`…) sont
aujourd'hui résolues par l'API — donc **de façon non déterministe elle aussi**.
Les ajouter à la table est la suite logique, en relevant chaque `formatID` et
`propID` dans la documentation Microsoft plutôt que de mémoire.

Le scan de référence est conservé sous
`vmtest/results/REEL-20260915-1428-ravenwood/` : c'est la seule collecte de
machine réelle dont on dispose, et elle contient des cas absents de la VM.

### 14.22 Objets non décodés : rendre les octets, toujours (2026-09-15)

Question posée après l'analyse du §14.21 : « il n'y a pas d'hexa sur des objets
inconnus ? » Réponse : **deux fois sur quatre, non** — et c'était un trou, parce
qu'un objet dont on ne sait pas lire la structure doit rendre ses **octets**.
C'est la seule façon qu'un analyste puisse le décoder plus tard, et la seule qui
distingue « WAC ne sait pas lire ceci » de « il n'y avait rien ».

État des lieux :

| Objet non décodé | Avant | Après |
|---|---|---|
| shell item de type inconnu | ✅ dump hexa systématique | inchangé |
| `UsersPropertyView` de signature inconnue | journal seulement | inchangé (cf. plus bas) |
| **bloc d'extension `beef00XX` inconnu** | ❌ **journal seulement, absent du JSON** | objet `BeefUnknown` avec signature, taille et octets |
| **valeur de propriété de type `VT_` non géré** | ❌ **chaîne vide** | objet `UnsupportedValueType` + octets restants |

#### Bloc d'extension inconnu — absent du JSON

La fabrique se contentait d'écrire le dump dans le **journal** et n'ajoutait
**rien** à la liste des blocs. Le bloc était donc absent du JSON, et invisible
sauf à relancer la collecte avec `--loglevel=2`. Au niveau de journalisation par
défaut — celui du scan réel — la donnée disparaissait sans laisser de trace.

L'incohérence était nette : `UnknownShellItem` remonte son dump depuis sa
correction, les blocs d'extension non. La classe `BeefUnknown` rétablit la
symétrie.

*Effet de bord utile* : ce défaut ne laissait par construction aucune trace
mesurable, donc son ampleur sur les collectes passées est inconnue. Les
prochaines la montreront directement, par la présence d'objets `"Unknown": true`.

#### Valeur de type non géré — perdue silencieusement

`getValue` se terminait par `return Json::str(L"")`. La propriété sortait avec
son nom et son type, mais **sans valeur** — indiscernable d'une propriété
réellement vide, alors que la donnée est présente dans le fichier. Les octets
restants de l'entrée sont désormais restitués.

Types actuellement décodés : `VT_EMPTY`, `VT_NULL`, `VT_I1/I2/I4/I8`, `VT_INT`,
`VT_UI1/UI2/UI4/UI8`, `VT_UINT`, `VT_R8`, `VT_BOOL`, `VT_BSTR`, `VT_LPWSTR`,
`VT_FILETIME`, `VT_DATE`, `VT_BLOB`, `VT_STREAM`, `VT_CLSID`,
`Vector<VT_LPWSTR>`, `Vector<VT_UI1>`. Manquent notamment `VT_R4`, `VT_CY`,
`VT_ERROR`, `VT_DECIMAL` et les autres vecteurs (`Vector<VT_FILETIME>`,
`Vector<VT_CLSID>`…).

Sur la collecte réelle de `RAVENWOOD`, les 80 valeurs de property store relevées
sont **toutes** de types décodés (`VT_I8`, `VT_LPWSTR`, `VT_STREAM`, `VT_UI4`,
`Vector<VT_UI1>`) et toutes renseignées : le cas ne s'y est pas produit.

##### Conséquence plus grave dans `Property`

La taille d'une `Property` n'est pas annoncée : elle se **déduit** de
l'avancement du décodage (`size = pos`). Un type inconnu laissait donc la
position inchangée, et la propriété suivante était lue au mauvais endroit —
produisant des propriétés d'apparence normale mais **fausses**. Les deux boucles
concernées s'arrêtent désormais sur ce cas, en consignant combien de propriétés
sur combien ont été lues : mieux vaut une liste tronquée et signalée qu'une liste
complète et inventée.

Les entrées d'un property store (`SPS`), elles, sont bornées par leur propre
taille annoncée : un type inconnu n'y perd que sa propre valeur, sans décaler les
suivantes.

#### `dump_wstring` lisait un octet de trop — partout

En vérifiant ces dumps, un défaut dans la fonction elle-même : son troisième
paramètre s'appelait `end` et la boucle allait jusqu'à `x <= end`, soit un index
de fin **inclus**. Or les cinq appelants lui passaient tous une **taille** —
chacun lisait donc **un octet au-delà** de la zone voulue, y compris sur des
tampons de fichier dont la taille exacte venait du format. Le paramètre est
désormais une longueur, avec borne exclusive, et la fonction rejette les
longueurs nulles ou négatives.

#### `VT_BOOL` non canonique

Une valeur ni `0x0000` ni `0xFFFF` rendait une chaîne vide. La valeur brute est
maintenant restituée en hexadécimal et journalisée.

#### Reste à faire

`UsersPropertyView` de signature inconnue écrit encore son dump dans le seul
journal, comme le faisaient les blocs d'extension. Le corriger suppose de décider
où rattacher l'objet dans le JSON — à traiter avec §14.4.

### 14.23 Complétude des blocs `beef` et des types `VT_`, mesurée contre les références (2026-09-15)

Demande : vérifier que **toutes les définitions connues** sont implémentées, pour
les blocs d'extension puis pour les types de valeur. Méthode : comparer à
l'implémentation de référence plutôt qu'à une liste de mémoire — la table de
`trans_id` avait déjà montré ce que coûte l'approximation (§14.11).

#### Blocs d'extension `0xbeefXXXX`

Références croisées : [ExtensionBlocks](https://github.com/EricZimmerman/ExtensionBlocks)
d'Eric Zimmerman (le moteur de ShellBags Explorer), la
[spécification libfwsi](https://github.com/libyal/libfwsi) de libyal, et
[pyshellitems](https://github.com/forensicmatt/pyshellitems).

| Source | Blocs |
|---|---|
| ExtensionBlocks (Eric Zimmerman) | 28 |
| WAC | 27 |
| libfwsi (code) | 14 |
| pyshellitems | 5 |

**WAC est aligné sur la référence la plus complète, à une signature près :
`0xbeef0005`** — et celle-là, la référence elle-même ne la décode pas (son
fichier porte la mention « Unsupported Extension block »). libfwsi mentionne en
plus `0xbeef000b`, sans structure documentée non plus.

Mieux : bloc par bloc, **WAC décode ce que décode la référence**, et parfois
davantage — `beef0026` y ajoute la liste d'ID, `beef000e` le GUID et son libellé
(§14.22).

Depuis §14.22, une signature inconnue rend de toute façon ses octets : l'absence
de `0xbeef0005` n'est plus une perte de donnée, seulement une absence de
décodage — que personne au monde ne sait faire aujourd'hui.

##### Un défaut trouvé en comparant : `beef0004`

Deux manques, dont un grave.

**Les offsets du nom long étaient codés en dur (36 et 46).** Ils ne sont exacts
que pour la **version 9** du bloc — celle de Windows 8.1 et au-delà. La
référence, elle, calcule la position selon la version. Sur un bloc de version 3
(XP), 7 (Vista) ou 8 (Windows 7), WAC lisait donc le nom long **au mauvais
endroit**. C'est exactement le profil de défaut qui ne se voit pas sur une
machine récente et se révèle sur un système ancien, comme `$ATTRIBUTE_LIST`
(§14.10). La version — jusqu'ici lue nulle part (§14.19) — sert désormais à
calculer l'offset réel.

**La référence de fichier `$MFT` n'était pas lue.** Le bloc `beef0004` porte,
depuis la version 7, le **numéro d'entrée `$MFT` sur 48 bits et le numéro de
séquence sur 16**. C'est une donnée de premier ordre : elle rattache une entrée
de shellbag ou de raccourci à son enregistrement exact dans la table de
fichiers, donc permet de retrouver le fichier même renommé ou supprimé. WAC ne
la décodait pas, alors que sa lecture brute du volume exploite déjà ces
références ailleurs.

Validé en VM : 18 blocs, tous en version `0x09`, 17 marqués NTFS et 1 FAT.
`Windows` → entrée 3750 (séquence 1), `Prefetch` → 141078 (séquence 9),
`output` — créé par les tests du jour — → 202783. L'ordre des numéros suit
l'ancienneté de création, ce qui est le comportement attendu d'une MFT.

*Note* : le calcul du numéro d'entrée de la référence décale la partie haute de
24 bits ; sur un champ de 6 octets, c'est 32 qu'il faut. WAC suit la
spécification libfwsi (48 bits en petit-boutiste), pas ce calcul.

**Contrôle croisé ajouté** : les 27 premières entrées de la MFT sont réservées
aux métafichiers (`$MFT`, `$MFTMirr`, `$LogFile`…), et une séquence nulle
désigne un volume FAT. Le harnais rejette toute référence marquée NTFS dont
l'entrée est inférieure à 27 ou la séquence nulle.

#### Types de valeur `VT_`

Référence : [libfwps](https://github.com/libyal/libfwps) de libyal, la
bibliothèque de lecture des property stores.

`getType()` **nommait** déjà 52 types — la nomenclature `VARTYPE` est complète.
Mais `getValue()` n'en **décodait** que 23. Cinq types décodés par libfwps
manquaient, et sortaient donc sans valeur :

| Type | Code | Contenu |
|---|---|---|
| `VT_R4` | 0x0004 | flottant 32 bits |
| `VT_CY` | 0x0006 | monétaire, entier 64 bits ×10 000 |
| `VT_ERROR` | 0x000A | HRESULT |
| `VT_DECIMAL` | 0x000E | décimal 128 bits |
| `VT_LPSTR` | 0x001E | **chaîne ASCII** — taille en octets, non en caractères |

`VT_CY` et `VT_DECIMAL` sont restitués sans conversion : diviser ou passer par
un `double` perdrait la précision qui fait l'intérêt de ces types.

##### Les vecteurs sont désormais traités génériquement

Le bit `VT_VECTOR` (0x1000) signale un tableau : un compteur d'éléments sur 32
bits suivi des éléments du type scalaire (MS-OLEPS). **Deux vecteurs seulement
étaient reconnus** — `Vector<VT_UI1>` et `Vector<VT_LPWSTR>` — et tous les autres
(`Vector<VT_FILETIME>`, `Vector<VT_CLSID>`, `Vector<VT_I4>`, `Vector<VT_LPSTR>`…)
tombaient dans le cas « type non pris en charge ».

Décoder le compteur puis déléguer chaque élément au lecteur scalaire les couvre
tous d'un coup — et tout type scalaire ajouté plus tard bénéficie
automatiquement de sa forme vectorielle. Deux garde-fous : un compteur supérieur
à 65 536 est traité comme une donnée corrompue (les octets sont rendus), et un
élément de type non décodé arrête la boucle plutôt que de relire le même octet.

Les deux vecteurs historiques gardent leur traitement propre : celui de
`Vector<VT_UI1>` n'est pas un simple tableau d'octets mais peut contenir un
property store imbriqué (signature « SPS1 »), ce qu'aucune règle générique ne
devinerait.

#### `VT_STREAM` : le contenu du flux était jeté

Le code lisait le nom du flux, lisait la taille des données, avançait
d'autant — **et ne rendait que le nom**. Or ce nom est un identifiant
d'indirection sans portée : sur la collecte réelle, les **quinze** valeurs
`VT_STREAM` rendaient toutes `prop4294967295` (soit `propFFFFFFFF`).
L'artefact ne portait donc rien d'exploitable, alors que les données étaient là.

Le contenu est désormais restitué, avec sa taille. Quand il commence par la
signature « SPS1 », c'est un property store imbriqué : il est décodé comme tel.
Sinon, les octets sont rendus en hexadécimal.

#### `VT_BLOB` : trois property stores supposés, sans vérification

`int pos2 = 17;` puis **trois** `SPS` lus d'affilée — offset codé en dur, nombre
fixe, aucune vérification. Sur un BLOB d'une autre forme, et rien ne garantit
celle-là, les trois lectures partaient dans des octets arbitraires et publiaient
des propriétés **inventées**. Le contenu brut n'était jamais rendu.

Désormais : la taille annoncée borne la lecture, la signature « SPS1 » est
vérifiée avant de décoder, et l'on enchaîne autant de stores que le BLOB en
contient réellement. À défaut, les octets.

#### À valider sur machine réelle

La VM de test ne contient **aucune** valeur de property store dans les shellbags,
les documents récents et les jumplists — là où la collecte de `RAVENWOOD` en
compte 80. `VT_STREAM`, `VT_BLOB`, les nouveaux types scalaires et les vecteurs
génériques ne sont donc validés que par la compilation et la lecture du format.
La prochaine collecte réelle est leur premier vrai test.

### 14.24 Identification des shell items : signatures et masque de classe (2026-09-15)

Demande : vérifier les « exceptions » des idList — les signatures particulières
comme `UserPropertyView0x23febbee` — et compléter ce qui manque. Référence :
`libfwsi` de libyal, qui est la spécification du format.

#### Pourquoi des signatures MTP au milieu des « users property view »

Question posée en cours d'analyse, et la réponse éclaire tout le reste : **ce
n'est pas une anomalie, c'est l'architecture du format**.

L'octet de classe `0x00`/`0x79` désigne une **enveloppe commune** — taille, data
size, **signature à l'offset 6**, taille du property store, taille de
l'identifiant. Ce que l'enveloppe contient est déterminé par la **signature**,
pas par l'octet de classe. Vérifié dans la référence :
`libfwsi_mtp_volume_values.c` lit sa signature au *même offset 6* que
`libfwsi_users_property_view_values.c`. libyal a des fichiers séparés mais les
essaie tous sur le même item, chacun renvoyant « pas moi » si la signature n'est
pas la sienne.

Router les MTP depuis `UsersPropertyView` est donc structurellement juste. Ce qui
était faux, c'est le **nom**.

#### Deux types masqués par un nom générique

| Signature | Réalité | Nom avant |
|---|---|---|
| `0x10312005` | **volume MTP** | « UserPropertyView0x10312005 » |
| `0x07192006` | **entrée de fichier MTP** | « UserPropertyView0x07192006 » |

MTP est le protocole des appareils photo, téléphones et lecteurs multimédias. La
présence de ces items atteste qu'**un tel appareil a été branché et parcouru** —
exactement ce qu'une investigation cherche à établir. Le nom générique le
masquait entièrement. Un champ `ItemType` le nomme désormais.

#### Cinq signatures non traitées, une lue sans garde

libfwsi reconnaît six signatures de « users property view » ; WAC n'en traitait
qu'une. Les cinq autres — `0x10141981`, `0x23a3dfd5`, `0x3b93afbb`,
`0x49505241`, `0xbeebee00` — tombaient dans la branche « signature inconnue ».
Elles sont maintenant reconnues, et l'identifiant de 4 octets que trois d'entre
elles portent est relevé, comme le fait libfwsi.

Sur `0x23febbee`, libfwsi lit les 16 octets du GUID de dossier connu **sous
condition `identifier_size == 16`**. WAC ne vérifiait rien : dès que
l'identifiant avait une autre taille, il publiait un GUID composé d'octets
arbitraires — un identifiant inventé, dans une pièce d'enquête.

#### Le défaut de fond : valeurs exactes au lieu d'un masque

Le plus large, et il touche tous les idList. **libfwsi identifie la famille d'un
shell item par `class_type & 0x70`** : les bits 4 à 6 désignent le type, les bits
de poids faible ne sont que des drapeaux. `shell_item_class()` énumérait des
valeurs exactes :

| Famille | Reconnues | **Non** reconnues |
|---|---|---|
| Volume `0x2X` | 6 | **26** (0x20, 0x21, 0x22, 0x24, 0x26, 0x27, 0x28…) |
| Entrée de fichier `0x3X` | 7 | **25** (0x33, 0x34, 0x37, 0x38, 0x3A…) |
| Emplacement réseau `0x4X` | 6 | **26** (0x40, 0x43, 0x44, 0x45, 0x48…) |

Une entrée de fichier de classe `0x33` ou `0x3A` ressortait donc « UNKNOWN »,
alors qu'elle est parfaitement décodable et ne diffère que par ses drapeaux. Un
repli par masque a été ajouté **après** les valeurs exactes — celles-ci sont
vérifiées, et les classes hors famille (`0x1F`, `0x52`, `0x61`, `0x71`, `0x74`,
`0x78`, `0x79`) doivent primer.

#### Six types identifiés par une signature, pas par la classe

WAC n'identifiait un item que par son octet de classe. Or six types documentés se
reconnaissent à une signature placée **dans les données** :

| Type | Critère (libfwsi) | Taille min. |
|---|---|---|
| **dossier délégué** | GUID `{5E591A74-DF96-48D3-8D67-1733BCEE28BA}` 32 octets avant la fin | 38 |
| graveur de CD | « AugM » à l'offset 4 | 18 |
| dossier de jeux | « GFSI » à l'offset 4 | 32 |
| fichier `.cpl` | `0xFFFFFF38` à l'offset 4 | 24 |
| site web | `00 B0 01 C0` à l'offset 4 | 24 |
| archive Acronis | `52 67 B1 AC` à l'offset 2 | 50 |

Tous tombaient dans « UNKNOWN ». **Le plus coûteux est le dossier délégué** : il
enveloppe un **shell item complet** à l'offset 6 — donc un chemin, des dates,
des property stores, tout décodable — et il est courant dans les shellbags.
`DelegateFolder` décode désormais l'item imbriqué par récursion, plus le GUID de
la classe déléguée et son libellé.

Les cinq autres sont nommés par `TypedShellItem`, avec leurs octets joints :
les nommer vaut mieux que « inconnu » même sans décoder tous leurs champs.

##### L'ordre des tests compte

Les critères n'ont pas tous la même force, et libfwsi les essaie dans un ordre
précis. Deux sont **faibles** :

- celui du site web porte sur quatre octets à l'offset 4 — or c'est là qu'une
  entrée de fichier écrit sa **taille** : un fichier de `0xC001B000` octets
  serait pris pour un site web si ce test venait en premier ;
- celui de l'archive Acronis lit l'**octet de classe** lui-même.

Ces deux-là ne sont donc consultés qu'après le dispatch par classe, juste avant
le repli « inconnu ». libfwsi fait de même : il essaie `file_entry` avant
`web_site`.

#### Ce qui reste

Les champs propres aux formats MTP (nom du périphérique, identifiants d'objet) ne
sont pas décodés : seule l'enveloppe l'est, et le type est nommé. Idem pour les
cinq types de `TypedShellItem`. Leurs octets sont joints, donc rien n'est perdu.

# B-032 — Couverture de fichiers : ce que KapeTriage copie et WAC non

| Statut | Priorité | Effort |
|---|---|---|
| fait (3b0a5c0 … 563cc8b) | P2 | moyen |

## Pourquoi
B-015 a confronté la collecte de WAC (configuration du kit, sans binaires) à celle de KAPE, cible KapeTriage, sur la VM (`vmtest/kape-compare.sh --no-binary`). 1 130 fichiers communs, SHA-1 identiques sauf ceux écrits entre les deux collectes. Chaque écart de couverture doit être ajouté ou écarté avec sa raison.

## Source
La comparaison de `vmtest/kape-compare.sh --no-binary` (WAC et KAPE, cible KapeTriage, l'un après l'autre sur la VM).

## Sortie attendue
KAPE seul, à ajouter :
1. **Raccourcis hors de Recent** : menu Démarrer (utilisateur et commun), Bureau (utilisateur et Public), Quick Launch et barre des tâches épinglée — 17 fichiers. Même décodeur que recentdocs.json.
2. **Ruche du profil Default** (`C:\Users\Default\NTUSER.DAT` et journaux) : modèle de tout nouveau profil ; une persistance posée là se propage.
3. **Métadonnées NTFS** : `$Secure:$SDS` (descripteurs de sécurité : propriétaires et ACL de chaque fichier de la $MFT), `$UsnJrnl:$Max`, `$Boot`, `$TxfLog`.
4. **Traces WPP de Defender** (`Support\*.bin`) : copie brute seulement, faute de format documenté.
Déjà au backlog : ActivitiesCache (B-010) ; navigateurs Edge et IE, WebCache, INetCookies (B-016).
5. **Clés maîtresses DPAPI** (`AppData\Roaming\Microsoft\Protect\<SID>\*`, `Preferred`, et celles du système sous `Windows\System32\Microsoft\Protect`) : copiées telles quelles (chiffrées par le mot de passe de l'utilisateur ou la clé DPAPI_SYSTEM). Elles permettent, à l'analyse et avec le mot de passe ou la clé, de déchiffrer les secrets de l'utilisateur : mots de passe enregistrés, identifiants, cookies. Décision utilisateur du 2026-10-01 : utiles à l'enquête, donc prises. Leur JSON : SID, GUID de la clé, dates, clé préférée et sa date d'expiration — jamais la clé.
Écartés : `desktop.ini`, sans valeur d'enquête.

WAC seul, pour mémoire (couverture que KapeTriage n'a pas) : historique PowerShell (PSReadLine), dépôt WMI, file BITS, rapports WER, historique de détection et quarantaine de Defender, journaux setupapi, fichiers hosts et réseau, dossiers de démarrage, ruches des profils de service et systemprofile, second volume et clés USB (FAT/exFAT), état vivant (processus, sessions, réseau, horloge), binaires des fournisseurs de messages.

## Référence indépendante
KAPE sur la même VM, même instant (`vmtest/kape-compare.sh`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les points 1 à 5 ajoutés, avec leur JSON en --convert (sauf le 4, copie brute justifiée), ou écartés avec leur raison.
- kape-compare.sh ne montre plus de fichier « KAPE seul » non classé.

## Tâches
- [x] 1 Raccourcis hors de Recent — artefact `shortcuts` (shortcuts.json)
- [x] 2 Ruche Default — profil Default lu comme un profil, SID `S-0-0-0`, `Profile: "Default"`
- [x] 3 $Secure:$SDS (security_descriptors.json, SecurityId dans mft.json), $UsnJrnl:$Max et $Boot (ntfs_volumes.json), $TxfLog (brut)
- [x] 4 Traces WPP de Defender — copie brute (filtre .bin du dossier Support)
- [x] 5 Clés maîtresses DPAPI (utilisateurs et système) — copiées chiffrées, dpapi_master_keys.json sans la clé
- [x] 6 User Shell Folders (venu de B-031) : user_shell_folders.json, et le Bureau redirigé suivi par shortcuts

## Journal
- 2026-10-01 : ouverte depuis B-015.
- 2026-10-01 : décision utilisateur — les clés maîtresses DPAPI sont prises (elles servent l'enquête), au lieu d'être écartées.
- 2026-10-01 : point 1 fait — nouvel artefact `shortcuts` (clé `shortcuts`, `shortcuts.json`) : menu Démarrer commun et de chaque profil, Bureau de chaque profil et public, Quick Launch ; emplacement `TaskBar` pour `User Pinned\TaskBar`. Décodage par celui de recentdocs. Le dossier Startup est exclu de l'extraction et de la conversion (paramètre `skipped` de `ExtractDirectoryTreeRaw`) : il relève de startup_folders, et le prendre deux fois doublait les pièces du manifeste. Référence indépendante : deux témoins (Bureau public, épinglé de « wac ») et la liste des .lnk/.url que Windows donne dans ces dossiers pour chaque profil de ProfileList — 78 raccourcis, ensembles identiques.
- 2026-10-01 : point 1 commité (3b0a5c0).
- 2026-10-01 : décision utilisateur — le profil Default est lu comme un profil complet (ruches, Bureau, menu Démarrer, Recent…). Sans SID réel, il porte le SID `S-0-0-0` (zéros seuls : forme d'un SID pour que les outils lient les entrées, révision 0 donc aucun compte ; pas `S-1-0-0`, vrai SID nul de Windows) et `Profile: "Default"` à la place de `SIDName`. Préalable : `addUser` devient la seule fonction qui émet SID et SIDName (refactor c8a9200, 62 JSON identiques avant/après sur la même collecte). Référence indépendante : une valeur Run posée dans le NTUSER.DAT de Default (reg load), retrouvée dans run.json ; les raccourcis du profil Default s'ajoutent à la liste de Windows (92, ensembles identiques).
- 2026-10-01 : point 2 commité (36f0e14).
- 2026-10-01 : point 3, `$Secure:$SDS` — choix (proposé, accepté par l'utilisateur) : `security_descriptors.json`, chaque descripteur une fois (Volume + SecurityId), et `SecurityId` seul dans mft.json, plutôt que le propriétaire recopié sur 360 000 entrées. Décodeur de descripteur existant réutilisé (securityDescriptorToJson). Contrôle du format lui-même : le condensat NTFS de chaque entrée est recalculé (2 818 sur 2 818 identiques en VM). Référence indépendante : propriétaire de 41 fichiers selon Get-Acl, retrouvé par SecurityId ; témoin à propriétaire « wac » et ACE Everyone posés par icacls ; 0 SecurityId orphelin sur C: et G:. Test unitaire vu échouer : le saut des blocs miroirs retiré n'était d'abord pas détecté (le contrôle de position les écarte déjà) — le test place désormais une entrée cohérente en tête d'un miroir. Nouveau lecteur unique `readLittleEndian<T>` (tools.h), à généraliser par B-030.
- 2026-10-01 : `$Secure:$SDS` commité (5c714fa).
- 2026-10-01 : `$Boot` et `$UsnJrnl:$Max` → `ntfs_volumes.json` (clé `ntfs_volumes`) : numéro de série (32 bits comme les raccourcis le relèvent, et 64 bits), géométrie, en-tête du journal dont `UsnJournalId` = date de création (un journal recréé par `fsutil usn deletejournal` se voit). `$TxfLog` copié brut sous `log_file`. Référence indépendante : DeviceIoControl (FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_QUERY_USN_JOURNAL) dans la VM — fsutil y est localisé — valeurs identiques sur C: et G:. Test vu échouer (série prise dans les 32 bits hauts). Harnais : `Write-VolumeCache` après le témoin du volume de données — en cycle --only, la suppression témoin était encore dans le cache et absente de la lecture brute du journal.
- Relevé en passant : `recent_docs.cpp` écrit le numéro de série d'un volume sans zéros de tête (`to_hex(serial)`), un série `0A1B2C3D` sort `A1B2C3D` — correctif à part.
- 2026-10-01 : `ntfs_volumes` commité (bbcfeef), correctif du harnais (5b7dc5f), série des raccourcis sur 8 chiffres (277ff6b).
- 2026-10-01 : point 4 — traces WPP de Defender (`Support\MpWpp*.bin`, ≈ 18 Mo en VM) copiées brutes sous la clé `defender`, sans conversion (traces ETW binaires, symboles privés). Contrôle : les 3 fichiers que Windows liste sont au manifeste.
- 2026-10-01 : point 4 commité (273c0b0).
- 2026-10-01 : point 5 — clés maîtresses DPAPI copiées telles quelles (chiffrées), avec Preferred et CREDHIST, du système (`System32\Microsoft\Protect`, `S-1-5-18` et `S-1-5-18\User`) et de chaque profil ; `dpapi_master_keys.json` : propriétaire, GUID de l'en-tête (vérifié égal au nom du fichier), version, politique, tailles des blocs (domaine ou non), dates, clé préférée et expiration — aucun matériau de clé. Référence : les 5 fichiers que Windows liste et ce que lit Windows dans les 3 Preferred, identiques. Test vu échouer (contrôle des tailles de blocs retiré).
- 2026-10-01 : point 5 commité (39fe780).
- 2026-10-01 : point 6 — `user_shell_folders.json` (clé `user_shell_folders`) : chaque valeur de User Shell Folders de chaque profil, brute et résolue (`%USERPROFILE%` = chemin du profil ; un partage ou une autre variable d'utilisateur ne sont pas suivis), date de la clé. Les raccourcis suivent un Bureau redirigé sur un disque local (`shortcutLocations()`, partagé par collecte et conversion). Référence : Bureau de « wac » redirigé vers `OneDrive\Desktop` dans la VM, ses 20 valeurs lues non développées par Windows identiques, le raccourci posé sur le Bureau redirigé retrouvé (93 raccourcis). Harnais : une valeur du registre posée juste avant la collecte doit être écrite (`RegistryKey.Flush`, RegFlushKey), sans quoi la copie brute de la ruche ne l'a pas encore.
- 2026-10-01 : cycle complet — un seul ❌, hors WAC : firewall.json de la seconde collecte (--collect, ~10 min après la référence) compte 505 règles contre 504 relevées au début ; Edge WebView s'est mis à jour entre-temps et a créé « Microsoft Edge (mDNS-In) ». La première collecte en compte bien 504. Le contrôle compare à un compte pris au début du cycle : fragilité du harnais à corriger (compter avant chaque collecte).
- 2026-10-01 : point 6 commité (bf05868). `$TxfLog\$Tops:$T`, flux nommé que la copie récursive laissait, copié brut (563cc8b).
- 2026-10-01 : **close**. kape-compare.sh --no-binary (1 217 fichiers KAPE, 2 622 WAC, 1 173 communs) : KAPE seul = navigateurs (35, B-016), ActivitiesCache (3, B-010), desktop.ini (5, écartés) ; ez-compare.py les nomme ainsi, plus aucune famille « KAPE seul » non classée. Les 5 journaux SRU qui diffèrent sont ceux qu'ESE a fait tourner entre les deux collectes, tout le dossier étant pris des deux côtés. Cycle complet vert (0 ❌, 389 ✅), innocuité et déterminisme compris. Dossier de comparaison FR/EN mis à jour (couverture, tableau de collecte). Commits : 3b0a5c0 (raccourcis), c8a9200 (refactor addUser), 36f0e14 (profil Default), 5c714fa (descripteurs de sécurité), 5b7dc5f (harnais), bbcfeef (volumes NTFS), 277ff6b (série des raccourcis), 273c0b0 (traces WPP), 39fe780 (clés DPAPI), bf05868 (User Shell Folders), 563cc8b ($Tops:$T).

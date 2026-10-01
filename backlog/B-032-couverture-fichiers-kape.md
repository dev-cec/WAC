# B-032 — Couverture de fichiers : ce que KapeTriage copie et WAC non

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | moyen |

## Pourquoi
B-015 a confronté la collecte de WAC (configuration du kit, sans binaires) à celle de KAPE, cible KapeTriage, sur la VM (`vmtest/kape-compare.sh --no-binary`). 1 130 fichiers communs, SHA-1 identiques sauf ceux écrits entre les deux collectes. Chaque écart de couverture doit être ajouté ou écarté avec sa raison.

## Source
`vmtest/results/kape/*/compare.txt`.

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
- [ ] 4 Traces WPP de Defender
- [ ] 5 Clés maîtresses DPAPI (utilisateurs et système)
- [ ] 6 User Shell Folders (venu de B-031) : suivre les dossiers redirigés (Bureau, Documents, OneDrive) pour y chercher les fichiers de l'utilisateur

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

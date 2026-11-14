# B-078 — Contexte de liaison (`Context`) : étude complète sur Windows 11, avec WAE

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | gros |

## Pourquoi
Demande de l'utilisateur (2026-11-13 et 14). WAE doit pouvoir ouvrir le
**dossier de n'importe quel objet** — un exécutable, un script, un document
Office, n'importe quel fichier, ou ce qu'atteste un événement : une
installation de logiciel, la création d'un compte (alors tout ce qui se
rapporte à ce compte)… — et y réunir tout ce qui s'y rapporte : arrivée,
présence, exécutions (quand, par qui, comment), persistance, réseau,
détections.

Les JSON actuels ne le permettent pas sans deviner (mesures sur la collecte
Server 2025 du 2026-11-13, dans WAE) :
- le SUJET d'un enregistrement ne se distingue pas de l'endroit où WAC l'a
  lu (chaque ligne d'un journal texte porte `File` = le journal) ;
- les rôles des événements sont des `EvtEventData` `{Name, Value}` :
  `NewProcessName` (quoi), `ParentProcessName` (comment), `SubjectUserSid`
  (qui), `TargetLogonId` (quelle session) ;
- des formes que seule la machine sait résoudre : BAM
  `\Device\HarddiskVolume3\…`, UserAssist `System32\cmd.exe`, MUICache
  `C:\…\x.exe.FriendlyAppName`, `%USERPROFILE%`, Prefetch `\VOLUME{…}\…`,
  `processes.json` sans chemin ;
- `AmcacheSha1` est le SHA-1 du fichier quand `Size` ≤ 31 457 280, sans que
  le JSON le dise ;
- des liens existent déjà sans être nommés : `TargetLogonId` (4624) ↔
  `SubjectLogonId` (4688), `VolumeSerial` des raccourcis ↔ `ntfs_volumes`.

## Décision (utilisateur, 2026-11-14)
- **WAC écrit dans chaque enregistrement un bloc `Context`** normalisé — ce
  que l'enregistrement dit, par rôle — ; **WAE relie** (le dossier d'un
  objet). C'est le partage décidé le 2026-10-02 : WAC convertit chaque
  artefact (un `Context` est la conversion d'un enregistrement), WAE relie ;
  et WAC seul connaît la machine (volumes vivants, profils, dossiers connus,
  processus, couverture d'Amcache).
- WAE **ne garde pas** ses règles actuelles (forme des valeurs) : elles
  seront retirées quand il lira `Context`, sans repli pour les collectes
  sans `Context`.
- L'étude se refait **complète, sur la VM Windows 11** (un poste client :
  Prefetch, BAM, UserAssist, jump lists… vivants), artefact par artefact.

## Schéma de départ (à confirmer par l'étude)
Champs sans valeur non émis (règle commune n° 1).
```
"Context": {
  "Kind": "Execution|Arrival|Presence|Creation|Modification|Deletion|Persistence|Installation|Account|Logon|Network|Detection|Configuration|Access",
  "Subject": { "Path": "C:\\Windows\\System32\\cmd.exe", "Name": "cmd.exe", "Ntfs": "C:|1234|5",
               "Sha1": "…", "Sha256": "…", "Md5": "…", "Sid": "…", "Software": "…", "Device": "…" },
  "Actor":   { "Sid": "S-1-5-21-…-1000", "User": "WACTEST\\wac", "LogonId": "0x3e7",
               "Process": { "Path": "…", "Pid": 1234, "StartUtc": "…" } },
  "How":     { "ParentPath": "…", "CommandLine": "…", "Url": "…", "Host": "…", "RemoteAddress": "…",
               "VolumeSerial": "…", "DeviceSerial": "…" },
  "Evidence":{ "Path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx" }
}
```
Chemins par `normalizeFilePath` (partagée avec WAE), empreintes complètes
seulement ; `investigation.json` → `Host.Volumes` (lettre,
`\Device\HarddiskVolumeN`, GUID, numéro de série) et `Host.Profiles`
(SID ↔ dossier).

## Méthode
1. Cycle complet sur `win11-test` : la collecte de référence cliente.
2. Pour chaque JSON (les 120 de la table d'artefacts de WAE) : ce qu'un
   enregistrement atteste (`Kind`), son sujet, son acteur, son « comment »,
   ce que WAC doit calculer pour le dire (et d'où il le sait), avec un
   exemple réel de la collecte.
3. Pour chaque sorte d'objet du dossier (fichier, compte, logiciel,
   appareil, adresse, session) : la liste des artefacts qui en parlent et
   par quel champ de `Context`.
4. Le schéma arrêté, puis une fiche par famille d'artefacts (exécution,
   arrivée, système de fichiers, persistance, comptes et sessions, réseau,
   défense, journaux texte, serveurs), et le socle (B-079).

## Constats de la collecte Windows 11 (2026-11-14)
- **Déjà bien relié par WAC** : le Prefetch 31 est décodé, `FullPath`
  résolu (`\VOLUME{…}` → `C:\WINDOWS\…`), et chaque fichier chargé
  (`FileNames[]`) porte son chemin, ses empreintes et sa référence MFT ;
  les téléchargements d'IE (`web_client` `Download.TargetPath`), BITS
  (`Files[].Source` → `Destination`), Zone.Identifier (`HostUrl`), les
  raccourcis (`Target`, `VolumeSerial`, empreintes de la cible).
- **Manque une forme normalisée** : BAM et `shadow_copy_registry`
  (`\Device\HarddiskVolume3\…`), UserAssist (`System32\cmd.exe`, dossier
  connu), MUICache (`C:\…\x.exe.FriendlyAppName`), `office_trust_records`
  et `user_shell_folders` (`%USERPROFILE%/…`), `processes.json` (nom sans
  chemin), SRUM (`Identity` `!!svchost.exe!2045/05/31…`), `firewall`
  (`%SystemRoot%\…`), `persistence`/`run`/`services`/tâches (commandes avec
  arguments).
- **Rôles cachés** : `events`, `rdp_server`, `shadow_copy_events` portent
  leurs rôles dans `EvtEventData[{Name, Value}]` ; il faut une table par
  événement (4688, 4624, 4720, 4732, 7045, 4698, 1116, Sysmon 1, 3, 11…).
- **Vides sur une VM neuve, pas un défaut** : `shimcache.json` (Windows
  n'écrit `AppCompatCache` qu'à l'arrêt : 52 octets, en-tête seul),
  `amcache_inventory.json` et `amcache_applications.json` (tâche
  quotidienne d'évaluation de compatibilité pas encore passée). **L'étude
  demande une VM qui a vécu** (redémarrages, une journée) : à refaire avant
  d'arrêter le schéma.

## Tableau par JSON (première passe, sur la collecte Windows 11)
`Kind` : ce que l'enregistrement atteste. Sujet, acteur, comment : le champ
actuel, et ce que WAC doit calculer pour l'écrire dans `Context`.

| JSON | Kind | Sujet | Acteur | Comment / origine | À calculer par WAC |
|---|---|---|---|---|---|
| prefetchs | Execution (n fois, 8 dernières) | `FullPath`, empreintes | — | fichiers chargés `FileNames[]` (chemin, empreintes, MFT) | `Subject.Ntfs` de l'exe ; `Evidence` = le `.pf` (`Path`) |
| amcache_application_files | Presence (pas une exécution) | `LongPath`, `AmcacheSha1`, `Size` | — | éditeur, version | `Subject.Sha1` quand `Size` ≤ 31 457 280 |
| amcache_applications, amcache_inventory | Installation / Presence | programme, raccourci (`ShortcutTargetPath`) | — | `UninstallString`, `RootDirPath` | chemin résolu du programme |
| shimcache | Presence | `Path` | — | — | — (vide sur VM neuve) |
| bams | Execution (dernière) | `Name` | `SID` | — | `\Device\HarddiskVolumeN\…` → `C:\…` (carte des volumes) ; identifiant d'application pour les paquets |
| userassists | Execution (compte, dernière) | `Name` | `SID` | — | dossier connu → chemin complet ; `Kind` absent pour les `UEME_CTL…` |
| muicache | Presence (lancé une fois) | `Name` | `SID` | — | séparer chemin et propriété (`.FriendlyAppName`) |
| program_usage | Execution | `Name`, `Shortcut.Target` | `SID` | — | chemin de l'exe quand `Name` est un identifiant d'application |
| srum | Execution / Network (volumes) | `App` (`Identity`) | `UserSID` | octets réseau, temps CPU | décoder `Identity` (`!!exe!date!…`) en chemin |
| processes | Execution (vivante) | `Name`, empreintes | `SID` | `ParentProcessId` | **chemin de l'image** (WAC l'a au moment de la collecte), heure de création |
| events 4688 / Sysmon 1 | Execution | `NewProcessName` / `Image` | `SubjectUserSid`, `TargetUserSid`, `SubjectLogonId` | `ParentProcessName`, `CommandLine` | table des rôles par identifiant d'événement |
| powershell_history | Execution (commandes) | — | `SID` | `Commands[].Command` | chemins cités dans les commandes (au moins `Evidence`) |
| error_reports | Execution (plantage) | `AppPath` | — | `OriginalFilename` | — |
| zone_identifiers | Arrival | `Path` | — | `HostUrl`, `ReferrerUrl`, `ZoneId` | `Subject.Ntfs` (le fichier porteur du flux) |
| bits_jobs | Arrival | `Files[].Destination` | `OwnerSID` | `Files[].Source`, `NotifyProgram` | un sujet par fichier |
| web_client | Arrival (téléchargement) / Access (visite) | `Download.TargetPath` | `SID` / `User` | `Download.Url`, `Url` | hôte ; `SID` du profil quand seul `User` est donné |
| emails | Arrival (pièce jointe) | `Attachments[]` (nom, empreinte) | `SID` | `SenderAddress`, `Subject` | adresse réelle de l'expéditeur (souvent un nom) |
| mft | Presence | `Path`, `Entry`/`Sequence` | — (`SecurityId` → propriétaire) | — | propriétaire (SID) par `$Secure` |
| usn_journal | Creation / Modification / Deletion / Rename | `Path`, `FileEntry`/`FileSequence` | — | `Reasons` | `Kind` tiré de `Reasons` ; ancien nom ↔ nouveau |
| deleted_files | Deletion | `Path`, `Entry`/`Sequence`, empreintes récupérées | — | — | — |
| recycle_bin | Deletion | `OriginalPath` | `SID` | — | — |
| fat_volumes | Presence / Deletion | `Path` | — | — | numéro de série du volume FAT |
| ntfs_volumes, shadow_copies, boot_records | Configuration | volume | — | — | carte des volumes (B-079) |
| recentdocs, explorer_recent_docs, jumplist*, shortcuts | Access (ouverture) | `Target` | `SID` | application (`Application`), `VolumeSerial`, `Tracker.MachineId` | volume cible → lettre ou support amovible |
| shellbags, typed_paths, word_wheel_query | Access (dossier, recherche) | dossier / texte | `SID` | — | chemin reconstitué des `ShellItems` |
| thumbcache | Presence (image vue) | — | `SID` | `ThumbnailCacheId` ↔ `search_index` | lien par l'identifiant de vignette |
| activities_cache | Access / Execution | `AppId` (application, fichier) | `SID` | `Payload` | chemin du fichier ouvert |
| search_index | Presence | `ItemPathDisplay` | — | `ThumbnailCacheId` | — |
| office_trust_records | Access (macros autorisées) | `Document` | `SID` | `MacrosEnabled` | `%USERPROFILE%` → profil du SID |
| run, persistence, services, ScheduledTasks, startup_folders, wmi_persistence, powershell_profiles, shadow_copy_registry | Persistence | binaire lancé (`Value`, `Binary`, `ServiceDll`, `Actions[].Command`, `Path`) | `SID` / `RunAsSID` | arguments, déclencheur | **chemin de l'exe séparé des arguments**, variables résolues |
| installed_programs | Installation | logiciel (`DisplayName`, `InstallLocation`) | `SID` (installation par utilisateur) | `InstallSource`, `UninstallString` | identifiant du logiciel ; lien vers ses fichiers |
| setupapi, devices, Usbstor, mounted_device, mount_points | Installation (appareil), Access (volume) | appareil (`SerialNumber`, `InstanceId`) | `SID` (mount_points) | lettre, GUID de volume | **appareil ↔ volume ↔ lettre ↔ numéro de série** |
| users, local_groups | Account | `SID` | — | groupes (`Members[]`) | — |
| Sessions, events 4624/4634/4647, rdp_server, rdp_client | Logon | compte (`TargetUserSid`) | — | `LogonType`, `IpAddress`, `TargetLogonId` | `LogonId` en clé de session |
| events 4720/4722/4724/4732/4738 | Account (création, modification) | `TargetSid` | `SubjectUserSid` | groupe (4732) | table des rôles |
| security, dpapi_master_keys, cloud_identity | Account / Configuration | compte (`SID`) | — | — | — |
| network, network_configuration, known_networks, network_shares, hosts, firewall, internet_settings | Network / Configuration | adresse, partage, règle (`Application`) | — (processus pour `network`) | `ProcessId`, `Process` | **chemin du processus** (`network`), `%SystemRoot%` résolu (`firewall`) |
| defender_detections, defender_quarantine, defender_log, antivirus, sysmon, defender_configuration | Detection / Configuration | fichier (`Resources[].Path`) | `DomainUser` | `ProcessName`, `ThreatName`, empreinte | SID de `DomainUser` |
| events (autres), shadow_copy_events | selon l'identifiant | table des rôles | table | table | **table des rôles par événement** |
| server_logs, system_traces, remote_administration, messaging, ssh, vpn, file_transfer, cloud_storage, virtualisation, application_registry, intune_logs | selon la ligne (souvent Configuration) | — sauf exception | `SID` quand connu | hôte distant (`HostName`) | **`Evidence` = `File`**, jamais le sujet |
| active_directory_*, dns_server_*, dhcp_server_*, web_server_*, user_access_log, group_policies, hyperv_machines, server_applications | Account / Configuration / Access | objet AD (`ObjectGUID`, SID), zone, bail (`IpAddress`, MAC), site, client (`Address`) | — | — | SID des objets AD ; bail → adresse ↔ machine |
| investigation, conversion, OperatingSystem, event_log_configuration, root_certificates | Configuration (la collecte, le système) | — | — | — | `Host.Volumes`, `Host.Profiles` (B-079) |

## Tableau par sorte d'objet (le dossier dans WAE)
| Objet | Clés d'identité (Context) | Ce que le dossier réunit |
|---|---|---|
| Fichier (tout type) | `Subject.Path`, `Subject.Ntfs`, empreintes | arrivée (Zone.Identifier, BITS, web, pièce jointe, copie depuis un support), présence (MFT, USN, Amcache, ShimCache), ouvertures (raccourcis, jump lists, RecentDocs, Office), exécutions (Prefetch, BAM, UserAssist, 4688/Sysmon, SRUM, processus), persistance, réseau du processus, détections, suppression |
| Compte | `Sid` | création (4720), groupes (4732, `local_groups`), sessions (4624…, `Sessions`, RDP), exécutions et accès dont il est l'acteur, fichiers de son profil |
| Session | `LogonId` | ouverture et fermeture, origine (adresse, type), tout ce qu'elle a exécuté |
| Logiciel | identifiant d'installation, chemin d'installation | installation (qui, quand, source), fichiers, services et tâches, exécutions |
| Appareil, volume | numéro de série, GUID de volume, lettre | branchements, lettre, fichiers ouverts ou copiés depuis lui |
| Adresse, hôte | IP, nom | connexions, téléchargements, sessions distantes, règles |

## Référence indépendante
Les témoins du harnais (fichier téléchargé, compte créé, tâche, clé USB,
session RDP, exécution connue) : pour chacun, l'histoire attendue écrite à
l'avance, et les champs de `Context` qui la portent.

## Tâches
- [x] Cycle `win11-test`, collecte de référence cliente
- [x] Tableau par JSON, première passe (à reprendre sur une VM qui a vécu)
- [x] Tableau par sorte d'objet, première passe
- [ ] VM qui a vécu (redémarrages, une journée) : ShimCache, inventaire
      Amcache ; nouveau cycle, tableaux confirmés
- [ ] Table des rôles des événements (identifiant → sujet, acteur, comment)
- [ ] Schéma arrêté ; fiches par famille créées

## Journal
- 2026-11-13 : ébauche dans WAE (`backlog/etudes/`), depuis la collecte
  Server 2025 ; constats ci-dessus.
- 2026-11-14 : décisions de l'utilisateur (ci-dessus) ; l'ébauche devient
  cette fiche, WAE n'en garde pas de copie.
- 2026-11-14 : cycle `win11-test` (sans l'étape 7), première collecte de la
  VM recréée le 2026-11-13 (build 26300) : 297 ✅, 3 ❌. Expliqués :
  `check_web_client` s'arrête sur une date fausse écrite par WAC (année
  30828 tronquée en `0828`, fiche B-080) ; `bams.json` (l'entrée de
  `taskkill.exe` lancé juste avant la collecte absente) et
  `defender_quarantine.json` (entrée EICAR absente) : écritures différées
  de Windows sur une VM neuve, à revoir au prochain cycle avant de parler
  de régression.
- 2026-11-14 : première passe des deux tableaux sur la collecte Windows 11 ;
  ShimCache et inventaire Amcache vides sur VM neuve (expliqué), à revoir
  sur une VM qui a vécu.

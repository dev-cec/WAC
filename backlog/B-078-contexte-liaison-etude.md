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

## Référence indépendante
Les témoins du harnais (fichier téléchargé, compte créé, tâche, clé USB,
session RDP, exécution connue) : pour chacun, l'histoire attendue écrite à
l'avance, et les champs de `Context` qui la portent.

## Tâches
- [ ] Cycle complet `win11-test`, collecte de référence cliente
- [ ] Tableau par JSON (Kind, sujet, acteur, comment, à calculer)
- [ ] Tableau par sorte d'objet
- [ ] Schéma arrêté ; fiches par famille créées

## Journal
- 2026-11-13 : ébauche dans WAE (`backlog/etudes/`), depuis la collecte
  Server 2025 ; constats ci-dessus.
- 2026-11-14 : décisions de l'utilisateur (ci-dessus) ; l'ébauche devient
  cette fiche, WAE n'en garde pas de copie.

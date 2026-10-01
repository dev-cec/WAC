# B-031 — Couverture du registre : ce que le lot Kroll de RECmd lit et WAC non

| Statut | Priorité | Effort |
|---|---|---|
| fait (8bb296b à 39865a8) | P1 | moyen |

## Pourquoi
B-015 a confronté WAC au lot `Kroll_Batch.reb` de RECmd (celui que KAPE lance). Sur les artefacts communs, les valeurs sont identiques. Mais ce lot lit des clés que WAC ignore, dont plusieurs ont une vraie valeur d'enquête. Chaque écart de couverture doit être ajouté ou écarté avec sa raison (critère de B-015).

## Source
Le CSV de RECmd dans `vmtest/results/ez/registry-*` et `lib/ez-compare.py registry`.

## Sortie attendue
Par ordre de valeur pour l'enquête. Chaque clé ajoutée reçoit son JSON en `--convert`, avec la forme des artefacts voisins :
1. **Programmes installés** — `SOFTWARE\…\Uninstall` et `WOW6432Node` (nom, éditeur, version, date, emplacement, chaîne de désinstallation) ; `Products` (MSI).
2. **Exclusions de Defender** — `SOFTWARE\Microsoft\Windows Defender\Exclusions` (chemins, extensions, processus), et les politiques qui désactivent la protection : un attaquant les pose.
3. **RecentDocs du registre** — `NTUSER\…\Explorer\RecentDocs` par extension, avec l'ordre MRU.
4. **MountPoints2** — volumes et partages montés par utilisateur (`##serveur#partage`).
5. **Réseaux connus** — `SOFTWARE\…\NetworkList\Profiles` et `Signatures` : nom, type, première et dernière connexion, MAC de la passerelle.
6. **État du système utile à la lecture des autres artefacts** — `NtfsDisableLastAccessUpdate` (dates d'accès NTFS fiables ou non), `Control\Windows\ShutdownTime`, `PrefetchParameters` (Prefetch actif ou non), `Control\Select`.
7. **Démarrage** — `StartupApproved` (entrées Run désactivées par l'utilisateur), `RunNotification`.
8. **Activité de l'utilisateur** — `TypedURLs`, `FeatureUsage`, `Taskband`, `JumplistData`, `AppCompatFlags` (Layers, Compatibility Assistant Store), `RADAR`.
9. **Périphériques** — `Enum\SCSI`, `Windows Portable Devices`, `VolumeInfoCache`, `DeviceClasses`.
10. **Partages et accès distant** — `LanmanServer\Shares`, configuration RDP (`Terminal Server`), `LogonUI` (dernier utilisateur).
Écartés d'abord : l'état des journaux d'événements (`WINEVT\Channels`, `Autologger`), `FileExts` et `User Shell Folders`. Revus le 2026-10-01 sous la règle « prélever toutes les traces utiles » : voir le journal.

## Référence indépendante
RECmd sur les mêmes pièces (ez-compare.sh registry), et pour chaque clé un témoin de la VM posé par place-file-artefacts.ps1.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque clé listée est ajoutée, ou écartée avec sa raison dans le journal.
- Comparaison à RECmd identique sur les clés ajoutées.

## Tâches
- [x] 1 à 5 (P1) : installed_programs (8bb296b), defender_configuration (2016305), explorer_recent_docs (fee24cf), mount_points (7272671), known_networks (255c026) ; produits MSI (b0311b8)
- [x] 6 état du système : réglages dans OperatingSystem.json, ShutdownTime, NtfsLastAccessUpdated (1273fcc)
- [x] 7 démarrage : StartupApproved, Run 32 bits, RunNotification dans run.json (0f02bd5)
- [x] 8 activité : FeatureUsage, JumplistData, compatibilité, RADAR, Taskband (a16de63) ; FileExts (39865a8) ; TypedURLs versé à B-016
- [x] 9 périphériques : USB, SCSI et leurs dates, appareils portables, VolumeInfoCache, DeviceClasses (63c6f5b)
- [x] 10 partages (a7423e3), Terminal Server et LogonUI dans les réglages (1273fcc)
- [x] En chemin : commandes d'ouverture des types exécutables dans persistence.json (8160392), configuration réseau (2a1ce7d)
- [x] Revus : configuration des journaux et sessions ETW de démarrage (19707d9, d3ee1e4)

## Journal
- 2026-10-01 : ouverte depuis B-015.
- 2026-10-01 : points 1 à 5 faits, chacun avec sa clé de wac.yml et son témoin. En chemin : ruches utilisateur copiées seulement avec la clé registry (corrigé, needsUserHives) ; entrées CPC\Volume de MountPoints2 volatiles (mesuré) ; dates de NetworkList en heure locale (mesuré contre l'événement 10000).
- 2026-10-01 : points 6 à 10 faits, chacun recoupé en VM avec une source indépendante (registre en ligne, Get-PnpDeviceProperty, Get-SmbShareAccess, Get-NetAdapter).
- 2026-10-01 : écarts revus sous la règle « prélever toutes les traces utiles ». L'état des journaux devient l'artefact event_log_configuration, sessions ETW de démarrage comprises : couper un canal ou arrêter EventLog-Security aveugle les journaux sans y toucher. Recoupé avec Get-WinEvent -ListLog (490 journaux) et Get-AutologgerConfig (39 sessions). Les clés Parameters et State de Services\EventLog ne sont pas des journaux : écartées (la DLL du service est dans services.json).
- 2026-10-01 : FileExts → program_usage (OpenWithList dans l'ordre MRU, UserChoice) ; OpenWithProgids écarté, rempli par les installeurs. User Shell Folders versé à B-032 : la clé ne trace aucune activité, mais un Bureau ou des Documents redirigés changent l'endroit où chercher les fichiers de l'utilisateur. TypedURLs versé à B-016. Alias de la SAM et droits des comptes (SECURITY\Policy\Accounts) versés à B-034.
- 2026-10-01 : close.

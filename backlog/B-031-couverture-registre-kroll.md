# B-031 — Couverture du registre : ce que le lot Kroll de RECmd lit et WAC non

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
Écartés, avec leur raison : l'état des journaux d'événements (`WINEVT\Channels`, `Autologger`), qui relève de la configuration et non d'une trace ; `FileExts` et `User Shell Folders`, sauf demande.

## Référence indépendante
RECmd sur les mêmes pièces (ez-compare.sh registry), et pour chaque clé un témoin de la VM posé par place-file-artefacts.ps1.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque clé listée est ajoutée, ou écartée avec sa raison dans le journal.
- Comparaison à RECmd identique sur les clés ajoutées.

## Tâches
- [ ] 1 à 5 (P1)
- [ ] 6 à 10

## Journal
- 2026-10-01 : ouverte depuis B-015.

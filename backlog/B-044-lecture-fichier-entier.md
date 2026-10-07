# B-044 — Une seule lecture d'un fichier entier

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | faible |

## Pourquoi
Relevé le 2026-10-07 pendant B-026 : une quinzaine de modules lisent un fichier entier chacun à sa façon (istreambuf_iterator ou read sur la taille), certains sans borne de taille : defender_log, fat_volume, dpapi_master_keys, config, hive_recover, defender_history, powershell_history, pe_resource, recycle_bin, error_reports, setupapi_log, ntfs_volumes, web_client (deux), security_descriptors, xml_light. Une seule existe désormais dans tools : readWorkingFile(fichier, taille maximale), sortie de rdp_client (1a6f559).

## Source
Les modules cités.

## Sortie attendue
Chaque lecture entière passe par readWorkingFile, avec une taille maximale nommée par module ; aucune sortie changée.

## Référence indépendante
JSON identiques avant et après sur une même collecte (comme B-030).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Commit `refactor :` seul.

## Tâches
- [ ] Remplacer les lectures entières
- [ ] JSON comparés avant/après

## Journal
- 2026-10-07 : créée pendant B-026.
- 2026-10-07 (B-024) : lectures little-endian locales que l'inventaire de B-030 a manquées, faute de s'appeler rd* : lu16/lu32 d'authenticode.cpp, read16/32/64 bornées (pointeur, taille, décalage) d'evtx.cpp — à ramener à readLittleEndian<T> (une variante bornée sur pointeur et taille s'il le faut).
- 2026-10-08 : en cours — inventaire. Ajout : archiveLe16/archiveLe32 de cab.cpp, lecteurs little-endian locaux vus pendant B-029.

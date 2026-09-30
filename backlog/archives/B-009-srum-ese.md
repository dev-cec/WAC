# B-009 — SRUM et Windows.edb (lecteur ESE)

| Statut | Priorité | Effort |
|---|---|---|
| fait (50752ab) | P2 | fort |

## Pourquoi
SRUM : octets envoyés et reçus par application sur 30 à 60 jours (exfiltration) ; Windows.edb : index de recherche.

## Source
`\Windows\System32\sru\SRUDB.dat`, `ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`.

## Sortie attendue
`srum.json` (tables réseau et applications) ; `windows_search.json`.

## Référence indépendante
Lecteur ESE confronté à `esentutl` / une implémentation indépendante (libesedb) sur les mêmes fichiers.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Lecteur ESE sans dépendance, borné, confronté à une référence indépendante.

## Tâches
- [x] Lecteur ESE (ese_database) : pages de 4 à 32 Kio, arbres B, catalogue, colonnes fixes/variables/étiquetées/multivaluées, valeurs longues (identifiants 32 et 64 bits) ; compression signalée, non décodée (absente des bases de la VM)
- [x] Tables SRUM (srum.json), identités résolues
- [ ] Windows.edb → reporté à B-010 : Windows 11 tient l'index de recherche en SQLite (Windows.db), aucun Windows.edb réel pour éprouver la variante ESE
- [x] Tâches BITS (bits_jobs.json), commande de notification comprise

## Journal
- 2026-09-29 : les tâches BITS (qmgr.db) rejoignent cette fiche, faute de lecteur ESE dans B-007.
- 2026-09-30 : lecteur confronté à dissect.esedb (vmtest/lib/ese-compare.py) : 1 064 268 valeurs identiques ; a révélé les identifiants de valeurs longues sur 8 octets (qmgr.db).
- 2026-09-30 : BITS n'écrit un travail dans qmgr.db qu'à sa création et à l'ajout d'un fichier, pas à un changement de propriété : le témoin pose ses propriétés avant son fichier.
- 2026-09-30 : SruDbIdMapTable a des entrées sans IdBlob (1 et 2 sur la VM) : rien à résoudre, le contrôle les écarte.

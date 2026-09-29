# B-009 — SRUM et Windows.edb (lecteur ESE)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | fort |

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
- [ ] Lecteur ESE (pages, arbres B, colonnes longues)
- [ ] Tables SRUM
- [ ] Windows.edb
- [ ] Tâches BITS (qmgr.db, reportées de B-007) : persistance par téléchargement planifié

## Journal
- 2026-09-29 : les tâches BITS (qmgr.db) rejoignent cette fiche, faute de lecteur ESE dans B-007.

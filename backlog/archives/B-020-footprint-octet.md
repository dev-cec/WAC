# B-020 — Texte « a l'octet » dans le Footprint HIVE_REPLAY

| Statut | Priorité | Effort |
|---|---|---|
| fait (6789e0c) | P3 | faible |

## Pourquoi
Reste de français dans un texte anglais d'investigation.json.

## Source
`sources/audit.cpp`.

## Sortie attendue
« byte for byte ».

## Référence indépendante
Relecture.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- aucun

## Tâches
- [x] Corriger : « reconstructible byte for byte »

## Journal
- 2026-09-29 : corrigé dans audit.cpp ; cycle VM lancé.
- 2026-09-29 : cycle VM vert ; commité (6789e0c), fiche archivée.

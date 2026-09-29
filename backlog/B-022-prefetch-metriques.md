# B-022 — Prefetch : métriques absentes sur 124 fichiers sur 279

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
Limite connue : références $MFT des fichiers chargés absentes pour 124 Prefetch ; cause non établie.

## Source
`sources/prefetchs.cpp`.

## Sortie attendue
Références présentes quand le format les porte.

## Référence indépendante
PECmd sur les mêmes fichiers (B-015).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Cause établie et documentée, ou corrigée.

## Tâches
- [ ] Diagnostic par version de format

## Journal
- (vide)

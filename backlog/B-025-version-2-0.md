# B-025 — Version 2.0.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | faible |

## Pourquoi
Le lot d'artefacts et l'i18n sont des modifications majeures.

## Source
`bump-version.sh --major`.

## Sortie attendue
Version 2.0.0 dans WAC.rc, documents et bin.

## Référence indépendante
Cycle VM sur le binaire publié.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- juste avant article dfir.

## Tâches
- [ ] bump-version.sh --major
- [ ] Commit

## Journal
- 2026-10-07 : décision utilisateur — passage en version 2.0.0 et non 1.5.0 : l'ensemble des modifications (lot d'artefacts, i18n, collecte et conversion séparées, consigne intouchable, volumes partagés…) constitue une montée de version majeure. À faire juste avant l'article DFIR (B-018), lui-même en dernier.
- 2026-10-08 : en cours — bump-version.sh complété (document de comparaison, phrases qui citent la version).

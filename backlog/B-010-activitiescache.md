# B-010 — Chronologie Windows (ActivitiesCache.db)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | fort |

## Pourquoi
Activités par application et document, horodatées.

## Source
`AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db`.

## Sortie attendue
`activities.json`.

## Référence indépendante
Lecteur SQLite confronté à `sqlite3` sur le même fichier.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Décider : lecteur SQLite maison ou dépendance justifiée (sqlite amalgamation).

## Tâches
- [ ] Décision lecteur
- [ ] Tables Activity, ActivityOperation

## Journal
- (vide)

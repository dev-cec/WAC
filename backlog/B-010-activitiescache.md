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
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.
- 2026-09-30 : l'index de recherche Windows rejoint cette fiche (reporté de B-009) : Windows.db et Windows-gather.db en SQLite sur Windows 11 ; Windows.edb (ESE, colonnes compressées XPRESS) sur Windows 10, à éprouver sur un vrai Windows 10.

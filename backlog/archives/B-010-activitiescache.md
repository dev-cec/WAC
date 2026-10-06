# B-010 — Chronologie Windows (ActivitiesCache.db)

| Statut | Priorité | Effort |
|---|---|---|
| fait (379fd67, 0aadefa) | P3 | fort |

## Pourquoi
Activités par application et document, horodatées.

## Source
`AppData\Local\ConnectedDevicesPlatform\*\ActivitiesCache.db`.

## Sortie attendue
`activities.json`.

## Référence indépendante
Lecteur SQLite confronté à `sqlite3` sur le même fichier : base Windows 10 de plaso (112 activités, `activities_cache_fixtures.sh`, SHA-256 épinglé) et base réelle de la VM, journal `-wal` rejoué.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Décider : lecteur SQLite maison ou dépendance justifiée (sqlite amalgamation).

## Tâches
- [x] Décision lecteur (amalgamation SQLite, déjà intégrée par B-016)
- [x] Tables Activity, ActivityOperation
- [x] Index de recherche Windows (Windows.db, Windows-gather.db) ; Windows.edb sous Windows 10 collecté, pas converti (B-039)

## Journal
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.
- 2026-09-30 : l'index de recherche Windows rejoint cette fiche (reporté de B-009) : Windows.db et Windows-gather.db en SQLite sur Windows 11 ; Windows.edb (ESE, colonnes compressées XPRESS) sur Windows 10, à éprouver sur un vrai Windows 10.
- 2026-10-06 : Chronologie faite — `activities_cache` (clé de `wac.yml`, `activities_cache.json`). Dossier `ConnectedDevicesPlatform` de chaque profil collecté en brut (base, `-wal`, réglages de la plateforme). Toutes les colonnes de `Activity` et `ActivityOperation`, converties par leur type déclaré (DATETIME = temps Unix UTC, GUID dans l'ordre .NET, charges utiles JSON analysées) : le schéma change selon la version de Windows. Mesuré dans la VM : Windows 11 n'enregistre plus que les réglages synchronisés (type 11, 3 lignes) ; les activités d'applications, le temps au premier plan et le presse-papiers ne sont que sous Windows 10, d'où la base de plaso. Test `activities_cache_test` : 118 contrôles, 112 enregistrements identiques à Python ; une date décalée d'une heure fait échouer 113 contrôles. Cycle VM `--only=activities_cache` vert, 3 lignes sur 3 identiques à Python.
- 2026-10-06 : index de recherche fait — `search_index` (`search_index.json`). Magasin de propriétés de Windows.db (une fiche par WorkId, chaque propriété selon son type VARIANT) et table du collecteur de Windows-gather.db (URL reconstituée, dernière modification). SQLite déclare à la demande les collations propres à Windows Search. Référence : la requête de Windows sur son propre index (OLE DB, Search.CollatorDSO) — document témoin retrouvé avec sa taille et son résumé, 517 éléments de même date et même taille ; un élément réindexé après la requête est compté à part. Test unitaire des valeurs (FILETIME, VT_UI8, CLSID, UTF-16, vecteurs) vu échouer sur une date décalée. Windows.edb (Windows 10, ESE) collecté avec ses journaux, non converti : à reprendre avec un vrai Windows 10 (B-039).
- 2026-10-06 : **Close**. Cycle complet vert (435 ✅, 0 ❌), innocuité comprise. Commits : 379fd67 (Chronologie), 0aadefa (index de recherche), eff954d et 4ee5159 (harnais).

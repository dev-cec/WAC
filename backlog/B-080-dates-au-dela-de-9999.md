# B-080 — Dates au-delà de l'an 9999 écrites tronquées (`0828` pour 30828)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | petit |

## Pourquoi
Trouvé par le cycle `win11-test` du 2026-11-14 (B-078) : `web_client.json`
écrit `"ExpiryUtc": "0828-09-14T02:48:05.4775807Z"` pour deux entrées du
cache web. La valeur lue est le FILETIME maximal (0x7FFFFFFFFFFFFFFF :
« n'expire jamais »), soit l'an **30828** ; `formatIso8601` (tools.cpp)
écrit l'année par `fourDigits`, qui garde les quatre derniers chiffres :
une date fausse de 29 000 ans, valide en apparence. `check-json.py`
(`check_web_client`) s'arrête dessus (`OverflowError: date value out of
range`). L'exactitude des dates est la priorité absolue (décision de
l'utilisateur, B-077).

## À faire
- Une date dont l'année dépasse 9999 ne s'écrit pas en ISO 8601 à quatre
  chiffres : ne pas l'émettre comme instant ; dire la valeur lue (le
  FILETIME brut, ou « jamais » pour le maximum) — règle commune n° 1 : pas
  de valeur inventée.
- Relever les autres sentinelles de « jamais » ou de « pas de date » qui
  passent aujourd'hui pour des dates : `0x7FFFFFFFFFFFFFFF`, horodatage PE
  à 0 (`LinkDateUtc` 1970-01-01 d'Amcache), 9999-12-29T23:59:59 de la
  réplication d'Active Directory (`ChangedUtc`), et décider, artefact par
  artefact, de leur écriture.
- `check-json.py` : ne pas s'arrêter sur une date hors de la plage de
  Python, la signaler.

## Référence indépendante
Test unitaire de `formatIso8601`/`timeToIso8601Utc` sur 0x7FFFFFFFFFFFFFFF,
la dernière seconde de 9999 et la première de 10000, vu échouer avant le
correctif ; cycle `win11-test` : `web_client.json` sans date tronquée.

## Journal
- 2026-11-14 : fiche créée (cycle B-078).

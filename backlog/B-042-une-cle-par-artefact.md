# B-042 — Une clé wac.yml par artefact ; ruches et journaux comme dépendances

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
Règle de l'utilisateur (2026-10-07) : aucun artefact n'est prélevé systématiquement, chacun a sa clé sous `artefacts:` de `wac.yml`. Les ruches, les catalogues — et les journaux d'événements quand un autre artefact les lit — ne sont pas des artefacts mais des **dépendances**, prélevées dès qu'un artefact demandé en a besoin (comme la $MFT pour `usn_journal` ou `zone_identifiers`). Une clé absente vaut `true` (décision du même jour).

Aujourd'hui, la clé `registry` regroupe seize sorties sans clé propre : `Usbstor`, `mounted_device`, `bams`, `muicache`, `amcache_applications`, `amcache_application_files`, `amcache_inventory`, `userassists`, `run`, `shimcache`, `shellbags`, `mrus`, `mruApps`, `users`, `local_groups`, `OperatingSystem`. Et `events` vit à part (`conf._events`, option `--events`), alors que `rdp_server` en dépend aussi : constaté par le cycle de B-022, où `rdp_server`, absent du `wac.yml` du harnais, faisait prélever les journaux malgré `events: false`.

## Source
`sources/config.cpp` (table des clés), `tools.h` (`CollectedArtefacts`, `needsUserHives`), `main.cpp` (conversion), `raw_collect.cpp` (cibles), `wac.yml`, `vmtest/run-wac-test.sh` (wac.yml configuré), `check-json.py` (`--configuration`).

## Sortie attendue
- Une clé par artefact (noms de fichier de sortie comme base : `usb_devices`, `mounted_devices`, `bam`, `muicache`, `amcache`, `userassist`, `run_keys`, `shimcache`, `shellbags`, `mru`, `users`, `local_groups`, `operating_system`…), `registry` retirée des artefacts.
- Les ruches prélevées si au moins un artefact qui les lit est demandé ; les journaux si `events` ou `rdp_server` l'est ; chaque dépendance dit, dans l'enquête, quels artefacts l'ont demandée.
- `events` traité comme toute clé (fin de `conf._events`).

## Référence indépendante
Le contrôle `--configuration` de check-json.py étendu : pour chaque clé à `false`, aucune sortie de cet artefact ; pour chaque dépendance prélevée, au moins un artefact demandé qui la lit ; une collecte où seul un artefact de ruche est demandé ne prend que les ruches qu'il lit.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Plus aucune sortie sans clé propre.
- Manuel FR + EN : liste des clés et table artefact → dépendances.

## Tâches
- [ ] Inventaire complet sortie → clé → dépendances
- [ ] Clés, conversion et cibles
- [ ] wac.yml livré et wac.yml du harnais
- [ ] Contrôle `--configuration` étendu, cycle complet
- [ ] Documentation FR + EN

## Journal
- 2026-10-07 : créée sur la règle de l'utilisateur ; clé absente = true (choix explicite). Dans l'immédiat, `rdp_server: false` ajouté au wac.yml configuré du harnais (161391c), sans exception dans le contrôle.

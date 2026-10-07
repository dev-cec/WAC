# B-042 — Une clé wac.yml par artefact ; ruches et journaux comme dépendances

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | moyen |

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
- [x] Inventaire complet sortie → clé → dépendances
- [x] Renommage convertFileArtefact → convertArtefact (b4c6386)
- [x] Clés, conversion et cibles (tools.h, config.cpp, main.cpp, raw_collect.cpp, translations) ; aide de --events et --convert corrigée
- [x] wac.yml livré — c'est aussi celui de --write-config (ressource RCDATA, une seule source) ; config_test adapté (34 contrôles verts, `registry` refusée)
- [x] Harnais : `wants registry` remplacés par les clés servies (run-wac-test.sh, place-file-artefacts.ps1) ; wac.yml configuré avec amcache et registry_backups à false
- [x] Contrôle `--configuration` : règles amcache et registry_backups, dépendances (journaux, ruches des utilisateurs) présentes si et seulement si un artefact demandé les lit
- [ ] Cycle complet — lancé, en cours
- [ ] Documentation FR + EN (liste des clés, dépendances, wac_version) — non commité à ce stade
- [ ] Documentation FR + EN

## Journal
- 2026-10-07 : créée sur la règle de l'utilisateur ; clé absente = true (choix explicite). Dans l'immédiat, `rdp_server: false` ajouté au wac.yml configuré du harnais (161391c), sans exception dans le contrôle.
- 2026-10-07 : inventaire. Clés nouvelles : `events` (ex-`conf._events`, désormais vrai par défaut comme les autres), `operating_system` (OperatingSystem.json, prélevé d'office jusqu'ici), `usbstor`, `mounted_devices`, `bam`, `muicache`, `amcache`, `userassist`, `run_keys`, `shimcache`, `shellbags`, `mru`, `mru_apps`, `users`, `local_groups`, `registry_backups` (RegBack) ; `registry` supprimée. Dépendances : ruches des utilisateurs si muicache, userassist, run_keys, shellbags, mru, mru_apps (+ les artefacts déjà listés dans needsUserHives) ; journaux si events ou rdp_server (needsEventLogs) ; Amcache.hve pour amcache seul ; SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT toujours (fuseau, profils, noms des comptes). Les treize blocs copiés de la phase registre remplacés par convertArtefact (version à plusieurs sorties pour Amcache) : chaque artefact en échec écrit désormais son fichier « non prélevé ».
- 2026-10-07 : en cours — reste : wac.yml livré, wac.yml et `wants registry` du harnais, contrôle `--configuration`, tests, cycle, documentation.
- 2026-10-07 : demande utilisateur — le wac.yml porte la version de WAC (écrite par --write-config) et un fichier d'une version précédente est refusé : il pourrait manquer de nouvelles options ou réutiliser des options obsolètes. Choix : version identique exigée (majeur.mineure.correctif) ; WAC.rc reste la seule source — `@WAC_VERSION@` dans sources/wac.yml, remplacé par --write-config et par la compilation pour bin/wac.yml ; le harnais écrit la version de WAC.rc dans ses wac.yml. État : code des clés, harnais et contrôle écrits, non commités, non compilés depuis les dernières retouches.
- 2026-10-07 : tout le code de la fiche écrit, compilé sans avertissement, config_test et file_artefacts_test verts ; rien de commité de ce code. Cycle complet lancé.

# B-039 — Artefacts organisés par version de Windows et par disponibilité

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | moyen |

## Pourquoi
Chaque artefact n'existe que sur certaines versions de Windows, à un emplacement et dans un format qui changent d'une version à l'autre : `.evt` puis `.evtx`, Prefetch v17 puis v30, `index.dat` puis WebCache, Chronologie sous Windows 10 seulement, SRUM et Amcache depuis 8, jump lists depuis 7, index de recherche en ESE puis en SQLite. Aujourd'hui, cette connaissance est dispersée dans le code de chaque collecteur. Demande utilisateur du 2026-10-06 : réorganiser les artefacts par version et disponibilité. Prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP) ; B-038 (versions serveur) s'appuie aussi sur elle.

## Source
Le code de chaque collecteur, les fiches archivées et leurs mesures, la documentation publique des formats.

## Sortie attendue
- Une table unique, dans le code et dans la documentation FR et EN : pour chaque artefact (clé de `wac.yml`), les versions de Windows client et serveur où il existe, son emplacement et son format selon la version, et son absence en Server Core.
- WAC détermine la version de la machine examinée, et pour un artefact absent de cette version émet un `CollectionStatus` qui le dit (absent de cette version, et non échec ni zéro trouvé).
- Le format attendu est choisi d'après la version, ou reconnu sur la pièce quand la version ne suffit pas.

## Référence indépendante
Les VM de B-037 et B-038 : sur chacune, chaque artefact est soit collecté, soit déclaré absent conformément à la table, jamais en échec.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque clé de `wac.yml` figure dans la table.
- Aucun collecteur ne garde pour lui seul une condition de version que la table ne porte pas.

## Tâches
- [ ] Inventaire, par artefact, des versions, emplacements et formats (à partir du code et des fiches)
- [ ] Table dans le code (une seule source) et dans la documentation FR et EN
- [ ] Détection de la version de la machine examinée (hors ligne : ruche SOFTWARE)
- [ ] `CollectionStatus` « absent de cette version »

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur — prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP).

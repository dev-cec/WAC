# B-039 — Artefacts organisés par version de Windows et par disponibilité

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | moyen |

## Pourquoi
Chaque artefact n'existe que sur certaines versions de Windows, à un emplacement et dans un format qui changent d'une version à l'autre : `.evt` puis `.evtx`, Prefetch v17 puis v30, `index.dat` puis WebCache, Chronologie sous Windows 10 seulement, SRUM et Amcache depuis 8, jump lists depuis 7, index de recherche en ESE puis en SQLite. Aujourd'hui, cette connaissance est dispersée dans le code de chaque collecteur. Demande utilisateur du 2026-10-06 : réorganiser les artefacts par version et disponibilité. Prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP) ; B-038 (versions serveur) s'appuie aussi sur elle.

Elle doit surtout **faciliter l'arrivée des prochaines versions de Windows et des nouveaux formats d'artefacts** (demande utilisateur du 2026-10-06) : Windows change un format (Chronologie retirée de 11, index de recherche passé d'ESE à SQLite) sans prévenir, et chaque changement ne doit coûter qu'un ajout localisé, pas une reprise de chaque collecteur.

## Source
Le code de chaque collecteur, les fiches archivées et leurs mesures, la documentation publique des formats.

## Sortie attendue
- Une table unique, dans le code et dans la documentation FR et EN : pour chaque artefact (clé de `wac.yml`), les versions de Windows client et serveur où il existe, son emplacement et son format selon la version, et son absence en Server Core.
- WAC détermine la version de la machine examinée, et pour un artefact absent de cette version émet un `CollectionStatus` qui le dit (absent de cette version, et non échec ni zéro trouvé).
- Le format attendu est choisi d'après la version, ou reconnu sur la pièce quand la version ne suffit pas.
- **Ajouter une version de Windows** = ajouter ses lignes à la table (disponibilité, emplacement, format) ; **ajouter un format** = un décodeur enregistré pour ce format, reconnu par sa signature ou sa version interne. Aucune autre modification dispersée.
- **Une version inconnue** (plus récente que la table) n'empêche pas la collecte : elle est traitée comme la dernière version connue, et signalée comme telle dans le journal d'investigation et le `CollectionStatus`.
- **Un format inconnu** (nouvelle version interne d'un fichier, schéma de base changé) est reconnu comme tel : la pièce est collectée brute, le JSON dit « format non pris en charge » avec la version rencontrée, jamais une conversion fausse ni un silence.

## Référence indépendante
Les VM de B-037 et B-038 : sur chacune, chaque artefact est soit collecté, soit déclaré absent conformément à la table, jamais en échec.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque clé de `wac.yml` figure dans la table.
- Aucun collecteur ne garde pour lui seul une condition de version que la table ne porte pas.
- Démontré par l'exemple : une version fictive ajoutée à la table et un format interne inconnu présenté à un décodeur (test unitaire) — la première est collectée comme la dernière connue et signalée, le second est collecté brut et déclaré non pris en charge.

## Tâches
- [ ] Inventaire, par artefact, des versions, emplacements et formats (à partir du code et des fiches)
- [ ] Table dans le code (une seule source) et dans la documentation FR et EN
- [ ] Détection de la version de la machine examinée (hors ligne : ruche SOFTWARE)
- [ ] `CollectionStatus` « absent de cette version »
- [ ] Repli d'une version inconnue sur la dernière connue, signalé
- [ ] Reconnaissance des formats par signature ou version interne ; « format non pris en charge » avec la pièce brute
- [ ] Guide « ajouter une version de Windows / un format » dans la documentation développeur

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur — prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP).
- 2026-10-06 : objectif précisé par l'utilisateur — la fiche doit faciliter l'arrivée des prochaines versions de Windows et des nouveaux formats d'artefacts.

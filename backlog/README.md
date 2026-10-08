# Backlog de WAC

Le suivi du projet : ce qui est fait, ce qui est en cours, ce qui reste.
Remplace `TODO.txt`.

## Règles

- **Une fiche par élément** : `B-NNN-sujet.md`. Elle dit pourquoi, la source,
  la sortie attendue, la **référence indépendante** qui prouvera la justesse,
  les critères d'acceptation, les tâches et un journal daté des décisions.
- **Statuts** : `à faire` → `en cours` → `à valider` (écrit, compilé,
  tests unitaires verts, cycle VM à passer) → `à commiter` → `fait`
  (commit cité). `à décider` quand un choix de principe précède tout
  développement.
- **Priorités** : P1 attendu de toute collecte, P2 utile, P3 plus tard.
- Un élément fini quitte la table « Ouvert » : sa fiche est **déplacée dans
  `archives/`** avec le statut `fait (commit)` et son journal complété. Une
  fiche n'est jamais supprimée : `archives/` est l'historique du projet.
- On ne déclare pas fini ce qui n'a pas passé la définition ci-dessous.

## Définition de « fini » (tout élément)

1. Compilation MinGW sans avertissement (`./build-windows.sh --test`).
2. Tests unitaires existants verts sous Wine ; pour un décodeur nouveau, un
   test sur des entrées au résultat connu, **vu échouer** quand le défaut est
   réintroduit.
3. Cycle VM complet vert (`vmtest/run-wac-test.sh`), avec un **témoin** de
   valeur connue retrouvé par `check-json.py` pour tout nouvel artefact.
4. Contrôle d'innocuité vert : rien d'écrit sur la machine examinée.
5. Nouvel artefact : prélèvement brut **et** JSON dans `--convert`, même
   structure que les autres (struct + toJson, getData/clear), clé sous
   `artefacts:` de `wac.yml`, textes console FR et EN.
6. Règles communes respectées (`/var/www/html/.claude/CLAUDE.md`) : aucun
   champ vide émis, lectures bornées, pas de code mort ni de copier-coller.
7. Documentation FR **et** EN à jour : manuel, guide des tests, dossier de
   validation, dossier d'innocuité si une opération change, README ; PDF
   régénérés.
8. Commit sur master, un sujet par commit (`feat :`, `fix :`, `docs :`,
   `refactor :`), sans push sauf demande ; ce backlog mis à jour.

## Ouvert

### Version 2.0.0

Les fiches restantes, puis la montée de version (B-025), puis l'article (B-018).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-025](B-025-version-2-0.md) | Version 2.0.0 (montée majeure), juste avant l'article DFIR | à faire | P2 | faible |
| [B-018](B-018-article-dfir.md) | Article de présentation (2 pages, magazine DFIR), après la 2.0.0 et avant la 3.0 | à faire | P3 | moyen |

### Version 3.0 — rétrocompatibilité et serveurs

Très gros chantier, après l'article : collecte depuis Windows XP SP1 et sur les
versions serveur, artefacts propres aux serveurs (web, Active Directory).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-039](B-039-artefacts-par-version-windows.md) | Artefacts organisés par version de Windows et par disponibilité (prérequis de B-035, B-037, B-038) | à faire | P3 | moyen |
| [B-038](B-038-compatibilite-windows-server.md) | Collecte compatible avec les versions serveur, de Server 2003 à 2026 (prérequis de B-035) | à faire | P3 | fort |
| [B-035](B-035-web-serveur.md) | Web côté serveur : journaux, code des sites, bases de données (clé `web_server`) — après B-039 et B-038 | à faire | P3 | fort |
| [B-041](B-041-active-directory.md) | Artefacts de compromission d'Active Directory (contrôleurs de domaine) | à faire | P2 | fort |
| [B-014](B-014-vss-brut.md) | Clichés instantanés lus en brut | à décider (reportée en 3.0) | P3 | fort |
| [B-037](B-037-compatibilite-windows-xp.md) | Collecte compatible avec toutes les versions de Windows depuis XP SP1 (après B-039) | à faire | P3 | fort |
| [B-036](B-036-recuperation-fichiers-supprimes.md) | Récupération des fichiers supprimés par lecture brute du disque, sans trace | à décider (étude, reportée en 3.0) | P2 | fort |

## Réalisé

Dans [archives/](archives/) :
- [B-000 — point de départ](archives/B-000-point-de-depart.md) : ce que WAC
  faisait au 29 septembre 2026, de la version d'origine de 2025 à la migration,
  avec les décisions, leurs raisons et les commits ;
- puis une fiche par élément fini depuis, statut `fait` et commit cités.

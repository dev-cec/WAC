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

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-010](B-010-activitiescache.md) | Chronologie Windows (ActivitiesCache.db) | à faire | P3 | fort |
| [B-011](B-011-rdp-cache.md) | Cache bitmap RDP et connexions RDP sortantes | à faire | P3 | moyen |
| [B-014](B-014-vss-brut.md) | Clichés instantanés lus en brut | à décider | P3 | fort |
| [B-015](B-015-confrontation-kape.md) | Confrontation à KAPE et aux outils Zimmerman | en cours | P1 | moyen |
| [B-016](B-016-web.md) | Navigateurs, téléchargements, code des sites | à faire | P1 | fort |
| [B-017](B-017-emails.md) | Courriels et pièces jointes | à faire | P2 | fort |
| [B-018](B-018-article-dfir.md) | Article de présentation (2 pages, magazine DFIR) | à faire | P3 | moyen |
| [B-022](B-022-prefetch-metriques.md) | Prefetch : métriques absentes sur 124 fichiers sur 279 | à faire | P2 | moyen |
| [B-023](B-023-messages-evenements.md) | Messages lisibles d'environ un tiers des événements seulement | à faire | P3 | moyen |
| [B-024](B-024-msys2.md) | Compilation MSYS2 à éprouver sur un vrai Windows | à faire | P3 | faible |
| [B-025](B-025-version-1-5.md) | Version 1.5.0 | à faire | P2 | faible |
| [B-026](B-026-thumbcache.md) | Cache des miniatures (thumbcache) | à faire | P3 | moyen |
| [B-027](B-027-empreinte-comparee.md) | Empreinte comparée WAC / KAPE / EZ sous bac à sable (Sysmon, audit en option) | à faire | P2 | fort |
| [B-029](B-029-variante-element-archive.md) | Variante d'élément d'archive mal décodée (à reproduire) | à faire | P3 | faible |
| [B-030](B-030-conversions-dans-tools.md) | Regrouper toutes les fonctions de conversion dans tools (fin de refactoring) | à faire | P2 | moyen |
| [B-031](B-031-couverture-registre-kroll.md) | Couverture du registre face au lot Kroll de RECmd (Uninstall, exclusions Defender, RecentDocs, MountPoints2, réseaux connus…) | à faire | P1 | moyen |

## Réalisé

Dans [archives/](archives/) :
- [B-000 — point de départ](archives/B-000-point-de-depart.md) : ce que WAC
  faisait au 29 septembre 2026, de la version d'origine de 2025 à la migration,
  avec les décisions, leurs raisons et les commits ;
- puis une fiche par élément fini depuis, statut `fait` et commit cités.

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

### Version 3.0 — tous les clients, de XP à 11, et tous leurs artefacts

Décision utilisateur du 2026-10-17 : la 3.0.0 couvre les versions clientes de
Windows XP SP1 à Windows 11, avec tous les artefacts ; les serveurs passent en
4.0. Ordre : harnais sous Vista (fait), clichés instantanés (fait), fichiers
supprimés (B-036), la couverture MITRE ATT&CK (B-052), puis la revue (B-050) et la publication.

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-036](B-036-recuperation-fichiers-supprimes.md) | Récupération des fichiers supprimés par lecture brute du disque, sans trace | en cours : niveau 1 | P2 | fort |
| [B-053](B-053-sysmon.md) | Sysmon s'il est présent : journal (même déplacé), configuration, archives des fichiers supprimés | à faire | P1 | moyen |
| [B-056](B-056-temoins-cliche-windows-7.md) | Témoins du cliché instantané peu fiables sous Windows 7 (libvshadow lit comme WAC) | à faire (avant B-050) | P2 | moyen |
| [B-052](B-052-couverture-mitre-attack.md) | Couverture MITRE ATT&CK : toutes les traces utiles à la détection prélevées ? Résultat dans la documentation | à faire (avant de clore la 3.0) | P1 | fort |
| [B-050](B-050-revue-code-securite-avant-3.0.md) | Revue de code et revue de sécurité de tout le projet — préalable à la publication de la 3.0.0 | à faire | P1 | fort |

### Version 4.0 — serveurs

Collecte sur les versions serveur, de Server 2003 à 2025, et artefacts propres
aux serveurs (web, Active Directory).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-038](B-038-compatibilite-windows-server.md) | Collecte compatible avec les versions serveur, de Server 2003 à 2026 (prérequis de B-035) | en cours | P3 | fort |
| [B-035](B-035-web-serveur.md) | Web côté serveur : journaux, code des sites, bases de données (clé `web_server`) — après B-039 et B-038 | à faire | P3 | fort |
| [B-041](B-041-active-directory.md) | Artefacts de compromission d'Active Directory (contrôleurs de domaine) | à faire | P2 | fort |

## Réalisé

Dans [archives/](archives/) :
- [B-000 — point de départ](archives/B-000-point-de-depart.md) : ce que WAC
  faisait au 29 septembre 2026, de la version d'origine de 2025 à la migration,
  avec les décisions, leurs raisons et les commits ;
- puis une fiche par élément fini depuis, statut `fait` et commit cités.

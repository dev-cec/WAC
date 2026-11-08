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
supprimés (B-036), la couverture MITRE ATT&CK (B-052), puis la revue (B-050), la publication, et l'article de la 3.0.0 (B-058).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|

### Version 4.0 — serveurs

Collecte sur les versions serveur, de Server 2003 à 2025, et artefacts propres
aux serveurs (web, Active Directory).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|

### Clôture de la 4.0.0

Revue de sécurité du code de la 4.0.0, avant sa publication.

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|

### Version 5.0 — traces d'applications, clients et serveurs

Décision utilisateur du 2026-11-05 : la 4.0.0 se clôt avec les serveurs ; ces
artefacts passent en 5.0.0, avec une option `wac.yml` par produit, regroupées
par type. Ils valent pour les clients comme pour les serveurs. Code mis de côté
dans un `git stash` (voir B-062).

| Fiche | Sujet | Statut | Priorité | Effort |
|---|---|---|---|---|
| [B-062](B-062-traces-applications-mecanisme.md) | Traces d'applications : mécanisme commun, une option `wac.yml` par produit | en cours (compilé, tests verts) | P1 | moyen |
| [B-063](B-063-administration-a-distance.md) | `remote_administration` : outils d'administration à distance | à faire (5.0.0, code mis de côté) | P1 | moyen |
| [B-064](B-064-antivirus-tiers.md) | `antivirus` : journaux des antivirus autres que Defender | à faire (5.0.0, code mis de côté) | P1 | moyen |
| [B-065](B-065-messageries.md) | `messaging` : messageries | à faire (5.0.0, code mis de côté) | P2 | moyen |
| [B-066](B-066-stockage-en-ligne.md) | `cloud_storage` : métadonnées du stockage en ligne | à faire (5.0.0, code mis de côté) | P2 | faible |
| [B-067](B-067-transfert-de-fichiers.md) | `file_transfer` : outils de transfert de fichiers | à faire (5.0.0, code mis de côté) | P2 | faible |
| [B-068](B-068-vpn.md) | `vpn` : clients VPN | à faire (5.0.0, code mis de côté) | P2 | faible |
| [B-069](B-069-virtualisation.md) | `virtualisation` : VirtualBox, VMware Workstation, WSL | à faire (5.0.0, code mis de côté) | P2 | faible |
| [B-070](B-070-openssh.md) | `ssh` : OpenSSH serveur et client | à faire (5.0.0, code mis de côté) | P1 | faible |
| [B-071](B-071-applications-serveur-et-journaux.md) | `server_applications` et `server_logs` : applications et journaux de serveur | à faire (5.0.0, code mis de côté) | P1 | moyen |
| [B-072](B-072-traces-systeme.md) | `system_traces` : ce que Windows garde en plus | à faire (5.0.0, code mis de côté) | P1 | moyen |
| [B-073](B-073-registre-des-outils.md) | `application_registry` : PuTTY, WinSCP, WinRAR et 7-Zip dans le registre | à faire (5.0.0, code mis de côté) | P2 | faible |
| [B-076](B-076-traces-applications-conversion.md) | Traces d'applications : conversion générique en JSON (journaux texte, texte structuré) | en cours (tests verts ; témoin et cycles à faire) | P1 | moyen |
| [B-074](B-074-revue-code-securite-5.0.md) | Revue de code et revue de sécurité de la 5.0.0 | à faire (en dernier) | P1 | fort |
| [B-075](B-075-documentation-article-5.0.md) | Documentation de la 5.0.0 à jour et article de la 5.0.0 | à faire (après B-074, avant la publication) | P1 | moyen |

## Réalisé

Dans [archives/](archives/) :
- [B-000 — point de départ](archives/B-000-point-de-depart.md) : ce que WAC
  faisait au 29 septembre 2026, de la version d'origine de 2025 à la migration,
  avec les décisions, leurs raisons et les commits ;
- puis une fiche par élément fini depuis, statut `fait` et commit cités.

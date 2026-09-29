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
- Un élément fini **quitte la table « Ouvert »** et rejoint « Réalisé » avec
  son commit ; sa fiche est supprimée, l'historique restant dans git.
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
| [B-002](B-002-petits-artefacts-fichiers.md) | Lot 1 : petits artefacts fichiers (7) | à valider | P1 | faible |
| [B-003](B-003-ruches-security-default.md) | Ruches SECURITY et DEFAULT, RegBack | à faire | P2 | faible |
| [B-004](B-004-zone-identifier.md) | Flux Zone.Identifier (Mark of the Web) | à faire | P2 | faible |
| [B-005](B-005-mft-usn-autres-volumes.md) | $MFT et $UsnJrnl de chaque volume NTFS fixe | à faire | P2 | faible |
| [B-006](B-006-defender-detections.md) | Defender : historique des détections et quarantaine | à faire | P2 | moyen |
| [B-007](B-007-persistance-etendue.md) | Persistance étendue (registre, BITS) | à faire | P1 | moyen |
| [B-008](B-008-wmi.md) | Abonnements WMI (dépôt CIM) | à faire | P1 | fort |
| [B-009](B-009-srum-ese.md) | SRUM et Windows.edb (lecteur ESE) | à faire | P2 | fort |
| [B-010](B-010-activitiescache.md) | Chronologie Windows (ActivitiesCache.db) | à faire | P3 | fort |
| [B-011](B-011-rdp-cache.md) | Cache bitmap RDP et connexions RDP sortantes | à faire | P3 | moyen |
| [B-012](B-012-lot2-registre.md) | Lot 2 : registre utilisateur et système | à faire | P2 | faible |
| [B-013](B-013-fat-exfat.md) | Lecture brute FAT et exFAT | à faire | P2 | fort |
| [B-014](B-014-vss-brut.md) | Clichés instantanés lus en brut | à décider | P3 | fort |
| [B-015](B-015-confrontation-kape.md) | Confrontation à KAPE et aux outils Zimmerman | à faire | P1 | moyen |
| [B-016](B-016-web.md) | Navigateurs, téléchargements, code des sites | à faire | P1 | fort |
| [B-017](B-017-emails.md) | Courriels et pièces jointes | à faire | P2 | fort |
| [B-018](B-018-article-dfir.md) | Article de présentation (2 pages, magazine DFIR) | à faire | P3 | moyen |
| [B-019](B-019-mftentry-live.md) | MftEntry: 0 émis pour les pièces « live » | à faire | P2 | faible |
| [B-020](B-020-footprint-octet.md) | Texte « a l'octet » dans le Footprint HIVE_REPLAY | à faire | P3 | faible |
| [B-021](B-021-new-delete-shellbags.md) | new/delete nus dans reg_shellbags | à faire | P2 | faible |
| [B-022](B-022-prefetch-metriques.md) | Prefetch : métriques absentes sur 124 fichiers sur 279 | à faire | P2 | moyen |
| [B-023](B-023-messages-evenements.md) | Messages lisibles d'environ un tiers des événements seulement | à faire | P3 | moyen |
| [B-024](B-024-msys2.md) | Compilation MSYS2 à éprouver sur un vrai Windows | à faire | P3 | faible |
| [B-025](B-025-version-1-5.md) | Version 1.5.0 | à faire | P2 | faible |

## Réalisé

**Inventaire par domaine, avec les décisions et leurs raisons : [REALISE.md](REALISE.md)**
— à lire avant de reprendre le projet. Ci-dessous, les lots dans l'ordre.

| Période | Réalisé | Commits |
|---|---|---|
| 2025-05 | Version d'origine (1.0 à 1.3.1) : collecte par VSS, COM et API, empreintes MD5 | 6508455 … 5ee5a1c |
| 2026-09-15/17 | Collecte hors ligne : lecture NTFS brute, plus de VSS ni de COM ; journaux d'événements lus hors ligne ; rejeu des journaux de ruche ; consigne scellée et copie de travail ; décompression NTFS et WOF ; profils lus dans la ruche copiée | f3a6b3a, 1aab531, 958d35b, 6a41ed5, 6a61a8e, d812e20, 78e573f |
| 2026-09-22 | `--binary` : empreintes et prélèvement des binaires cités, documents à macros, authentification Microsoft en mémoire ; aucun champ vide ; documentation LaTeX FR et EN | e6bf86f, 5934a3b, 886a765, 4f7666c, 7fba566, 88508c2 |
| 2026-09-23 | Tout le code en anglais ; documentation doxygen complète ; lectures bornées (données tronquées ou forgées) ; listes de sauts, Prefetch, raccourcis corrigés ; guide des tests | 1984886, 8f23ad8, d88a4b5, 6f903a8, 973f5d0, bb84afd |
| 2026-09-24/25 | Lecteur de ruches propre (plus d'offreg.dll) ; 5 DLL importées ; dates UTC exactes, heure d'été ; enregistrements NTFS déchirés refusés ; SID et GUID nommés hors ligne ; relevés en direct scellés ; collecte séparée de la conversion ; `--binary-all` ; LZX ; dossier de validation | 5eabec8, f989656, 50537d5, 66e5567, a3e27ec, 37bfea4, bae8b85, 5eb3517, 5c12c3a, 42a10df |
| 2026-09-26 | Signatures tierces vérifiées (chaîne, horodatage, CRL, pilotes vulnérables) avec `--update-trust` ; analyse parallèle ; `wac.yml` ; version 1.4.0 ; relevé réseau direct | 3d06aa1, c341d31, fc0610b, 2d13f42, 73c23d0, 9fefefc, c6f1b57, c993162 |
| 2026-09-29 | Clés JSON cohérentes (B-001) ; $MFT et journal USN ; volume lu sans cache, BAM de la collecte séparée ; scripts de vérification `.sh` et confinement des chemins ; dossier d'innocuité et contrôle par témoins ; `bin/` et `sources/` ; compilation unique MinGW (MSVC retiré) ; console FR/EN | 92b14e9, 01549c7, 49d27d3, 2901062, 654e2b8, 5d1a0e9, ec795f5, 84e60e7, 2742bbb |

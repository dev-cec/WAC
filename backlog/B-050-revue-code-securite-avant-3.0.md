# B-050 — Revue de code et revue de sécurité de tout le projet, avant la 3.0.0

| Statut | Priorité | Effort |
|---|---|---|
| à faire (préalable à la publication de la 3.0.0) | P1 | fort |

## Pourquoi
Demande utilisateur du 2026-10-15 : avant de publier la 3.0.0, une revue de code de l'ensemble du projet, et idéalement une revue de sécurité. La 3.0 ajoute beaucoup de décodeurs de formats non documentés (Prefetch 26, ShimCache et Amcache de Windows 8, index de recherche ESE, files BITS anciennes, réseau et journaux de XP…), et le travail de 2.0.1 à 2.0.3 a montré que des défauts anciens produisent du JSON valide et faux sans le moindre signal : rejeu des ruches qui perdait une entrée, condensats SAM faux au schéma RC4, empreintes prises sur les copies de travail. Une revue d'ensemble, distincte des contrôles du harnais, cherche ce que les cycles ne voient pas.

## Périmètre
Tout le dépôt, pas seulement les modifications récentes :
- `sources/` : chaque collecteur et décodeur, le lecteur NTFS brut, le lecteur de ruches, le lecteur ESE, la consigne et son sceau, la configuration ;
- les scripts livrés (`sources/scripts` : vérification de la consigne, en PowerShell et en shell) ;
- `build-windows.sh`, `bump-version.sh` ;
- le harnais (`vmtest/`) : en second, il ne part pas chez l'analyste.

## Ce que la revue de code doit chercher
- **Justesse** : lectures bornées par la taille réelle du tampon (règle commune n° 3), résultats d'appels lus (n° 5), champs vides non émis (n° 1), dates UTC et locales, codes Windows (énumération ou champ de bits), conversions d'encodage ;
- **Règles communes** (`/var/www/html/.claude/CLAUDE.md`) : code mort, copier-coller, nommage anglais, commentaires faux ou absents ;
- **Cohérence** : une seule normalisation des chemins, une seule fonction par conversion, même structure pour chaque artefact.

## Ce que la revue de sécurité doit chercher
Toute pièce lue est hostile (règle commune n° 3) : ruches, bases ESE et SQLite, Prefetch, raccourcis, journaux, quarantaine de Defender… forgés pour faire lire WAC hors de son tampon, boucler, allouer sans borne ou écrire hors du dossier de sortie. Aussi :
- l'innocuité de la collecte (rien d'écrit sur le disque examiné) ;
- la consigne intouchable après sa copie initiale ;
- l'absence de secret dans le code et dans l'historique git ;
- les dépendances (SQLite, libyaml) et le chargement des DLL système (esent.dll, WinHTTP).

## Outils
- **`/code-review`** (Claude Code) : par cible de chemin, module par module (lecteurs bruts, décodeurs, consigne, scripts), au niveau `high` ou `xhigh`, constats rapportés puis vérifiés un par un ; `--fix` seulement après lecture. La variante `/code-review ultra` (revue multi-agents dans le nuage, déclenchée et facturée par l'utilisateur) convient à l'ensemble du dépôt d'un coup : à lancer par l'utilisateur s'il le souhaite.
- **`/security-review`** (Claude Code) : revue de sécurité dédiée ; à appliquer à l'ensemble du code, par branche ou par lots, en plus de `/code-review`.
- Le harnais existant : chaque constat corrigé reçoit le test qui l'aurait pris (règle commune, section 6).

## Critères d'acceptation
- Chaque module de `sources/` passé en revue (liste tenue dans le journal ci-dessous) ;
- chaque constat soit corrigé (commit cité, avec son test), soit écarté avec sa raison écrite ici ;
- revue de sécurité passée sur tout le code livré ;
- cycles VM Windows 11 et 8.1 sans échec après les corrections ;
- puis seulement : montée de version 3.0.0 (`bump-version.sh --major`) et publication.

## Tâches
- [ ] Découper le dépôt en lots de revue (par dossier ou famille de décodeurs)
- [ ] `/code-review` lot par lot ; constats triés et traités
- [ ] `/security-review` sur le code livré ; constats triés et traités
- [ ] Proposer à l'utilisateur `/code-review ultra` sur l'ensemble, s'il le souhaite
- [ ] Cycles VM verts après corrections
- [ ] Mise à jour des documents (validation, innocuité) si une correction change une opération

## Journal
- 2026-10-15 : fiche créée à la demande de l'utilisateur : revue de code de l'ensemble du projet avant de publier la 3.0.0, gros chantier ; idéalement une revue de sécurité avec le greffon adapté (`/security-review`).
- 2026-10-17 : décision utilisateur — la 3.0.0 couvre les clients de XP à 11 avec tous les artefacts (clichés instantanés et fichiers supprimés compris) ; la revue porte sur ce périmètre, avant la publication.

# B-074 — Revue de code et revue de sécurité de la 5.0.0

| Statut | Priorité | Effort |
|---|---|---|
| à faire (en dernier, avant la publication de la 5.0.0) | P1 | fort |

## Pourquoi
Demande de l'utilisateur (2026-11-08) : la 5.0.0 se clôt, comme la 4.0.0 (B-060), par une revue de code et une revue de sécurité. Les traces d'applications prélèvent des fichiers qui portent des secrets (sessions de messageries, configurations d'outils de transfert, vidages de plantage), écrits par des produits tiers dont le format change : un défaut y coûte plus cher qu'ailleurs, et ce code a été écrit hors des cycles, compilé tard.

## Ordre
**Dernier élément de la 5.0.0** : elle passe quand B-062 à B-073 sont closes, sur le code qui sera livré. Tout code ajouté après elle demande de revoir au moins ce qui a changé.

## Périmètre
Tout le code venu depuis le tag `4.0.0` (`git diff 4.0.0..`), harnais compris.
- **Revue de code** : règles communes (`/var/www/html/.claude/CLAUDE.md`) — aucun champ vide émis, pas de code mort ni de copier-coller, un seul nom par concept, résultats d'appels lus, une fonction par chose ; structure des artefacts (struct + toJson, getData/clear) ; une clé `wac.yml` par produit, groupes cohérents ; commentaires justes.
- **Entrées hostiles** : filtre à motifs, expansion des dossiers par lecture brute (`..`, liens, jonctions, noms forgés, profondeur), `ListDirectoryRaw`, lecture des options ; chaque décodeur nouveau (registre des outils) : lectures bornées, longueurs annoncées.
- **Secrets prélevés** : ce que la table prend et ce qu'elle exclut (clés privées SSH, valeurs de mot de passe du registre, vidages de plantage, `tdata`, `sitemanager.xml`, `WinSCP.ini`) ; ce qui en sort dans le JSON, les journaux et la console ; décisions de l'utilisateur appliquées.
- **Exécution sur la machine examinée** : rien d'écrit, lecture brute seulement, innocuité mesurée sur les nouveaux chemins.
- **Dépendances** : versions embarquées confrontées aux failles publiées (OSV, NVD), comme pour la 4.0.0.
- **Dépôt et publication** : secrets dans l'historique depuis `4.0.0`, jeux de test et témoins du harnais compris.

## Sortie attendue
Un rapport daté dans cette fiche : ce qui a été examiné et comment, chaque constat avec sa gravité et son scénario concret, le correctif et son commit, ou la raison de ne pas corriger ; ce qui n'a pas été examiné.

## Référence indépendante
Pas seulement une relecture : recherche de secrets sur l'historique (motifs et detect-secrets), cppcheck, `hostile_input_test` étendu aux lecteurs et au filtre de la 5.0 (mutations à graine fixe, pages de garde), confrontation des dépendances aux bases de failles publiques.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Tout le périmètre examiné, ou l'écart dit et accepté par l'utilisateur.
- Chaque constat grave ou élevé corrigé, avec le test qui l'aurait pris, vu échouer ; les autres corrigés ou acceptés par écrit.
- Cycle VM complet vert après les correctifs, sur un client et un serveur.
- Aucun secret réel dans l'historique ; s'il y en a un, il est renouvelé.

## Tâches
- [ ] Vérifier que B-062 à B-073 sont closes
- [ ] Choisir les outils et fixer la méthode
- [ ] Revue de code, par point du périmètre
- [ ] Revue de sécurité, par point du périmètre
- [ ] Correctifs et leurs tests
- [ ] Cycle VM complet après les correctifs
- [ ] Rapport, documentation FR et EN si une opération change

## Journal
- 2026-11-08 : créée à la demande de l'utilisateur, à faire en dernier dans la 5.0.0, sur le modèle de B-060.

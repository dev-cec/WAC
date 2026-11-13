# B-074 — Revue de code et revue de sécurité de la 5.0.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

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
- [x] Choisir les outils et fixer la méthode
- [ ] Revue de code, par point du périmètre
- [ ] Revue de sécurité, par point du périmètre
- [ ] Correctifs et leurs tests
- [ ] Cycle VM complet après les correctifs
- [ ] Rapport, documentation FR et EN si une opération change

## Journal
- 2026-11-08 : créée à la demande de l'utilisateur, à faire en dernier dans la 5.0.0, sur le modèle de B-060.
- 2026-11-12 : **outils et premiers passages, pendant la série de cycles.** cppcheck 2.19 et detect-secrets 1.5 (installés hors du dépôt, l'hôte mis à niveau ne les avait plus). cppcheck sur les 23 sources modifiées depuis `4.0.0` : 5 erreurs `returnDanglingLifetime` (`event_messages.cpp`, pointeur lu avant que l'objet passe au cache, qui le garde), 1 avertissement d'indice (`time_zone.cpp`, gardé par le ternaire), 3 conditions « toujours vraies » (valeurs rendues par pointeur), `%lc` d'un `wchar_t` (promu en `wint_t`) : faux positifs, relus un à un ; le reste est du style. detect-secrets sur les lignes ajoutées depuis `4.0.0` : 0 constat ; motifs (mot de passe, jeton, clé privée, AWS, GitHub) : seulement les secrets factices des tests et des témoins. Constat : `localTimeToIso8601Utc` (tools.cpp) n'est appelée que par `system_conversions_test` — code mort, à retirer avec ses contrôles.
- 2026-11-12 : **dépendances.** Aucune changée depuis `4.0.0` (SQLite 3.54.1, libyaml 0.2.5). OSV : rien pour l'une ni l'autre. NVD, publiées du 25 octobre au 12 novembre : dix CVE de SQLite « avant 3.54.0 », corrigées par la 3.54.1 embarquée ; CVE-2026-119586 touche la 3.54.1 mais seulement le shell (`.recover`), que WAC ne compile pas (`sqlite3.c` seul) ; rien pour libyaml.
- 2026-11-12 : **constat élevé, corrigé : une clé privée d'un fichier texte entrait dans le JSON.** La conversion écarte les valeurs nommées comme un secret des fichiers XML, JSON et INI, mais sortait les fichiers texte ligne à ligne : un `.ovpn`, `.key` ou `.pem` du dossier `OpenVPN\config` (pris entier) aurait mis en clair sa clé privée PEM, sa clé statique OpenVPN, son `<pkcs12>` ou son `<auth-user-pass>`. Correctif : `secretBlockEnd` (application_trace_files.cpp) — le bloc laissé de côté jusqu'à sa fermeture, la ligne d'ouverture gardée seule avec `HasPassword`, un bloc jamais fermé cachant le reste du fichier ; un certificat, public, gardé. `testSecretBlocks` : 5 contrôles, vu échouer par mutation (3), 65 contrôles verts ; `hostile_input_test` 46 000 entrées, vert (07429530). Relu sans constat : `wildcard.h` (itératif, coût borné), table des traces, `application_registry.cpp` (valeurs de mot de passe écartées, profondeur bornée). Cycle VM à passer.

# B-060 — Revue de sécurité complète avant la clôture du projet

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

## Pourquoi
Demande de l'utilisateur (2026-11-03) : avant de clôturer le projet, une revue de sécurité complète. WAC tourne avec les droits les plus élevés sur une machine peut-être compromise, lit des fichiers qu'un attaquant a pu forger, et sa sortie contient des données sensibles : un défaut y coûte plus cher que dans un outil ordinaire. La revue B-050 portait sur la 3.0.0 ; le code des serveurs et de l'annuaire est venu après.

## Ordre
**Dernier élément du backlog** : elle passe quand toutes les autres fiches sont closes, pour porter sur le code qui sera effectivement livré. Tout ajout de code après elle demande de revoir au moins ce qui a changé.

## Périmètre
- **Entrées hostiles** : chaque décodeur (ruches, ESE, NTFS, journaux d'événements, Prefetch, `.lnk`, Registry.pol, XML, SQLite...) : lectures bornées par le tampon réel, longueurs annoncées, débordements d'entiers, récursions et boucles sans fin, consommation de mémoire.
- **Mémoire C++** : `new`/`delete` nus, durée de vie des pointeurs, valeurs de retour ignorées.
- **Exécution sur la machine examinée** : privilèges demandés, DLL chargées et ordre de recherche, chemins et fichiers temporaires, commandes lancées, innocuité.
- **Sortie** : ce que contient la collecte (condensats SAM, clés DPAPI, bases web, quarantaine), sa protection, ce qui en sort dans les journaux et messages ; annuaire : aucun secret lu ni émis.
- **Scripts livrés** (`sources/scripts`, `verify-exhibits`, `verifier-consigne`) : manifeste forgé, chemins, injection.
- **Dépendances** : libyaml, SQLite et autres composants embarqués : versions, failles publiées, épinglage.
- **Dépôt et publication** : secrets dans tout l'historique git et les jeux de test, y compris le harnais (`vmtest/`) ; binaires et fichiers publiés dans les releases.

## Sortie attendue
Un rapport de revue daté, dans cette fiche ou joint à la documentation : ce qui a été examiné et comment, chaque constat avec sa gravité et son scénario concret, le correctif et son commit, ou la raison de ne pas corriger. Ce qui n'a pas été examiné y est dit.

## Référence indépendante
Pas seulement une relecture : des contrôles que le code ne peut pas biaiser. Outils à choisir au début de la revue : analyse statique, décodeurs compilés avec les détecteurs d'erreurs mémoire et soumis à du fuzzing, recherche de secrets sur l'historique, confrontation des dépendances aux bases de failles publiques.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Tout le périmètre ci-dessus examiné, ou l'écart dit et accepté par l'utilisateur.
- Chaque constat grave ou élevé corrigé, avec le test qui l'aurait pris, vu échouer ; les autres corrigés ou acceptés par écrit.
- Aucun secret réel dans l'historique ; s'il y en a un, il est renouvelé.

## Tâches
- [ ] Vérifier que toutes les autres fiches sont closes (B-038 ouverte : écart voulu par l'utilisateur, à finir avant la release)
- [x] Choisir les outils et fixer la méthode
- [ ] Revue et contrôles, par point du périmètre
- [ ] Correctifs et leurs tests
- [ ] Cycle VM complet après les correctifs
- [ ] Rapport, documentation FR et EN si une opération change

## Journal
- 2026-11-03 : créée à la demande de l'utilisateur, à faire en dernier, avant la clôture du projet.
- 2026-11-04 : lancée à la demande de l'utilisateur alors que B-038 reste ouverte (autres rôles à décider) : écart à l'ordre prévu, voulu par l'utilisateur. Tout code ajouté ensuite sera à revoir. Version encore en 3.0.1 ; la 4.0.0 sera posée après la revue.
- 2026-11-04 : outils : recherche sur tout l'historique git, detect-secrets, cppcheck 2.22, OSV et NVD, relecture du code ajouté depuis la 3.0.1 (web, annuaire, stratégies, W3C, SQLite), harnais `hostile_input_test` (mutations à graine fixe, pages de garde). Constats reproduits avant correction : (1) **élevé** nom forgé d'un index NTFS (`..\\..\\WAC.exe`) écrit hors de la consigne, sur le support de collecte ; (2) **élevé** `..` d'une configuration web lu hors de la collecte à la conversion (`pathUnder`) ; (3) **moyen** chaîne de `Define` d'Apache : 26 Gio occupés, processus tué par le noyau ; (4) **moyen** SQLite 3.53.4 touché par des CVE atteignables par une base forgée, et vues exécutées ; (5) **faible** chiffre non ASCII dans `scripts.ini`, résultat d'une requête ignoré, branche morte, zéro émis pour une valeur trop courte de l'annuaire. Corrigés, test vu échouer puis 16 contrôles verts, 32 000 entrées mutées. Écrit, compilé, cycle VM à passer.
- 2026-11-04 : cycle complet du contrôleur sur les correctifs : 572 contrôles, 0 échec, 44 sautés. Puis deux points restés ouverts corrigés plutôt qu'acceptés : (6) **moyen** une exception non rattrapée (`std::bad_alloc` sur un fichier géant) terminait la collecte sans sceau ni journal : `runPhase` borne l'exception à sa phase, la consigne dans le journal, le code de sortie le dit ; une exception dans un fil d'exécution auxiliaire reste fatale. (7) **faible** un champ de `#Fields:` nommé `File`, `Line`, `Time` ou deux fois le même écrivait deux clés dans un objet : il va dans `OtherFields`. Zéro des valeurs trop courtes de l'annuaire : test ajouté (`directoryNumberToJson`). Test hostile : 23 contrôles. Tests Wine rejoués, Timeline sur SQLite 3.54.1 : 118 contrôles verts ; PST, index.dat et MFT à fixtures non relancés sous Wine (couverts par les cycles VM pour les données réelles).

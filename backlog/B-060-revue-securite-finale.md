# B-060 — Revue de sécurité complète avant la clôture du projet

| Statut | Priorité | Effort |
|---|---|---|
| à faire (en dernier) | P1 | fort |

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
- [ ] Vérifier que toutes les autres fiches sont closes
- [ ] Choisir les outils et fixer la méthode
- [ ] Revue et contrôles, par point du périmètre
- [ ] Correctifs et leurs tests
- [ ] Cycle VM complet après les correctifs
- [ ] Rapport, documentation FR et EN si une opération change

## Journal
- 2026-11-03 : créée à la demande de l'utilisateur, à faire en dernier, avant la clôture du projet.

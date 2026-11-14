# B-083 — Revue de code et de sécurité, puis publication de la 5.1.0

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | fort |

## Pourquoi
Demande de l'utilisateur (2026-11-14) : la prochaine version de WAC, celle
du contexte de liaison pour WAE et des correctifs trouvés en chemin, se clôt
par une revue de sécurité et la publication d'une **5.1.0** — comme la
5.0.0 (B-074) et la 4.0.0 (B-060).

## Ordre
**Dernier élément de la version** : quand B-078 à B-082 (et les fiches par
famille nées de B-078) sont closes, sur le code qui sera livré. Tout code
ajouté après demande de revoir au moins ce qui a changé.

## Périmètre
Tout le code venu depuis le tag `5.0.0` (`git diff 5.0.0..`), harnais
compris, avec la même grille que B-074 :
- **Revue de code** : règles communes (aucun champ vide émis, pas de code
  mort, un seul nom par concept, résultats d'appels lus) ; le bloc `Context`
  écrit par une seule fonction, de la même forme dans tous les collecteurs.
- **Entrées hostiles** : chaque lecteur nouveau ou changé (bases SQLite
  d'inventaire d'Amcache, chaînes des événements, propriétés de l'index) :
  lectures bornées par la taille réelle ; **aucune chaîne invalide écrite
  dans un JSON** (B-082), contrôlé sur tous les JSON du cycle.
- **Secrets prélevés** : ce que le contexte ajoute (comptes, profils,
  chemins) et ce qui en sort dans le JSON, les journaux, la console.
- **Exécution sur la machine examinée** : rien d'écrit, innocuité mesurée.
- **Dépendances** : versions embarquées confrontées aux failles publiées.
- **Dépôt** : secrets dans l'historique depuis `5.0.0`.

## Publication
- Version `5.1.0` dans `WAC.rc` seul ; `bin/` = la dernière compilation.
- Manuels FR et EN à jour, `doc/build-docs.sh` sans `Overfull`.
- Tag `5.1.0` et release GitHub **sur demande explicite** de l'utilisateur
  (pas de push sans elle) ; l'article de release relu en entier avant.

## Référence indépendante
Comme B-074 : recherche de secrets sur l'historique, cppcheck,
`hostile_input_test` étendu aux lecteurs nouveaux, dépendances confrontées
aux bases de failles ; cycle VM complet vert sur la version publiée.

## Sortie attendue
Un rapport daté dans cette fiche : ce qui a été examiné et comment, chaque
constat avec sa gravité, son correctif et son commit, ou la raison de ne
pas corriger ; ce qui n'a pas été examiné.

## Journal
- 2026-11-14 : fiche créée à la demande de l'utilisateur.

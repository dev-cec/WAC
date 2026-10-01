# B-016 — Web côté client : navigateurs et téléchargements

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | fort |

## Pourquoi
Ce que l'utilisateur a fait sur le web : historique de navigation, recherches, fichiers téléchargés (le fichier et sa provenance), identifiants et cookies enregistrés. Le côté serveur (journaux, code du site, base de données) est un artefact distinct : B-035.

## Source
Profils Chrome, Edge et Firefox (SQLite) ; cache WebCache d'Internet Explorer et d'Edge Legacy (ESE) ; dossiers de téléchargement ; flux Zone.Identifier.

## Sortie attendue
Un artefact à sa propre clé de `wac.yml` (`web_client`) : `web_client.json` (historique, téléchargements, recherches, par navigateur et par profil), pièces des téléchargements.

## Référence indépendante
Navigation et téléchargement de test dans la VM ; comparaison aux outils de référence (SQLECmd, Hindsight).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Dépend du lecteur SQLite (B-010).
- Clé `web_client` dans `wac.yml`, indépendante de `web_server` (B-035).

## Tâches
- [ ] Lecteur SQLite
- [ ] Historiques et recherches
- [ ] Téléchargements + Zone.Identifier (B-004)
- [ ] WebCache (ESE)
- [ ] TypedURLs et TypedURLsTime (NTUSER), venus de B-031

## Journal
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.
- 2026-10-01 : décision utilisateur — le web est séparé en deux artefacts, chacun avec sa clé dans `wac.yml` : client (cette fiche) et serveur (B-035).

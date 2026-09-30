# B-016 — Navigateurs, téléchargements, code des sites

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | fort |

## Pourquoi
Historique de navigation, fichiers téléchargés (le fichier et sa provenance), webshells (code des sites copié en entier).

## Source
Profils Chrome/Edge/Firefox (SQLite), dossiers de téléchargement, racines IIS/Apache/nginx trouvées dans leur configuration.

## Sortie attendue
`browsers.json`, pièces des téléchargements, code des sites en pièces de la consigne.

## Référence indépendante
Navigation et téléchargement de test ; site IIS de test avec une page témoin.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Dépend du lecteur SQLite (B-010).

## Tâches
- [ ] Lecteur SQLite
- [ ] Historiques
- [ ] Téléchargements + Zone.Identifier (B-004)
- [ ] Sites web

## Journal
- 2026-09-26 : décision utilisateur, copier le code du site complet plutôt que trier.
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.

# B-016 — Navigateurs, téléchargements, code des sites

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | fort |

## Pourquoi
Historique de navigation, fichiers téléchargés (le fichier et sa provenance), webshells (code des sites copié en entier), et la base de données de l'application web : ses comptes utilisateurs et leurs mots de passe (normalement sous forme de condensats) disent qui pouvait s'y connecter, et un compte ajouté ou un mot de passe faible explique une connexion d'apparence légitime.

## Source
Profils Chrome/Edge/Firefox (SQLite), dossiers de téléchargement, racines IIS/Apache/nginx trouvées dans leur configuration ; bases de données des sites, repérées par la configuration de l'application (chaînes de connexion de web.config, wp-config.php, .env…) : fichiers SQLite et Access copiés, dossiers de données MySQL/MariaDB et PostgreSQL copiés si le moteur est sur la machine.

## Sortie attendue
`browsers.json`, pièces des téléchargements, code des sites en pièces de la consigne, bases de données des sites en pièces ; pour une base SQLite lisible, la table des comptes en JSON (identifiant, condensat et son algorithme, dates) — jamais un mot de passe en clair dans le JSON.

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
- [ ] Bases de données des sites : repérage par la configuration, copie, seuil de taille à étudier (une base de plusieurs Go se copie à part, sur décision de l'opérateur, `wac.yml`)
- [ ] Comptes de l'application : condensats et algorithme ; repérage des mots de passe vides ou faibles comme pour la SAM (B-034)

## Journal
- 2026-09-26 : décision utilisateur, copier le code du site complet plutôt que trier.
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.
- 2026-10-01 : décision utilisateur — prélever la base de données du serveur web si elle est présente (taille à étudier) ; ce qui intéresse, ce sont les comptes et leurs mots de passe, normalement chiffrés.

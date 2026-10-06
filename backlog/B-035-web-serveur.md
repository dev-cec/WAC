# B-035 — Web côté serveur : journaux, code des sites, bases de données

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | fort |

## Pourquoi
Sur un serveur web, la compromission passe par le site : un webshell déposé, une requête qui l'appelle, un compte ajouté à l'application. Les journaux disent qui a appelé quoi, le code montre ce qui a été déposé, la base de données dit qui pouvait se connecter (un compte ajouté, un mot de passe faible font passer une connexion pour légitime).

## Source
Serveurs IIS, Apache et nginx trouvés sur la machine, et leur configuration : racines des sites, emplacement des journaux, chaînes de connexion de l'application (web.config, wp-config.php, .env…).

## Prérequis
- B-039 : artefacts organisés par version de Windows et par disponibilité.
- B-038 : compatibilité avec les versions serveur de Windows, depuis Server 2003.

## Sortie attendue
Un artefact à sa propre clé de `wac.yml` (`web_server`), indépendante de `web_client` (B-016) :
- journaux d'accès et d'erreurs copiés, et convertis en JSON (requête, client, statut, date en UTC et en heure locale) ;
- code des sites copié en entier (décision du 2026-09-26) ;
- bases de données des sites copiées : fichiers SQLite et Access, dossiers de données MySQL/MariaDB et PostgreSQL si le moteur est sur la machine ; seuil de taille à étudier, une très grosse base se prenant sur décision de l'opérateur (`wac.yml`) ;
- pour une base lisible, la table des comptes de l'application en JSON (identifiant, condensat et son algorithme, dates) ; le repérage des mots de passe vides ou faibles revient à WAE.

## Référence indépendante
Site IIS de test dans la VM : une page témoin, une requête témoin dans le journal, une base SQLite témoin avec un compte.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Clé `web_server` dans `wac.yml`.
- Témoins retrouvés : page, requête, compte.

## Tâches
- [ ] Repérage des serveurs et de leur configuration
- [ ] Journaux (copie, conversion)
- [ ] Code des sites
- [ ] Bases de données (repérage, copie, seuil de taille)
- [ ] Comptes de l'application

## Journal
- 2026-09-26 : décision utilisateur, copier le code du site complet plutôt que trier.
- 2026-10-01 : décision utilisateur — prélever la base de données du site si elle est présente (taille à étudier) ; le web est séparé en deux artefacts, chacun avec sa clé dans `wac.yml` : client (B-016) et serveur (cette fiche).
- 2026-10-02 : décision utilisateur — passée en P3 : peu de serveurs web sous Windows ; tout ce qui touche au client d'abord.
- 2026-10-06 : prérequis ajoutés à la demande de l'utilisateur : B-039 (artefacts par version de Windows), puis B-038 (versions serveur, de 2003 à 2026).

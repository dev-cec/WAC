# B-035 — Web côté serveur : journaux, code des sites, bases de données

| Statut | Priorité | Effort |
|---|---|---|
| en cours (lot 1 IIS fait : d896111c ; lot 2 écrit et testé, cycle Server 2022 à passer ; lot 3 à faire) | P3 | fort |

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

## Plan par lots (2026-10-31)
- **Lot 1 — IIS**, le seul serveur que le harnais peut témoigner (rôle Web-Server des VM serveur) :
  - configuration : `inetsrv\config\applicationHost.config` (IIS 7 et suivants) lue en JSON — sites (liaisons, applications, répertoires virtuels, chemin physique), pools d'applications (identité), modules globaux (un module natif ajouté est une porte dérobée d'IIS, ATT&CK T1505.004), réglages des journaux ; `MetaBase.xml` d'IIS 5.1 et 6 (XP, 2003) prélevé brut, non converti (aucune machine pour le mesurer) ;
  - journaux W3C de chaque site (`W3SVC<id>`) et de HTTP.sys (`HTTPERR`), copiés et convertis : un lecteur W3C commun avec le journal du pare-feu (pas de copie du code), dates UTC comme IIS les écrit ;
  - code de chaque site : l'arbre de son chemin physique, copié en entier.
- **Lot 2** — `web.config` (chaînes de connexion), bases des sites (SQLite, Access) et seuil de taille dans `wac.yml`, table des comptes de l'application.
- **Lot 3** — Apache et nginx (configuration, journaux, racines), puis dossiers de données MySQL/MariaDB et PostgreSQL.

## Tâches
- [x] Lot 1 : repérage d'IIS et de sa configuration
- [x] Lot 1 : journaux W3C (copie, conversion), lecteur commun avec firewall_log
- [x] Lot 1 : code des sites
- [x] Lot 1 : témoins IIS dans le harnais (rôle, page, requête, module, pool), cycle serveur vert
- [ ] Lot 2 : bases de données (repérage, copie, seuil de taille), chaînes de connexion
- [ ] Lot 2 : comptes de l'application
- [ ] Lot 3 : Apache, nginx, moteurs de bases de données

## Journal
- 2026-09-26 : décision utilisateur, copier le code du site complet plutôt que trier.
- 2026-10-01 : décision utilisateur — prélever la base de données du site si elle est présente (taille à étudier) ; le web est séparé en deux artefacts, chacun avec sa clé dans `wac.yml` : client (B-016) et serveur (cette fiche).
- 2026-10-02 : décision utilisateur — passée en P3 : peu de serveurs web sous Windows ; tout ce qui touche au client d'abord.
- 2026-10-06 : prérequis ajoutés à la demande de l'utilisateur : B-039 (artefacts par version de Windows), puis B-038 (versions serveur, de 2003 à 2026).
- 2026-10-07 : décision utilisateur — version 3.0, avec la rétrocompatibilité.
- 2026-10-17 : décision utilisateur — version 4.0, avec les serveurs.
- 2026-10-31 : B-038 terminée pour les générations (rôles restants ici) ; reprise de la fiche, plan en trois lots, lot 1 (IIS) commencé.
- 2026-10-31 : lot 1 écrit, non commité : lecteur W3C commun (`w3c_log`, le journal du pare-feu y passe, sortie inchangée) ; `web_server` lit `applicationHost.config` (sites, liaisons, applications, répertoires virtuels et chemin résolu, pools et identité, modules globaux, réglages des journaux), convertit les journaux W3C d'IIS et de HTTPERR en UTC, une ligne à la fois (JsonArrayWriter) ; la collecte prend la configuration d'abord (dossier `inetsrv\config`), puis les arbres des sites (en entier, la racine d'un volume exclue), des journaux et de l'historique de la configuration, et `MetaBase.xml` d'IIS 5.1/6 brut. Tests : file_artefacts_test 299 (configuration réaliste, journaux IIS et HTTPERR ; deux mutants pris : dates lues en local, racine de volume prise), artefact_catalogue_test 910. Harnais : témoins IIS sur les serveurs (rôle, page, requête au jeton, module témoin jamais chargé, références appcmd) et check_web_server. Cycle Server 2022 à passer après celui de Server 2003.
- 2026-10-31 : documentation du lot 1 écrite (non commitée, avec le code après le cycle) : manuels FR/EN (clé `web_server` de wac.yml, quatre fichiers JSON, ce que la collecte prend), tableau des artefacts régénéré depuis le catalogue (traductions IIS ajoutées ; il rattrape aussi la note des listes de sauts personnalisées, restée en retard), couverture ATT&CK (`web_server` dans « Application Log Content » seulement : le rattacher à « Module Load » ou aux flux réseau marquerait couvertes des techniques sans rapport avec IIS ; 475/479 inchangé), document des tests (témoin IIS). 0 Overfull. Cycle Server 2022 après celui de Server 2003.
- 2026-10-31 : **premier cycle Server 2022 avec IIS : 492 ✅, 4 ❌** (doublés au journal). Pools (identité), 14 modules globaux avec le témoin, requête témoin au journal confirmés par appcmd. (1) **Contenu du site jamais pris (défaut WAC)** : à la collecte, `readIisConfiguration` lisait la copie de travail, pas encore faite — la configuration venait d'être extraite dans la consigne, qu'on ne relit pas ; seuls les dossiers par défaut (journaux, historique) étaient pris → la copie de travail est faite juste après l'extraction de la configuration (`storeToWorking`, l'appel et sa trace d'audit mis en commun avec les deux existants ; un fichier déjà copié n'est jamais relu). (2) Chemin du site : appcmd le donne développé, le harnais compare `PhysicalPathResolved`. (3) IIS_IUSRS sans membre chez WAC, IUSR (S-1-5-17) chez Windows : la valeur `C` de l'alias 0x238 a une liste de membres vide (lue dans la VM) — Windows ajoute IUSR implicitement ; WAC lit juste, le harnais l'écarte. (4) Droits d'IIS_IUSRS « en trop » : `secedit` relevé (section 31) avant l'installation du rôle (25b) → le rôle est installé en tête du script (0b), avant toute référence. Second cycle en cours.
- 2026-11-01 : **second cycle Server 2022 avec IIS : 502 ✅, 0 ❌** (page témoin prise avec son SHA-256, site, pool, 14 modules, requête témoin confrontés à appcmd). Commités : b3b2b75c (refactor : lecteur W3C commun), d896111c (feat : IIS, avec `bin/wac.yml` ; le `bin/` des exécutables suit dans bd44e12b, même compilation), d0df0772 (test : témoins IIS). Lot 1 fait ; restent le lot 2 (web.config et chaînes de connexion, bases, comptes de l'application) et le lot 3 (Apache, nginx, moteurs de bases).
- 2026-11-01 : **lot 2 écrit, non commité.** `web.config` de chaque site (copie de travail) : chaînes de connexion telles qu'écrites, fichier de base résolu (Data Source, AttachDbFilename, Dbq, Filename ; `|DataDirectory|` = App_Data du site ; aucun pour un serveur, un partage, un chemin relatif), section chiffrée dite par son fournisseur, non décodée → `web_server_connection_strings.json`. Collecte : sites extraits dans le bloc IIS, copie de travail, puis bases désignées hors des sites prises avec -wal et -journal, taille lue dans l'index du dossier, au-delà de `max_database_mib` (wac.yml, 1024 par défaut ; `web_server:` devient une section) dite et non copiée (le site reste copié entier, décision du 2026-09-26). Comptes : dans chaque base SQLite des sites et désignée, les tables au nom de comptes (users, wp_users, AspNetUsers, members…) ayant une colonne de mot de passe, chaque ligne, le condensat et le schéma reconnu par sa forme (bcrypt, phpass, argon2, PBKDF2 Django et ASP.NET Identity v3, crypt ; un condensat hexadécimal nu dit par sa taille) → `web_server_accounts.json`. Lecture d'une table nommée par la base : seul nom admis lettres, chiffres, `_` (SqliteDatabase::queryTable), jamais échappé. Corps de la boucle des arbres extrait (extractTree), bloc IIS en fonction (extractIis). Tests : file_artefacts_test 310, config_test 71 ; mutants pris : nom de table non filtré, dossier voisin au nom proche pris pour le site. Harnais : deux bases SQLite faites sur l'hôte (lib/make-web-databases.py, comptes connus), une dans App_Data, une dans C:\wacdata, un web.config témoin (trois chaînes) ; check_web_server confronte chaînes, base externe au manifeste, comptes.
- 2026-11-01 : **premier cycle Server 2022 du lot 2 : 502 ✅, 2 ❌.** Chaînes de connexion (trois, `|DataDirectory|` résolu, aucun fichier pour le serveur), base hors du site prise (manifeste), trois comptes et leurs schémas (phpass, bcrypt, ASP.NET Identity v3) trouvés. (1) Le contrôle plantait : une chaîne contient `|` (`|DataDirectory|`), la référence est coupée au premier seulement. (2) Clés `user_login`, `user_registered` hors convention : les noms de colonnes, venus de la base, étaient des clés de `Fields` → `Fields` devient une liste `{Column, Value}` (un nom venu de la base n'est jamais une clé). Second cycle en cours.
- 2026-11-01 : incident hors WAC — le dossier `doc/` entier (2 387 fichiers suivis et les articles 3.0 non suivis) a été trouvé déplacé dans `build-windows/doc` (ignoré par git), vers 09 h 27 ; aucune commande de la session identifiée comme en cause. Chaque fichier suivi vérifié identique à HEAD (empreintes git), le dossier remis à la racine, articles 3.0 compris, intacts.

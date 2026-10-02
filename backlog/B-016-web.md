# B-016 — Web côté client : navigateurs et téléchargements

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

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
- [x] Lecteur SQLite (9d4dc54) — copie privée, journal rejoué
- [x] Historiques et recherches — Chromium (Edge, Chrome, Brave, Vivaldi, Chromium, Opera)
- [x] Historiques et recherches — Firefox (places.sqlite, formhistory.sqlite)
- [x] Téléchargements Chromium (chaîne de redirections, référent, état, SHA-256)
- [x] Lien téléchargement ↔ Zone.Identifier (B-004) et fichier sur le disque (mft.json) — confié à WAE (décision utilisateur du 2026-10-02)
- [ ] index.dat d'IE ≤ 9 (Windows 7) : historique, cache, cookies
- [x] Login Data / logins.json (identifiants enregistrés : origine, compte, dates — jamais le mot de passe), cookies (jamais la valeur)
- [x] WebCache (ESE) — CacheEntry par conteneur
- [x] TypedURLs et TypedURLsTime (NTUSER), venus de B-031

## Journal
- 2026-09-30 : décision utilisateur — SQLite par l'amalgamation officielle (sqlite3.c) épinglée et compilée dans WAC, ouverte en lecture seule sur la copie de la consigne.
- 2026-10-01 : décision utilisateur — le web est séparé en deux artefacts, chacun avec sa clé dans `wac.yml` : client (cette fiche) et serveur (B-035).
- 2026-10-01 : SQLite 3.53.4 intégré (amalgamation, SHA3-256 vérifiée, 9d4dc54) ; une base est lue sur une copie privée de la copie de travail avec son -wal ou -journal, que SQLite rejoue — jamais sur la pièce.
- 2026-10-01 : `toHexadecimal` sorti de sha.h vers `conversions.h` (1b2adee, B-030) avant d'en avoir besoin ici.
- 2026-10-01 : Chromium — collecte brute par RawReader (un volume ouvert une fois) de chaque profil de navigateur trouvé par listage (History, Login Data, Web Data, Cookies, Shortcuts, Top Sites, Bookmarks, Preferences, avec journaux ; Local State) sans les caches ; `web_client.json` : Url, Visit (transition nommée d'après ui::PageTransition), Download (chaîne, référent, onglet, état, SHA-256 ; DangerType et InterruptReason bruts — la numérotation de la base n'est pas l'énumération du code), SearchTerm. Référence : la base History d'Edge de la VM, rapatriée par le harnais et relue par le SQLite de Python : 5 URL, 7 visites identiques (URL, instant, transition). La VM n'a ni téléchargement ni recherche : couverts par le test unitaire (vu échouer : chaîne lue sans tri).
- 2026-10-01 : Chromium commité (6174f52). Défaut de procédure : le WAC.exe de ce commit venait de la compilation mutante (chaîne non triée), sources restaurées sans recompilation ; recompilé et commité (93a32f5). raw_hive_test.exe rendu reproductible au passage (103adef).
- 2026-10-01 : Firefox — chaque dossier de `Profiles` : places.sqlite (Url, Visit avec type de visite, Download depuis les annotations destinationFileURI et metaData — fin en millisecondes, état brut —, TypedInput), formhistory.sqlite (FormEntry : formulaires et barre de recherche) ; copiés bruts : cookies, permissions, logins.json, key4.db, extensions, prefs.js, sessionstore.jsonlz4. Pas de Firefox dans la VM : vérifié par le test unitaire seul (vu échouer : fin lue sans la conversion des millisecondes).
- 2026-10-01 : Firefox commité (d28d3a2).
- 2026-10-01 : TypedURLs — `TypedUrl` dans web_client.json (Url, MruPosition, instant de TypedURLsTime, date de la clé), pour chaque NTUSER.DAT ; pas de `Browser` (IE et l'Explorateur y écrivent). L'analyse des noms `url<N>` est partagée avec TypedPaths (`urlValueNumber`, registry_common). Référence : deux TypedURLs posées dans la ruche de « wac » avec des instants connus, retrouvées ; typed_paths.json inchangé (témoin url25 à sa position).
- 2026-10-01 : TypedURLs commité (68c24af).
- 2026-10-01 : WebCache — dossier `WebCache` copié brut (base, journaux, point de contrôle) ; `CacheEntry` pour chaque entrée de chaque `Container_<n>` (History, MSHist, Content, iedownload, BackgroundTransferApi) : URL (User et Page pour l'historique), compteur, dates. Relevé AVANT d'écrire le décodeur, sur la base de la VM : la date de modification des conteneurs MSHist est en heure locale (7 200 s d'écart avec la même entrée de History) ; convertie par `suspectLocalToUtc`. Référence : dissect.esedb (Fox-IT) sur la même base, dans le harnais si installé — 28 entrées, URL et dates identiques, les 5 heures locales converties par zoneinfo ; 4 nœuds vides sans en-tête (que dissect ne sait pas lire non plus) écartés. Vu échouer : sans la conversion, 2 h d'écart.
- 2026-10-01 : WebCache commité (1995603).
- 2026-10-02 : SavedLogin (Chromium Login Data, Firefox logins.json) et Cookie (Chromium Network\Cookies ou Cookies, Firefox cookies.sqlite) — métadonnées seulement : mots de passe et valeurs de cookies jamais sélectionnés (test : aucun secret dans le JSON). Référence : Login Data (0 ligne) et Network\Cookies (10 lignes) d'Edge rapatriés et relus par Python, mêmes sites. Vu échouer : expiration Firefox lue sans la conversion des secondes.
- 2026-10-02 : identifiants et cookies commités (ad88b4c) ; navigation réelle Chrome, Firefox et mshta dans la VM (24f54e2) ; cache de WinINet collecté, CachedFile (d7d2a5f).
- 2026-10-02 : décision utilisateur — la mise en corrélation des preuves (téléchargement ↔ Zone.Identifier ↔ fichier sur le disque) est faite dans WAE ; WAC collecte et convertit. Demande utilisateur : Internet Explorer reste présent et utilisé (mshta, HTA) — WebCache et INetCache faits, index.dat d'IE ≤ 9 à faire.

# B-083 — Revue de code et de sécurité, puis publication de la 5.1.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

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
- 2026-11-15 : **ouverture de la revue**, toutes les autres fiches de la
  version closes (`daa54f38`). Outils, hors du dépôt : cppcheck 2.19
  (paquet Debian extrait, sans droits d'administrateur) et detect-secrets
  1.5 (environnement virtuel).
- 2026-11-15 : **secrets** : detect-secrets sur les 6 666 lignes ajoutées
  depuis `5.0.0`, 0 constat ; motifs (mot de passe en clair, clés privées,
  AWS, GitHub, Slack, clés d'API), 0 ; aucun fichier ajouté de type `.env`,
  `.pem`, `.key`, `.pfx`.
- 2026-11-15 : **dépendances** : inchangées depuis `5.0.0` (SQLite 3.54.1,
  libyaml 0.2.5). Rien de nouveau depuis la revue du 12 novembre :
  CVE-2026-119586 ne touche que le shell de SQLite (`.recover`), que WAC ne
  compile pas ; les CVE trouvées pour libyaml visent sa liaison Perl
  (CVE-2026-63676) ou son émetteur, que WAC n'utilise pas.
- 2026-11-15 : **cppcheck** sur les 76 sources changées : 3 erreurs, 4
  avertissements, le reste du style ; tous dans du code d'avant `5.0.0`.
  Corrigés à la demande de l'utilisateur, faux positifs compris, pour que
  l'outil ne dise plus rien :
  - `reg_shimcache.cpp` (deux `dangerousTypeCast`) : le chemin d'une entrée
    lu par un transtypage en `wchar_t*` d'octets sans alignement, et les
    champs voisins de même ; lus désormais en petit-boutiste
    (`utf16Text`, `readLittleEndian`) ;
  - `web_server.cpp` (deux `danglingTempReference`) : boucles sur un membre
    d'un temporaire — la durée de vie était prolongée, faux positif —,
    temporaires nommés ;
  - `tools.cpp` (`memleak`) : le SID des administrateurs, libéré par
    `FreeSid` sur tout chemin — faux positif —, n'est plus alloué :
    `CreateWellKnownSid` dans un tampon de la pile (Windows XP et après) ;
  - `idList.cpp` (`identicalConditionAfterEarlyExit`) : `VT_ILLEGALMASKED`
    et `VT_BSTR_BLOB` valent tous deux `0xfff` ; la seconde branche, morte,
    retirée ;
  - `application_trace_files.cpp` (`%lc` d'un `wchar_t`, faux positif) :
    décalage écrit sans `swprintf`.
  cppcheck relancé sur ces fichiers : plus rien.
- 2026-11-15 : **chaînes invalides (B-082)** : `check_no_lone_surrogates`
  dans `check-json.py`, sur tous les JSON du cycle, les noms que le système
  de fichiers garde tels quels exceptés (MFT, USN, fichiers supprimés, UAL) ;
  vu échouer sur un JSON forgé (le canal d'événement de B-082), vert sur la
  collecte du dernier cycle (120 JSON).
- 2026-11-15 : **entrées hostiles** : `hostile_input_test` étendu aux formes
  du `Context` (`contextFormsOnHostileText`, 20 000 textes à graine fixe :
  noms d'appareils, de volumes, lignes de commande, URL, partages, chemins à
  variables) ; vu échouer par mutation (majuscules retirées de
  `contextDevice`), 460 000 entrées vertes. Le lecteur des bases d'inventaire
  d'Amcache relu : nom de table refusé s'il n'est pas lettres, chiffres et
  `_` (`queryTable`), base lue sur une copie.
- 2026-11-15 : **exécution sur la machine examinée** : depuis `5.0.0`, trois
  appels de lecture ajoutés à la collecte — `OpenProcess` en
  `PROCESS_QUERY_LIMITED_INFORMATION` et `QueryFullProcessImageNameW` (le
  chemin de l'image de chaque processus, B-085), `QueryDosDeviceW` (le nom
  de périphérique des volumes, B-079). **Faible, corrigé** : le dossier
  d'innocuité ne les citait pas ; il les cite, et la table d'imports
  (`CreateWellKnownSid` au lieu d'`AllocateAndInitializeSid`/`FreeSid`).
- 2026-11-15 : **secrets prélevés** : le `Context` ne fait que redire ce que
  l'enregistrement porte (ligne de commande, URL, nom de compte) ; il
  n'ajoute aucune valeur nouvelle, et un secret LSA n'y est que nommé
  (contrôlé par `check-json.py`). Rien de nouveau n'est écrit dans les
  journaux ni sur la console.
- 2026-11-15 : **revue du code** ajouté depuis `5.0.0`. Aucune déclaration
  sans appelant parmi les fonctions de `context.h` ; résultats d'appels lus
  (`getRegSzValue`, `QueryDosDeviceW`, `Json::parse`, `snapshotInteger`,
  `wcstoul`). **Copier-coller, corrigé** : la coupe des blancs recopiée trois
  fois et sept boucles de casse dans `context.cpp`, et une seconde
  `toUpper` dans `dns_server.cpp` ; une seule de chaque désormais
  (`withoutSurroundingSpace`, `toUpper` et `toLower` de `tools`).
- 2026-11-15 : VM `srv2025-test` recréée (`create-vm.sh srv2025`) pour le
  cycle serveur, comme pour la 5.0.0 : contrôleur de sa forêt `wac.test`,
  rôles, serveurs web.

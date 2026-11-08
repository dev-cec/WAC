# B-060 — Revue de sécurité complète avant la clôture du projet

| Statut | Priorité | Effort |
|---|---|---|
| fait (36f274fe, e75ef5f0, c2128d18) | P1 | fort |

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
- [x] Vérifier que toutes les autres fiches sont closes (B-038 close le 2026-11-08 ; les fiches de la 5.0.0 hors périmètre)
- [x] Choisir les outils et fixer la méthode
- [x] Revue et contrôles, par point du périmètre
- [x] Correctifs et leurs tests
- [x] Cycle VM complet après les correctifs
- [x] Rapport, documentation FR et EN si une opération change

## Rapport (2026-11-08)
Porte sur le code de la 4.0.0 : la revue du 2026-11-04, puis une revue complémentaire de chaque commit de code venu après elle.

**Méthode.** Recherche de secrets sur tout l'historique git (motifs et detect-secrets), cppcheck 2.22, confrontation des dépendances embarquées à OSV et NVD, relecture du code ajouté depuis la 3.0.1 (web, annuaire, stratégies, W3C, SQLite, rôles), harnais `hostile_input_test` : mutations à graine fixe de chaque lecteur de texte et de binaire ajouté par la version (Apache, nginx, IIS, W3C, journaux, scripts et tâches des stratégies, `Registry.pol`, métadonnées de réplication, zones et journal DNS, journal DHCP, `.vmcx`, nœuds d'index NTFS), chaque entrée binaire contre une page de garde.

**Constats et correctifs** (chacun reproduit avant correction, test vu échouer) :

| # | Gravité | Constat | Correctif |
|---|---|---|---|
| 1 | élevée | nom forgé d'un index NTFS (`..\\..\\WAC.exe`) écrit hors de la consigne, sur le support de collecte | 36f274fe |
| 2 | élevée | `..` d'une configuration web lu hors de la collecte à la conversion | 36f274fe (`pathUnder`) |
| 3 | moyenne | chaîne de `Define` d'Apache : 26 Gio occupés, processus tué | 36f274fe |
| 4 | moyenne | SQLite 3.53.4 touché par des CVE atteignables par une base forgée ; vues et déclencheurs exécutés | e75ef5f0 (3.54.1, ni vues ni déclencheurs) |
| 5 | faible | chiffre non ASCII dans `scripts.ini`, résultat d'une requête ignoré, branche morte, zéro émis pour une valeur trop courte de l'annuaire | 36f274fe |
| 6 | moyenne | exception non rattrapée (`std::bad_alloc` sur un fichier géant) : collecte terminée sans sceau ni journal | 36f274fe (`runPhase`) |
| 7 | faible | champ `#Fields:` nommé `File`, `Line`, `Time` ou en double : deux clés dans un objet | 36f274fe (`OtherFields`) |
| 8 | faible | échec de la suppression de la copie de travail rendu par un « accès refusé » fixe : cause et entrée perdues | c2128d18 (`long_path_test`) |

Cycle du contrôleur sur les correctifs : 572 contrôles, 0 échec (2026-11-04). Série finale de la 4.0.0 sur la clé de collecte : tous les serveurs et Windows 11 verts (journal de B-038).

**Revue complémentaire** des commits de code postérieurs au 2026-11-04 : rôles DNS, DHCP, Hyper-V (8ee3dba0, couverts par les mutations) ; rejeu ESE sous chaque base de journaux (6ec6b47a) ; nom d'un attribut d'extension (1e4b7f30) ; journal des accès utilisateurs (1a05c822, d874b852 : chaque `front()` après un contrôle de vide, GUID et FILETIME lus à leur taille, année et jour bornés) ; demi-paire de substitution dans le JSON (6936405d, lecture de l'unité suivante bornée) et dans les scripts de vérification (87dfaa43 : le contrôle de sortie de la collecte porte sur le chemin restauré, sous Linux sur le chemin résolu) ; c2128d18 (le chemin bloqué écrit à la console ne peut porter de caractère de contrôle : la copie de travail est créée par l'API Win32, qui les refuse). Un constat **faible, accepté** : le rejeu ESE essaie chaque `.chk` du dossier copié ; des points de contrôle multipliés par un administrateur de la machine examinée multiplient les rejeux, ce qui ralentit la conversion sans rien lire ni écrire ailleurs.

**Non examiné ou accepté.** Une exception dans un fil d'exécution auxiliaire reste fatale (constat 6). Tests à fixtures (PST, `index.dat`, MFT) non relancés sous Wine après les correctifs : couverts par les cycles VM sur données réelles. Le code des traces d'applications (5.0.0, B-062 à B-073) n'est pas dans la 4.0.0 et devra être revu avant sa version. Aucun secret réel trouvé dans l'historique.

## Journal
- 2026-11-03 : créée à la demande de l'utilisateur, à faire en dernier, avant la clôture du projet.
- 2026-11-04 : lancée à la demande de l'utilisateur alors que B-038 reste ouverte (autres rôles à décider) : écart à l'ordre prévu, voulu par l'utilisateur. Tout code ajouté ensuite sera à revoir. Version encore en 3.0.1 ; la 4.0.0 sera posée après la revue.
- 2026-11-04 : outils : recherche sur tout l'historique git, detect-secrets, cppcheck 2.22, OSV et NVD, relecture du code ajouté depuis la 3.0.1 (web, annuaire, stratégies, W3C, SQLite), harnais `hostile_input_test` (mutations à graine fixe, pages de garde). Constats reproduits avant correction : (1) **élevé** nom forgé d'un index NTFS (`..\\..\\WAC.exe`) écrit hors de la consigne, sur le support de collecte ; (2) **élevé** `..` d'une configuration web lu hors de la collecte à la conversion (`pathUnder`) ; (3) **moyen** chaîne de `Define` d'Apache : 26 Gio occupés, processus tué par le noyau ; (4) **moyen** SQLite 3.53.4 touché par des CVE atteignables par une base forgée, et vues exécutées ; (5) **faible** chiffre non ASCII dans `scripts.ini`, résultat d'une requête ignoré, branche morte, zéro émis pour une valeur trop courte de l'annuaire. Corrigés, test vu échouer puis 16 contrôles verts, 32 000 entrées mutées. Écrit, compilé, cycle VM à passer.
- 2026-11-04 : cycle complet du contrôleur sur les correctifs : 572 contrôles, 0 échec, 44 sautés. Puis deux points restés ouverts corrigés plutôt qu'acceptés : (6) **moyen** une exception non rattrapée (`std::bad_alloc` sur un fichier géant) terminait la collecte sans sceau ni journal : `runPhase` borne l'exception à sa phase, la consigne dans le journal, le code de sortie le dit ; une exception dans un fil d'exécution auxiliaire reste fatale. (7) **faible** un champ de `#Fields:` nommé `File`, `Line`, `Time` ou deux fois le même écrivait deux clés dans un objet : il va dans `OtherFields`. Zéro des valeurs trop courtes de l'annuaire : test ajouté (`directoryNumberToJson`). Test hostile : 23 contrôles. Tests Wine rejoués, Timeline sur SQLite 3.54.1 : 118 contrôles verts ; PST, index.dat et MFT à fixtures non relancés sous Wine (couverts par les cycles VM pour les données réelles).
- 2026-11-05 : la revue porte sur le code de la 4.0.0 (`1a05c822` et ce qui s'y ajoutera). Les traces d'applications de la 5.0.0 n'y sont pas : leur code ajouté devra être revu avant cette version-là (secrets dans `tdata`, `sitemanager.xml`, `WinSCP.ini`, vidages de plantage).
- 2026-11-08 : revue complémentaire du code venu après le 2026-11-04 (rôles, rejeu ESE, journal des accès, demi-paires, suppression de la copie de travail) : un constat faible accepté (rejeux multipliés par des `.chk` forgés), le constat 8 corrigé (c2128d18, `long_path_test` vu échouer par mutation). Rapport écrit ; fiche close.

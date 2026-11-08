# B-076 — Traces d'applications : conversion générique en JSON

| Statut | Priorité | Effort |
|---|---|---|
| en cours (écrit, compilé, tests verts ; témoin et cycles à faire) | P1 | moyen |

## Pourquoi
Décision de l'utilisateur du 2026-11-08 : les traces d'applications (B-062 à B-072) ne restent pas en copie brute sans JSON. Question de l'utilisateur : « dans quel format sont-ils ? s'ils sont au format texte, on peut faire un JSON simple avec date et message au lieu de parser tous les champs ». Relevé sur la table : la majorité des 97 produits écrivent des **journaux texte, une ligne par événement** (antivirus, TeamViewer, AnyDesk, journaux de serveur, OpenSSH, VPN, VirtualBox, `SchedLgU.txt`, transcriptions PowerShell…) ; une partie du **texte structuré** (XML, JSON, INI, configuration) ; le reste des bases SQLite, des formats que WAC décode déjà, des LevelDB, des binaires ou chiffrés.

## Source
Les pièces des groupes de `application_traces.h` dans la consigne (copie de travail), rattachées à leur produit par leur chemin source : le dossier de la table (motifs `*`, `%profile%` = un profil sous `\Users` ou `\Documents and Settings`, ou le profil système), la profondeur et le filtre. La première ligne de la table qui prend le fichier l'emporte : l'ordre de la table décide, toujours le même.

## Sortie attendue
Un fichier par groupe, `<groupe>.json` (`remote_administration.json`, `antivirus.json`…), même structure que les autres artefacts. Chaque élément porte `Product` et `File` (chemin source), puis selon le contenu :
- **journal texte** (décodé par `decodeTextFile` : BOM, UTF-16, UTF-8, page de code) : un élément par enregistrement, `Line` (numéro de sa première ligne), `Text` ; les lignes sans date en tête qui suivent une ligne datée (pile d'appels, suite) lui sont rattachées. `TimeAsWritten` : la date reconnue en tête, telle qu'écrite. `TimeUtc` seulement si la date porte son décalage (`Z`, `+hh:mm`) : une date sans fuseau n'est pas un instant (règle de chronologie de WAE) ;
- **texte structuré** (`.xml`, `.json`, `.ini`, `.conf`, `.config`, `.toml`, `.cfg`, `known_hosts`, `sshd_config`…) : `Content`, sa structure en JSON ; une valeur dont le nom ressemble à un mot de passe (`*password*`, `*pwd*`, `*secret*`) n'est pas émise, `HasPassword` le dit ;
- **autre** (base, LevelDB, binaire, chiffré, image) : `Converted: false` et `Reason` ; le fichier reste dans la consigne, scellé, et le JSON dit qu'il existe.

Bornes contre une entrée hostile : une ligne au-delà de 64 Kio est coupée et le dit (`Truncated`) ; un fichier n'est lu que dans la limite de sa taille réelle.

## Référence indépendante
Test sous Wine : découpage en enregistrements et reconnaissance des dates sur des lignes réelles de chaque famille (ISO avec et sans décalage, `yyyy/MM/dd`, crochets), texte structuré masqué ; rattachement d'un chemin à son produit (profils, motifs, profondeur, filtre, premier qui l'emporte) ; entrées mutées dans `hostile_input_test`. Cycle VM : le témoin de B-062 écrit des lignes connues dans des journaux de produits, `check-json.py` les retrouve, ligne et date.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque pièce d'un groupe figure dans son JSON, convertie ou dite non convertie.
- Aucune valeur nommée comme un mot de passe émise.
- Une date sans décalage jamais présentée comme UTC.
- Tests vus échouer par mutation (date, rattachement, masquage).

## Tâches
- [x] Rattachement d'un chemin source à son produit (`application_traces`)
- [x] Découpage en enregistrements et dates (portable), texte structuré en JSON, masquage
- [x] Convertisseur par groupe, branché dans `--convert`, libellés FR et EN
- [x] Catalogue : forme « convertie » au lieu de « copie brute »
- [x] Tests unitaires et mutations, `hostile_input_test`
- [ ] Témoin et contrôle dans `check-json.py` (avec B-062)
- [ ] Documentation FR et EN (avec B-075)

## Journal
- 2026-11-08 : ouverte à la demande de l'utilisateur, en remplacement de la « copie brute sans JSON » prévue par B-062.
- 2026-11-08 : écrit. `traceOwnerOf` (application_traces) : la pièce rattachée par son chemin source, profils de `\Users`, `\Documents and Settings`, système et services ; le filtre de la collecte partagé (`nameMatchesFilter`, wildcard.h, au lieu d'`extensionMatches` statique de raw_hive.cpp). `application_trace_files.{h,cpp}` : date en tête (`yyyy-MM-dd`, `/`, `.`, fraction, `Z`/`±hh:mm`), enregistrements avec leurs suites, format par extension puis par contenu (octet nul, caractères de contrôle), XML/JSON/INI en structure, `isPasswordValue` étendu (`passwd`, `pwd`, `secret`, `pass` entier : `<Pass>` de FileZilla). Borne : 64 Kio par enregistrement, 256 Mio par fichier (au-delà : dit, non converti). `convertArtefactWith` : le modèle de conversion reçoit un collecteur construit par l'appelant. Catalogue : les 11 groupes `decoded`, sans toucher `defender_endpoint`, `onedrive` ni la sauvegarde des ruches, vraiment bruts. Tests : `application_traces_test` 1 444, `application_trace_files_test` 36 (nouveau, Wine), `hostile_input_test` 23 avec les 4 lecteurs mutés. Mutations vues échouer : décalage inversé (3), secrets JSON gardés (1), profondeur ignorée (1), `pass` retiré (1). Deux objets orphelins d'anciennes sources retirés de `build-windows/`.
- 2026-11-08 : cycles ciblés (`--only` sur les groupes) : **Windows 11 55 ✅, 0 ❌ ; Server 2025 59 ✅, 0 ❌**, à la collecte et à la collecte séparée. Témoins retrouvés : ligne TeamViewer datée sans UTC et sa suite, leurre non pris, ligne OpenSSH ramenée à 13:03:21.123Z, `WinSCP.ini` et `sitemanager.xml` en structure sans leur mot de passe, base pCloud listée, vidage de plantage ni collecté ni converti (manifeste). Données réelles : journaux d'installation de Windows, 23 140 enregistrements datés (Windows 11) et 19 905 (Server 2025) ; SleepStudy et notifications listés, non convertis. Limite vue : `NetSetup.log` (et `dcpromo.log`) écrivent `MM/dd/yyyy` — la règle générique ne lit pas une date mois ou jour en premier, ses 16 lignes restent sans date reconnue. Piste : un format de date déclaré par produit dans la table, pour les journaux de Windows dont le format est connu.
- 2026-11-08 : décision de l'utilisateur : **toutes les dates au même format**. Chaque enregistrement daté porte `Time` (heure locale de la machine examinée, avec son décalage) et `TimeUtc`, comme tous les artefacts de WAC ; une date sans fuseau est lue comme heure locale (`suspectLocalToUtc`, règles de la date), ou UTC pour un produit mesuré comme tel (`writesUtc`), `TimeZoneAssumed` le dit ; `TimeAsWritten` garde le texte. Exactement les chiffres de fraction écrits (`.5` reste `.5`), coupe au-delà de 100 ns dite (`TimePrecisionCut`). `NetSetup.log` et `dcpromo.log` lus mois en premier (`monthFirst`, déclaré par produit). Vérification des fuseaux supposés : fiche B-077 (contrôle « dernier enregistrement contre dernière écriture du fichier » ajouté à `check-json.py`, témoin TeamViewer daté de l'heure d'exécution, son UTC calculé par Windows). Tests : `application_trace_files_test` 45 ; mutations vues échouer (décalage additionné 3, sept chiffres toujours 4, mois en premier ignoré 2).

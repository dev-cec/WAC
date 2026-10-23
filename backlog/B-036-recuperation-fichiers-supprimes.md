# B-036 — Récupération des fichiers supprimés par lecture brute du disque

| Statut | Priorité | Effort |
|---|---|---|
| en cours : niveau 1 fait (c3b290b0), niveau 2 à faire (version 3.0) | P2 | fort |

## Pourquoi
mft.json liste déjà les fichiers supprimés dont l'enregistrement n'est pas encore réutilisé (`Deleted`), et usn_journal.json les suppressions, mais pas leur **contenu**. Or l'outil, le script ou l'archive qu'un intrus a effacés sont souvent encore sur le disque : le contenu reste dans des clusters libres tant que NTFS ne les a pas réattribués. Le récupérer **en lisant le volume en brut** (`\\.\X:`, comme $MFT et $UsnJrnl aujourd'hui) ne laisse aucune trace sur la machine examinée : aucun fichier ouvert par le système, aucun outil de récupération installé ou lancé dessus, aucune écriture sur le volume. Demande utilisateur du 2026-10-01.

## Source
Trois niveaux, à étudier dans cet ordre :
1. **Enregistrements supprimés de la $MFT** : un enregistrement `Deleted` garde son attribut `$DATA` — résident (contenu dans l'enregistrement même, ≤ ~700 octets) ou non résident (liste de plages de clusters). Les plages sont relues sur le volume, après vérification dans `$Bitmap` que les clusters sont toujours libres. Un cluster réattribué depuis appartient à un autre fichier : le contenu récupéré serait faux et valide en apparence.
2. **Entrées supprimées des index de répertoires** (slack des `$INDEX_ALLOCATION`) : noms et références d'enregistrements déjà réutilisés.
3. **Découpage de l'espace libre par signatures** (carving : PE `MZ`, ZIP/Office, PDF, scripts…) : des fichiers dont même l'enregistrement a disparu. Volumineux et peu sûr ; à décider séparément.
Les volumes FAT/exFAT (fat_volumes.json, entrées supprimées déjà relevées) suivent les mêmes niveaux : premier cluster et taille dans l'entrée, chaîne de la FAT effacée.

## Sortie attendue
À définir par l'étude. Piste : un artefact à sa clé de `wac.yml` (`deleted_files`), qui copie dans la consigne le contenu récupéré de chaque fichier supprimé retenu, avec son empreinte, la part récupérée (clusters libres / réattribués), et un JSON qui les relie à leur enregistrement de mft.json (Volume + Entry + Sequence). Un binaire récupéré passe par le même traitement que les autres (signature, chaîne, liste de confiance) ; un malveillant suit la règle de la quarantaine (copie chiffrée, jamais en clair sur le support).

## Référence indépendante
Dans la VM : des fichiers de contenu connu (texte, exécutable, archive, un fichier fragmenté, un fichier résident) créés puis supprimés, le cache du volume écrit ; leur SHA-256 relevé avant suppression doit être retrouvé. Puis un fichier supprimé dont les clusters sont réécrits ensuite : il doit être déclaré non récupérable, jamais rendu faux. Recoupement avec `ntfsundelete` (ntfs-3g) sur l'image du volume, et photorec pour le niveau 3.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Décision de principe avant tout développement : quels niveaux, quels fichiers (tous les supprimés, ou filtrés par type, taille, date), plafond de taille et de durée, sort des malveillants.
- Une clé `deleted_files` sous `artefacts:` de `wac.yml` (rappel utilisateur du 2026-10-21 : tout artefact a sa clé), au catalogue des artefacts par version et dans les manuels.
- Lecture seule du volume, rien d'écrit sur la machine examinée : contrôle d'innocuité vert, dossier d'innocuité mis à jour.
- Un contenu n'est jamais publié comme récupéré si un de ses clusters est réattribué : récupération partielle signalée comme telle.
- Lectures bornées : une liste de plages forgée (longueur, décalage hors volume, boucle) est refusée.
- Limites documentées : SSD et TRIM (clusters libérés remis à zéro par le disque), fichiers compressés ou chiffrés (EFS), BitLocker (volume lu déchiffré par le système, comme aujourd'hui).

## Étude (2026-10-22)
Mesures sur les collectes du harnais (mft.json) et sur les disques des VM, lus hors ligne et en lecture seule (dissect.ntfs), VM éteintes. Pour chaque enregistrement de base supprimé portant un `$DATA` sans nom : contenu résident, ou plages de clusters confrontées à `$Bitmap`, et premier cluster libre de chaque plage relu (tout à zéro ou non).

| Système | Fichiers supprimés relevés à la collecte | Taille annoncée |
|---|---|---|
| Windows 11 (26200) | 76 823 (dll 20 593, cat 11 273, js 9 285, evtx 3 737, exe 2 909, ps1 886…) | 30 Go |
| Windows 7 | 7 870 (dll 1 627, evtx 978, ps1 879, txt 822…) | 5,9 Go |

| Disque lu hors ligne | Résident | Clusters tous libres (dont relus à zéro) | En partie libres | Tous réattribués |
|---|---|---|---|---|
| Windows 7 | 297 | 148 — 121 Mo (14) | 30 — 3 Mo | 227 |
| Vista | 175 | 55 — 71 Mo (1) | 6 — 4 Mo | 24 |
| Windows 8 | 93 | 42 — 63 Mo (8) | 6 — 24 Mo | 4 |
| XP SP3 | 179 | 13 762 — 2,7 Go (0) | 195 — 81 Mo | 2 194 |

Constats :
- Le volume en jeu est grand (30 Go annoncés sous Windows 11), et fait surtout des mises à jour (dll, cat, js de WinSxS et de SoftwareDistribution) : tout prendre est exclu, un filtre et des plafonds sont nécessaires.
- Les enregistrements supprimés sont vite réutilisés sur un système actif : sous Windows 7, 7 870 supprimés à la collecte, 820 encore libres au disque éteint après la suite du cycle. La récupération ne vaut que pendant la collecte, et le relevé de mft.json est le seul témoin des autres.
- Le contenu résident (≤ ~700 octets : scripts courts, `.lnk`, `Zone.Identifier`) reste intact tant que l'enregistrement n'est pas réutilisé, TRIM ou non.
- Les disques des VM sont déclarés avec `discard='unmap'` : Windows y envoie TRIM comme à un SSD. Peu de premiers clusters relus à zéro sous 7, Vista, 8 ; mesure Windows 11 à faire (VM occupée par un cycle). Un cluster libre relu à zéro est déclaré effacé (TRIM), jamais publié comme contenu.
- Un premier cluster non nul ne prouve pas l'origine du contenu : seule la référence indépendante (fichiers de SHA-256 connu supprimés puis retrouvés) le prouve.

### Niveau 2 : la marge des index (mesure du 2026-10-22)
Blocs INDX des `$I30` de chaque répertoire, disques des VM éteintes : entrées `$FILE_NAME` plausibles (longueur de clé cohérente, nom imprimable, date de création dans une plage réaliste) au-delà de la taille utilisée de chaque nœud, comparées aux entrées vivantes de tous les index.

| Disque | Entrées dans la marge | Noms distincts (sans 8.3) | Absents de tout index vivant |
|---|---|---|---|
| Windows 8 | 52 789 | 27 241 | 41 (log, tmp, une exe, un sys) |
| Vista | 59 850 | 25 250 | 88 |
| XP SP3 | 12 439 | 8 668 | 1 315 (dll, tmp, exe des mises à jour) |

Presque toute la marge répète des entrées vivantes, déplacées par les réorganisations de l'arbre : le niveau 2 ne doit publier que les noms absents de tout index vivant. Chaque entrée porte la référence de son enregistrement, ses quatre dates `$FILE_NAME`, sa taille et son parent : le nom d'un outil effacé dont l'enregistrement est réutilisé, et quand il a été créé. Aucun contenu.

## Décision (2026-10-22)
- Niveaux 1, 2 et 3 retenus, dans cet ordre.
- On ne récupère pas les fichiers connus : on cherche les documents de l'utilisateur et les exécutables étrangers à Windows. Deux filtres : par le chemin avant toute lecture (WinSxS, SoftwareDistribution, servicing, cache Installer : rien n'y est relu), puis par le contenu — la règle de prélèvement des binaires de WAC : un exécutable récupéré authentifié (Microsoft, éditeur de confiance, liste `--update-trust`) est relevé avec empreinte et signataire, pas copié ; un non authentifié est copié, en quarantaine chiffrée s'il est malveillant ; documents, scripts, archives copiés.
- Plus récents d'abord (date de l'enregistrement ≈ suppression) ; plafonds réglables dans `wac.yml` : 64 Mio par fichier (au-delà, relevé sans copie), 4 Gio en tout.
- Clusters en partie réattribués : copie partielle signalée (trous à zéro, `Partial` et plages manquantes dans le JSON, aucune empreinte présentée comme celle du fichier d'origine).
- Réglage (décisions utilisateur) : sous `artefacts:` de `wac.yml`, `deleted_files` est une structure qui porte toutes ses options — `enabled` (true/false), `level` (1 $MFT, 2 + index, 3 + carving, cumulatifs), `max_file_mib` (64), `max_total_mib` (4096), `excluded_folders` (liste : WinSxS, SoftwareDistribution, servicing, cache Installer, catroot/catroot2, `$Extend`). Clé ou option absente = sa valeur par défaut (activé, niveau 3). Le lecteur YAML accepte pour cela les listes de scalaires, et seulement elles.
- Niveau 3 : plafond de durée ; seulement les formats à taille exacte et structure vérifiable (PE, ZIP/Office, PDF) ; même filtre « connu » ; mesure TRIM sous Windows 11 avant développement.

## Tâches
- [x] Étude : volumes de données en jeu (collectes et disques des VM), effet de TRIM sur les VM
- [x] Étude : TRIM sous Windows 11 — sur 14 802 fichiers lus, 36 relus à zéro (Zeroed) ; les témoins, sur le volume de données, intacts
- [x] Décision de principe (niveaux, filtres, plafonds, malveillants)
- [x] Niveau 1 : décodage des plages NTFS borné (liste forgée refusée entière) + test ntfs_runs_test, vu échouer sur l'ancien décodeur
- [x] Niveau 1 : lecteur YAML étendu aux listes de scalaires + réglage `artefacts: deleted_files:` (enabled, level, max_file_mib, max_total_mib, excluded_folders) + config_test
- [x] Niveau 1 : primitives brutes (enregistrement courant, allocation $Bitmap, clusters bornés au volume)
- [x] Niveau 1 : module deleted_files ($DATA résident et non résident, $Bitmap avant ET après lecture, trous, TRIM, plafonds, plus récents d'abord) + deleted_files_test (80 025 contrôles), vu échouer sans le contrôle d'après lecture
- [x] Niveau 1 : exécutables récupérés jugés comme ceux du volume (BinariesStoreRecovered), rangés sous `X:\$DeletedFiles\<entrée>-<séquence>_<nom>`
- [x] Niveau 1 : catalogue des artefacts, témoins du harnais (résident, texte, exécutable non signé, notepad.exe) et contrôle check-json
- [x] Niveau 1 : cycles VM — Windows 11 529 ✅ 0 ❌, Vista 375 ✅ 0 ❌, Windows 7 396 ✅ 2 ❌ (témoin du cliché, B-056), XP 84 ✅ 0 ❌ ; 4 témoins sur 4 retrouvés dans chaque collection de 11, Vista et 7 (c3b290b0)
- [x] Niveau 1 : manuels FR/EN, table des artefacts, guide des tests, dossier d'innocuité
- [x] Niveau 2 : slack des index — `indexSlackEntries` (parent = le répertoire, clé exacte, nom valide, dates 1980-2100, alias 8.3 écartés), blocs libérés lus en entier ; publié seulement un nom qu'aucun répertoire ne porte plus et que le niveau 1 ne rend pas (State NameOnly, Source IndexSlack, CurrentPath si le fichier existe ailleurs) ; deleted_files_test 89 942 contrôles, vu échouer sans le contrôle du parent ; `level: 2` par défaut
- [ ] Niveau 3 : carving (si retenu)
- [ ] FAT/exFAT

## Journal
- 2026-10-01 : créée à la demande de l'utilisateur — récupérer le contenu des fichiers supprimés par lecture brute du disque, pour ne laisser aucune trace sur la machine examinée.
- 2026-10-08 : reportée en 3.0 (décision utilisateur).
- 2026-10-17 : décision utilisateur — à faire pour la 3.0.0, après les clichés instantanés (B-014) ; c'est le dernier élément de la 3.0 avant la revue (B-050).
- 2026-10-21 : rappel utilisateur — tout artefact a sa clé dans `wac.yml` : `deleted_files` pour celui-ci (critère ajouté) ; les clichés instantanés (B-014) ont la leur, `shadow_copies`.
- 2026-10-22 : étude des volumes en jeu (section Étude) ; décision de principe demandée à l'utilisateur.
- 2026-10-22 : décision utilisateur (section Décision) ; niveau 1 commencé. Puis : un seul réglage `deleted_files: false|1|2|3`, pas de clé à part pour le carving. Plafonds et filtres réglables dans `wac.yml`, regroupés en une structure `artefacts: deleted_files:` (enabled, level, plafonds, dossiers écartés).
- 2026-10-22 : niveau 1 écrit et testé hors VM dans une copie de travail isolée (les cycles de B-051 occupaient bin/ et build-windows/) ; report dans l'arbre après les commits de B-051.
- 2026-10-22 : premier cycle complet Windows 11 (534 ✅, 3 ❌). Les quatre témoins supprimés absents : sous Windows 10 et 11, `DeleteFile` d'un fichier encore ouvert (Defender, indexeur) le renomme dans `$Extend\$Deleted\<identifiant>` (journal USN : RENAME_OLD_NAME puis RENAME_NEW_NAME), et ses enregistrements avaient été réutilisés deux minutes après, par Defender et la sortie de WAC sur C:. Or `\$Extend` était dans les dossiers écartés par défaut : 3 045 fichiers supprimés de `$Extend\$Deleted` (213 Mo) masqués. Corrections : `\$Extend\$RmMetadata` seul écarté ; à la conversion, `DeletedUtc` (FILE_DELETE) et `FormerPath` (dernier RENAME_OLD_NAME) lus dans le journal USN ; témoins du harnais sur le volume de données WACDATA. Le troisième ❌ (`mft.json`, prefs.js de Thunderbird réécrit pendant la collecte, enregistrement réutilisé ensuite) est un aléa de la lecture d'un système en marche, sans lien.
- 2026-10-23 : deuxième série. Windows 11 : les 4 témoins retrouvés (posés sur WACDATA ; `deleted-tool.exe` passé par `$Extend\$Deleted`, rendu avec son `FormerPath`), dans les deux collections. Défauts de harnais trouvés et corrigés : chaque témoin reprenait l'enregistrement du précédent (créés puis supprimés un à un) → tous créés derrière 3 000 fichiers vides tampons, puis supprimés ; un `MANIFEST.json` de Vista de 24,6 Mo rapatrié tronqué (`qga.py` relançait une lecture que l'agent avait déjà faite) → chaque lecture repositionnée (`guest-file-seek`) ; le contrôle du journal USN n'acceptait que `FILE_DELETE` → la suppression POSIX reconnue ; cliché du harnais purgé par Windows (4 Gio récupérés écrits sur C: dans la VM) → contrôles sautés et dits. Windows 7, première collection : 1 témoin sur 4, les 3 autres `Overwritten` (clusters réattribués, déclarés tels) ; secondes collections de Vista et 7 : enregistrements des témoins réutilisés, vérifiés par le journal USN et mft.json, dits perdus sans échec. Les fichiers laissés par `max_total_mib` sont désormais listés (`NotRead`), non omis.
- 2026-10-23 : troisième série. Windows 11 529 ✅ 0 ❌ (4 témoins sur 4 dans les deux collections), XP 84 ✅ 0 ❌. Vista : collection au-delà des 30 min de l'agent (récupération à 3,3 Mo/s dans cette VM, 25 Mo/s sous Windows 11) → limite du harnais portée à une heure. Vista et 7 n'avaient pas de volume de données (disque de Vista attaché jamais formaté : `Get-Disk` n'existe qu'à partir de Windows 8 ; disque de 7 pas attaché) → attaché, formaté par diskpart, trouvé par WMI ; témoins retrouvés dessus (cycles restreints). Règle revue : sous `binary: none`, rien n'est jugé et un exécutable récupéré est copié (il était relevé sans copie ni verdict, alors qu'il est ce que la récupération cherche).
- 2026-10-23 : quatrième série verte ; niveau 1 commité (916c6dc3 décodage borné, fd5030d6 listes YAML, 6be25ace factorisation, c3b290b0 fonction, 04f5351c et 712c7b12 harnais, documentation). Suite : niveau 2.
- 2026-10-23 : niveau 2. Témoin du harnais : 450 fichiers, les 150 du milieu de l'ordre déplacés — un dossier vidé entièrement repasse à un index résident, ses blocs hors de toute plage (cycle restreint Windows 11 : aucun des 150 retrouvé) ; avec le dossier qui garde ses blocs, 138 des 150 noms retrouvés, enregistrement et chemin actuel conformes à mft.json. Sur C: de Windows 11, 2 254 noms (cache IndexedDB de Firefox, temporaires, inf du DriverStore…).

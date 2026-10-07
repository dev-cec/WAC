# B-043 — Lecture brute : un enregistrement réutilisé copie un autre fichier sous le nom du premier

| Statut | Priorité | Effort |
|---|---|---|
| fait (afeb9d7) | P1 | moyen |

## Pourquoi
Cycle complet du 2026-10-07 (collecte séparée) : la pièce `C:\Windows\System32\sru\SRU00B25.log` (65 536 octets) commence par `hbin` — un bloc de ruche de registre, pas un journal ESE. Son enregistrement $MFT (188350) désigne dans mft.json un fichier écrit par WAC lui-même pendant la collecte. SRUM a supprimé ce journal entre la lecture de l'index du répertoire et la lecture du fichier ; l'enregistrement libéré a été réutilisé ; WAC l'a lu sans vérifier qu'il désignait encore le même fichier, et a scellé dans la consigne, sous le nom du journal, le contenu d'un autre fichier. Une pièce fausse sous un nom vrai : défaut d'intégrité, P1.

Cause dans le code : la référence lue dans l'index (48 bits d'entrée + 16 de séquence) n'est gardée que pour son numéro d'entrée ; ni la séquence, ni l'état « en usage », ni le nom et le parent de l'enregistrement ne sont comparés au moment de la lecture.

## Source
`sources/raw_hive.cpp` (résolution des chemins par les index, cache des répertoires, lecture de l'enregistrement et de $DATA).

## Sortie attendue
Un fichier dont l'enregistrement ne correspond plus à la référence de l'index (séquence différente, enregistrement libre, ou $FILE_NAME qui ne nomme plus ce fichier sous ce parent) n'est pas copié : il est consigné comme disparu pendant la collecte, avec sa raison. Jamais le contenu d'un autre fichier sous son nom.

## Référence indépendante
- Test unitaire : un volume NTFS (mft_fixtures, ntfs-3g) où un fichier est supprimé et son enregistrement réutilisé entre la lecture de l'index et celle du fichier ; la lecture doit refuser.
- Cycle : le contrôle mft.json / manifeste (check-json) ne doit plus trouver de pièce dont l'enregistrement désigne un autre fichier.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Séquence et usage vérifiés à chaque lecture d'enregistrement par référence.
- Le cas vu en VM documenté dans le dossier de validation.

## Tâches
- [x] Localiser la résolution nom → référence et la lecture de l'enregistrement (raw_hive.cpp : parseIndexNode, resolvePath et son cache, extractData, dumpWofStream)
- [x] Garder la référence complète (RawDirEntry.sequence, cache, resolvePath), vérifier « en usage + même séquence » avant ET après la lecture (readAsIndexed, une seule fonction pour extractData et WOF) ; écart → ERROR_FILE_INVALID, copie partielle effacée. Le nom et le parent ne sont pas revérifiés : la séquence suffit (NTFS l'incrémente à chaque libération), et un renommage garde le même fichier
- [x] Test sources/raw_volume_test.sh : l'image de mft_fixtures servie par Wine comme lecteur T: ; extraction comparée à ntfscat ; séquence de l'enregistrement changée → refus, aucune copie. Nouveau binaire 3/0, ancien (HEAD:bin/raw_hive_test.exe) 2 échecs sur 3
- [x] Documentation : guide des tests (section raw_volume_test.sh, comptes mft_test/usn_journal_test remis à jour), dossier de validation, FR + EN, PDF
- [x] Cycle complet : 452 ✅, 62 322 pièces de la collecte séparée conformes à mft.json

## Journal
- 2026-10-07 : ouverte sur le ❌ du cycle de B-042 ; contenu de la pièce vérifié (`hbin` en tête, SHA-256 24754FD5… identique au manifeste).
- 2026-10-07 : correctif écrit et compilé sans avertissement, test vu échouer sur l'ancien binaire ; non commité. Reste : guide des tests et dossier de validation FR + EN, cycle complet.
- 2026-10-07 : **Close**. Cycle complet vert (452 ✅). Commit : afeb9d7.
- 2026-10-07 : note — les binaires corrigés (bin/) sont partis dans le commit de fiche 8acdaf1 (build-windows.sh les met dans l'index) ; afeb9d7 porte le code. Historique non réécrit ; les commits de fiche se font désormais par chemin.

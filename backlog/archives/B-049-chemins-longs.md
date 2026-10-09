# B-049 — Pièces aux chemins de plus de 260 caractères

| Statut | Priorité | Effort |
|---|---|---|
| fait (215862c) | P1 | moyen |

## Pourquoi
Collecte du kit complet du 2026-10-09 (`vmtest/kape-compare.sh`) : 482 pièces en échec `0x8007001d Écriture impossible sur le périphérique spécifié`. Toutes ont un chemin de plus de 260 caractères une fois placées dans le magasin (`<sortie>\exhibits\<chemin d'origine>`). WAC écrit par `std::ofstream` et `std::filesystem::create_directories` sans préfixe `\\?\`, et son exécutable ne se déclare pas `longPathAware` — ce qui ne suffirait pas : il faut aussi `LongPathsEnabled` dans le registre, désactivé par défaut, et WAC n'écrit pas sur la machine examinée. Sur une machine réelle, les arborescences profondes (`node_modules`, profils d'applications, sources) sont courantes : leurs pièces sont perdues.

Dans la VM, ces chemins viennent de collectes imbriquées laissées par le banc dans `C:\wactest\out` ; le défaut est le même.

## Source
Toute écriture dans le magasin de pièces et la copie de travail, à la collecte comme à la conversion.

## Sortie attendue
Chaque écriture, copie, lecture et parcours du magasin et de la copie de travail passe la limite. Ce qui s'affiche ou se consigne garde la forme ordinaire (le manifeste consigne des chemins relatifs au magasin).

Choix (2026-10-09) : la forme étendue au point d'entrée-sortie (`long_path.h`), seulement pour un chemin trop long, plutôt qu'un dossier de sortie préfixé. Mesuré dans la VM avec g++ 13 : sur un chemin `\\?\`, les flux et `file_size` marchent, mais `create_directories` boucle sans fin, `copy_file` échoue (« File exists »), `relative` et `root_name` ne donnent rien, et un parcours de répertoire ne rend pas les fichiers du dossier. Un dossier de sortie préfixé aurait aussi fait passer le préfixe à esent, au registre hors ligne, et à `root_name` qui écarte le support de collecte.

## Référence indépendante
Témoin du banc : un fichier dont le chemin d'origine fait plus de 300 caractères, créé par PowerShell (`\\?\`), son SHA-256 calculé par Windows (`Get-FileHash -LiteralPath \\?\…`), retrouvé dans le manifeste et dans le magasin.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- aucune pièce en `0x8007001d` sur le kit complet ;
- le dossier de sortie toujours exclu de la collecte (comparaison des chemins sans le préfixe).

## Tâches
- [x] Repérer toutes les écritures et les comparaisons de chemins au dossier de sortie
- [x] `long_path.h` : `extendedPath`, `createFolders`, `copyFileLong`, `moveFileLong`, `forEachFileBelow`, `removeFolderTree`, `pathBelow` ; appliqué aux flux (lecture d'un fichier entier, empreintes, lecteur brut, lecteurs ESE, PST, mbox, CIM, FAT), à la copie de travail, au déplacement des binaires, aux ressources des fournisseurs, aux copies SQLite, à la suppression de la copie de travail
- [x] Témoin du banc à chemin long (`place-file-artefacts.ps1` 6b, 261 caractères), contrôle check-json ; listage du magasin par `\\?\`
- [x] Parcours Win32 sans arrêt à la première erreur : réparation des ruches de la copie de travail, raccourcis, courrier Thunderbird
- [x] Scripts livrés `verify-exhibits.ps1` / `verifier-consigne.ps1` : chemin validé sur la chaîne puis lu en `\\?\`
- [x] Banc : suppressions par `rd /s /q \\?\…`, copies des entrées EZ par robocopy, `split` effacé avant l'étape 4
- [x] Cycle VM complet vert : 472 ✅, 0 ❌, témoin à chemin long compris
- [x] Contrôle vu échouer : rejoué sur le manifeste de la collecte du 2026-10-09 d'avant la correction, une des 482 pièces perdues en témoin → ❌
- [x] Docs FR/EN : manuels (copier ou effacer une collecte), dossier de comparaison (défaut)

## Journal
- 2026-10-09 : fiche ouverte depuis la confrontation à KAPE (482 pièces perdues sur le kit complet).
- 2026-10-09 : correction écrite, compilation MinGW sans avertissement, tests unitaires verts sous Wine (Wine n'a pas la limite : seul le cycle VM éprouve la correction). Cycle complet lancé.
- 2026-10-09 : 1er cycle — 3 copies de travail en `ERROR_PATH_NOT_FOUND` : `extendedPath` jugeait la longueur sur le chemin donné ; un relatif `out\working\…` de 241 caractères dépasse une fois absolu. Corrigé : la longueur du chemin ABSOLU décide. Même cause pour 4 pièces de 245 à 251 caractères à la collecte.
- 2026-10-09 : 2e cycle — code 145 : le banc effaçait `out` par `rmdir` sans `\\?\`, qui laisse les chemins longs ; WAC refusait de collecter dans une copie de travail non vide (comportement voulu). Banc corrigé (rd `\\?\`, robocopy, Remove-Tree). Scripts de vérification livrés : `GetFullPath` lève une exception au-delà de 260 caractères sous PowerShell 5.1 → pièces intactes déclarées MISMATCH ; corrigés.
- 2026-10-09 : 3e cycle — SYSTEM et SOFTWARE non réparées (0x3f1) : `RepairWorkingHives` parcourait la copie de travail par `recursive_directory_iterator`, qui s'arrête à la première erreur ; `wactest\…` (chemins longs) passe avant `Windows\…`. Remplacé par `forEachFileBelow`, qui saute un dossier illisible et continue ; même chose pour les raccourcis et le courrier Thunderbird. Le témoin à chemin long, lui, passait (✅ aux étapes 6 et 7).
- 2026-10-09 : cycle complet vert (472 ✅, 0 ❌). Commit 215862c. Archivée.

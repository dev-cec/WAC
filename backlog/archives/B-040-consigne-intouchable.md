# B-040 — La consigne n'est plus lue après la copie de travail

| Statut | Priorité | Effort |
|---|---|---|
| fait (e94949c) | P1 | moyen |

## Pourquoi
La consigne (`exhibits`) est la pièce scellée. Une fois copiée dans la copie de travail (`working`), elle ne doit plus être touchée, ni en écriture ni en lecture : tout traitement lit la copie de travail. Un accès à la pièce après sa copie peut invalider une procédure (demande utilisateur du 2026-10-06).

## Source
Code existant qui lit la consigne après la copie de travail :
- conversion des artefacts par le chemin `file` de `ExhibitStoreIndex()` : Defender (journaux, détections, quarantaine), corbeille, `$MFT`, `$UsnJrnl`, `$Secure:$SDS`, `$Boot`, SRUM, BITS, rapports d'erreurs, dépôt WMI, volumes FAT, dossiers de démarrage ;
- fichiers des fournisseurs d'événements (`extractResource`) : copie depuis la consigne vers `working`, lecture dans la consigne en `--convert` ;
- binaires en `--convert` (`ExhibitReader`) : lus dans la consigne, exclus de la copie de travail.

## Sortie attendue
Après `ExhibitStoreToWorking`, aucune lecture ni écriture dans `exhibits`, hormis la vérification d'intégrité prévue par la procédure. Chaque lecture d'un fichier collecté passe par sa copie de travail.

## Référence indépendante
L'audit d'accès de Windows : une règle d'audit de lecture (SACL) sur la consigne de la collecte séparée pendant sa conversion, les événements 4663 de `WAC.exe` comparés à l'instant de sa recopie dans `conversion.json`, à la centaine de nanosecondes (`vmtest/guest/exhibit-read-audit.ps1`, `check-json.py`). La date de dernier accès NTFS, mise à jour paresseusement par Windows, n'aurait rien prouvé.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun appel restant à `ExhibitStoreIndex().file` ni à `exhibitStoreFolder()` pour lire un contenu après la copie de travail (revue du code).
- Cycle complet vert, collecte directe et séparée, sorties identiques à celles d'avant.

## Tâches
- [x] Chemin de la copie de travail dans `StoredExhibit` (`workingFile`, le chemin dans la consigne n'est plus exposé)
- [x] Bascule de chaque module
- [x] Fichiers des fournisseurs d'événements
- [x] Binaires en `--convert`, `$MFT` et journal des modifications : tout est recopié
- [x] Contrôle du harnais

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur, prioritaire, avant la suite de B-033.
- 2026-10-06 : fait. Tout est recopié dans la copie de travail (plus d'exception « lu sur place ») : la `$MFT`, le journal des modifications et les binaires prélevés y occupent une seconde fois leur place. Ce que WAC produit est écrit dans les deux à la fois. « Déjà déposé ? » se répond par ce que WAC a enregistré, sans regarder la consigne. Audit de Windows : 1 458 lectures de la consigne en cycle `events`, 13 335 en cycle complet (binaires compris), toutes avant la recopie, aucune après.
- 2026-10-06 : **Close**. Cycle complet vert (438 ✅, 0 ❌), innocuité comprise, conversion déterministe. Commit : e94949c.

# B-040 — La consigne n'est plus lue après la copie de travail

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

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
Contrôle du harnais : la date de dernier accès des fichiers de la consigne, relevée après leur copie de travail, ne change plus jusqu'à la fin de l'exécution (lecture seule NTFS du support, sans y écrire).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun appel restant à `ExhibitStoreIndex().file` ni à `exhibitStoreFolder()` pour lire un contenu après la copie de travail (revue du code).
- Cycle complet vert, collecte directe et séparée, sorties identiques à celles d'avant.

## Tâches
- [ ] Chemin de la copie de travail dans `StoredExhibit`
- [ ] Bascule de chaque module
- [ ] Fichiers des fournisseurs d'événements
- [ ] Binaires en `--convert`
- [ ] Contrôle du harnais

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur, prioritaire, avant la suite de B-033.

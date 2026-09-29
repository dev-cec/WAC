# B-005 — $MFT et $UsnJrnl de chaque volume NTFS fixe

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | faible |

## Pourquoi
Seul le volume système est pris : un disque de données ou un profil sur D: échappe à la chronologie.

## Source
`$MFT`, `$Extend\$UsnJrnl:$J`, `$LogFile` de chaque volume de `fixedNtfsVolumes()`.

## Sortie attendue
`mft.json` et `usn_journal.json` avec un champ `Volume`, ou un fichier par volume (à décider).

## Référence indépendante
Second disque NTFS dans la VM, témoin créé puis supprimé dessus.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Le témoin présent dans mft.json et sa suppression dans usn_journal.json du second volume.

## Tâches
- [ ] Décider la forme de sortie
- [ ] Prélèvement et conversion par volume
- [ ] Second disque dans la VM de test

## Journal
- (vide)

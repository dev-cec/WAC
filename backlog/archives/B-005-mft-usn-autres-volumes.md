# B-005 — $MFT et $UsnJrnl de chaque volume NTFS fixe

| Statut | Priorité | Effort |
|---|---|---|
| fait (c0bf905) | P2 | faible |

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
- [x] Décider la forme de sortie : un seul fichier, champ `Volume` (un numéro d'enregistrement n'a de sens que dans son volume)
- [x] Prélèvement et conversion par volume (`fixedNtfsVolumes()`, pièces sous `_volume_X`)
- [x] Second disque dans la VM de test (`create-vm.sh`, formaté NTFS `WACDATA` par le harnais, journal USN activé)

## Journal
- 2026-09-29 : décision utilisateur — second disque NTFS de 2 Go ajouté à la VM de test pour éprouver l'élément.
- 2026-09-30 : un disque de données n'a pas de journal USN tant qu'un service ne le demande pas : WAC consigne alors l'extraction « introuvable », avec sa raison ; le harnais active le journal de G: pour éprouver la conversion.

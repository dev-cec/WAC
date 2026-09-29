# B-013 — Lecture brute FAT et exFAT

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | fort |

## Pourquoi
Clés USB et partitions FAT/exFAT sont aujourd'hui signalées « non lues » : fichiers cités et binaires qui s'y trouvent échappent à la collecte.

## Source
Volumes FAT12/16/32 et exFAT de la machine (hors support de collecte).

## Sortie attendue
Équivalent de mft.json par volume (entrées, supprimées comprises), dates FAT en heure locale convertie, exFAT avec son décalage.

## Référence indépendante
Image FAT et exFAT construite sous Linux (mkfs.vfat, mkfs.exfat) avec fichiers et suppressions connus.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Fichiers et entrées supprimées retrouvés sur les deux images ; lectures bornées (image forgée).

## Tâches
- [ ] Lecteur FAT
- [ ] Lecteur exFAT
- [ ] Intégration aux binaires cités
- [ ] Tests sur images

## Journal
- (vide)

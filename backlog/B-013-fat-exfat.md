# B-013 — Lecture brute FAT et exFAT

| Statut | Priorité | Effort |
|---|---|---|
| fait (voir Journal) | P2 | fort |

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
- [x] Lecteur FAT (12, 16, 32) : noms longs, entrées supprimées (nom long retrouvé par la somme de contrôle, ou signalé tronqué)
- [x] Lecteur exFAT : ensembles d'entrées, supprimés à nom entier, dates au centième avec décalage UTC
- [x] fat_volumes.json : volumes fixes et amovibles hors support ; collecte des seules métadonnées, conversion sur la copie
- [x] Intégration aux binaires cités : FatAwareReader lit sur FAT/exFAT les fichiers que cite un artefact ; la collecte --binary parcourt aussi ces volumes. Témoin : copie de whoami.exe lancée depuis la clé, citée par son Prefetch, SHA-256 identique
- [x] Tests sur images : FAT12/16 (mkfs.vfat, pyfatfs), FAT32/exFAT formatées par Windows, contre dissect.fat

## Journal
- 2026-09-30 : Windows écrit une heure locale FAT avec le décalage du moment, WAC la lit avec celui de sa date (règle du projet) : une date d'hiver posée en été diffère d'une heure — témoin placé en été, écart documenté.
- 2026-09-30 : les noms longs supprimés sont écrasés d'un cycle à l'autre (réutilisation des emplacements) : le contrôle accepte le nom 8.3.
- 2026-09-30 : en --collect, un binaire authentifié Microsoft n'a que son empreinte Authenticode (règle de prélèvement) : le témoin de la clé, copie de whoami.exe, suit la même règle.

# B-019 — MftEntry: 0 émis pour les pièces « live »

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | faible |

## Pourquoi
Règle 1 : un champ sans valeur n'est pas émis. Les pièces live (running-machine.json…) n'ont pas d'entrée MFT, et 0 se lit comme l'entrée de $MFT elle-même.

## Source
`consigne.cpp` (manifeste), `RawHiveFingerprints::mftEntry`.

## Sortie attendue
Champ absent pour les pièces live.

## Référence indépendante
check-json : aucune pièce live avec MftEntry.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- La pièce $MFT garde son MftEntry 0 réel.

## Tâches
- [ ] mftEntry optionnel
- [ ] Contrôle check-json
- [ ] Test

## Journal
- (vide)

# B-019 — MftEntry: 0 émis pour les pièces « live »

| Statut | Priorité | Effort |
|---|---|---|
| fait (51e7809) | P2 | faible |

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
- [x] mftEntry optionnel (std::optional)
- [x] Contrôle check-json (check_mft_entries), vu échouer sur la collecte précédente
- [x] Test : check_mft_entries au cycle VM

## Journal
- 2026-09-29 : `RawHiveFingerprints::mftEntry` devient optionnel ; le manifeste ne l'émet que pour une pièce lue sur le volume. check_mft_entries échoue sur la collecte d'avant (running-machine.json, sessions.json, processes.json avec MftEntry). Cycle VM lancé.
- 2026-09-29 : cycle VM vert ; commité (51e7809), fiche archivée.

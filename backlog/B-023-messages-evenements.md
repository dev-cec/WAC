# B-023 — Messages lisibles d'environ un tiers des événements seulement

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | moyen |

## Pourquoi
Deux tiers des événements n'ont pas de message lisible : fournisseurs sans ressources exploitables, ou lacune du décodage.

## Source
`event_messages.cpp`.

## Sortie attendue
Taux mesuré par fournisseur.

## Référence indépendante
EvtxECmd (Maps) et l'observateur d'événements sur la même machine.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Écart expliqué fournisseur par fournisseur.

## Tâches
- [ ] Mesure par fournisseur
- [ ] Comparaison EvtxECmd

## Journal
- (vide)

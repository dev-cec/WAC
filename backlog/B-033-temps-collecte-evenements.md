# B-033 — Temps de collecte des journaux d'événements (≈ 180 s)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
Sur la VM, la collecte de WAC (kit, sans binaires) prend 197 s contre 40 s pour KAPE (KapeTriage) ; sans les journaux d'événements, 18 s. Les ~180 s viennent de la collecte des journaux et des 1 225 binaires fournisseurs de messages (680 Mo) copiés pour reconstituer les messages hors ligne. À mesurer, puis réduire : c'est le temps passé sur la machine examinée.

## Source
`vmtest/kape-compare.sh --no-binary`, WAC.log avec horodatage des étapes.

## Sortie attendue
Mesure par étape (lecture brute des .evtx, recherche des fournisseurs, copie et empreinte des binaires) ; pistes : ne copier que les fournisseurs effectivement cités par les journaux collectés, ne copier qu'une fois un binaire partagé (.mui et DLL communes), paralléliser l'empreinte.

## Référence indépendante
Même collecte avant/après : mêmes messages dans events.json (comparaison des JSON), temps mesuré par kape-compare.sh.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun message d'événement perdu (events.json identique avant/après).
- Temps de collecte des journaux divisé au moins par deux, ou raison documentée.

## Tâches
- [ ] Mesure par étape
- [ ] Réduction

## Journal
- 2026-10-01 : ouverte depuis B-015.

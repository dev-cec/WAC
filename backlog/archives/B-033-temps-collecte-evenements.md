# B-033 — Temps de collecte des journaux d'événements (≈ 180 s)

| Statut | Priorité | Effort |
|---|---|---|
| fait (86cec3f, 02c77dd) | P2 | moyen |

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
- [x] Mesure par étape (temps de chaque étape au journal d'investigation)
- [x] Réduction

## Journal
- 2026-10-01 : ouverte depuis B-015.
- 2026-10-06 : mesure par étape. Les « ≈ 180 s des journaux d'événements » étaient mal attribués : le journal d'investigation ne datait que les opérations, et une vingtaine d'artefacts sans opération propre comptaient pour la suivante. La lecture des journaux prend 22 s. Le temps de chaque étape, de son libellé à son OK, va maintenant au journal d'investigation. En cycle complet, le gros poste est l'empreinte des fichiers que citent les Prefetch (--binary), imputée à l'étape Prefetch.
- 2026-10-06 : réductions. (1) Les fichiers des fournisseurs passent par un seul lecteur brut : 26,3 s → 4,0 s. (2) Demande utilisateur : les volumes sont ouverts une fois, dès leur détection, avec le cache des index de répertoires, partagés par toutes les lectures ; une entrée du cache n'est prise que si son enregistrement MFT porte encore ce nom dans ce répertoire. (3) --collect ne prélève que les fichiers des fournisseurs cités par les journaux collectés (324 sur 1 426, 178 Mio au lieu de 739, 15 s au lieu de 61), lus dans la copie de travail des journaux (B-040).
- 2026-10-06 : résultat face à KapeTriage, sans binaires, même exécution : WAC 46,7 s (2,54 Go, 1 898 pièces) contre KAPE 58,1 s (0,97 Go) ; au départ, 197 s contre 40 s. Aucun message perdu : 98,6 % des sortes identiques à Windows, collecte directe comme séparée.
- 2026-10-06 : **Close**. Cycle complet vert (438 ✅, 0 ❌). Commits : 86cec3f (volumes partagés, temps par étape, lecteur unique des fournisseurs), 02c77dd (fournisseurs cités), et la mise à jour du document de comparaison.

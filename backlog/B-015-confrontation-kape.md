# B-015 — Confrontation à KAPE et aux outils Zimmerman

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Mesure indépendante de la couverture (quels fichiers KAPE prend que WAC ne prend pas) et de la justesse des JSON (MFTECmd, EvtxECmd, RECmd, PECmd… sur les mêmes pièces).

## Source
Collecte KAPE !SANS_Triage de la VM de test, au même instant qu'une collecte WAC.

## Sortie attendue
Rapport de couverture et d'écarts ; contrôle automatisable dans check-json si possible.

## Référence indépendante
C'est elle-même la référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque écart de couverture classé : ajouté au backlog ou écarté avec sa raison.
- Chaque écart de valeur expliqué ou corrigé.

## Tâches
- [x] Installer KAPE et les outils EZ sur la VM (vmtest/install-tools.sh, .NET 9.0.20)
- [ ] Collectes simultanées
- [ ] Comparaison fichiers et empreintes
- [ ] Comparaison des JSON (vmtest/lib/ez-compare.py) :
  - [x] mft.json / MFTECmd : 362 081 enregistrements, 8 dates, chemins, états identiques ; tailles : 1 490 WOF et 3 EVTX où WAC a raison (Windows), 5 métafichiers de convention. A révélé la fusion d'extensions périmées (fix).
  - [ ] events.json / EvtxECmd
  - [ ] prefetchs.json / PECmd
  - [ ] raccourcis et jump lists / LECmd, JLECmd
  - [ ] shellbags / SBECmd
  - [ ] Amcache, ShimCache / AmcacheParser, AppCompatCacheParser
  - [ ] corbeille / RBCmd ; SRUM / SrumECmd ; registre / RECmd

## Journal
- 2026-09-29 : décision utilisateur — les outils Zimmerman (et .NET) installés dans la VM de test ; KAPE écarté (inscription chez Kroll).
- 2026-09-30 : KAPE fourni par l'utilisateur : `vmtest/kape.zip` (exclu du dépôt par .gitignore, licence Kroll). La comparaison avec KAPE redevient possible.
- 2026-09-30 : temps, même $MFT de 380 Mo dans la VM : WAC convertit C: et G: en 7,3 s, MFTECmd C: seul en 8,1 s (CSV).

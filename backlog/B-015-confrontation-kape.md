# B-015 — Confrontation à KAPE et aux outils Zimmerman

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
- [ ] Installer KAPE et les outils EZ sur la VM
- [ ] Collectes simultanées
- [ ] Comparaison fichiers et empreintes
- [ ] Comparaison des JSON

## Journal
- 2026-09-29 : décision utilisateur — les outils Zimmerman (et .NET) installés dans la VM de test ; KAPE écarté (inscription chez Kroll).

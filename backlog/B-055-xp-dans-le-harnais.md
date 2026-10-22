# B-055 — Windows XP dans le harnais

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | fort |

## Pourquoi
XP SP1 à SP3 sont validés hors harnais (B-037, archivée) : passages de WAC32 au clavier, sortie relue disque éteint, confrontée aux outils de référence. Une régression sous XP ne serait vue qu'en refaisant ces passages à la main.

## Source
VM `winxp-test` (SP1) et `winxpsp3-test` ; pas de PowerShell ni d'agent invité : pilotage par `vmkeys.py` et le port série (fait), lecture des résultats sur le disque éteint (fait à la main).

## Sortie attendue
Un cycle `run-wac-test.sh` sous XP : collecte et conversion lancées au clavier, résultats relus sur le disque, contrôles de `check-json.py` qui s'appliquent à XP.

## Référence indépendante
Celles du harnais, et les références posées hors ligne (dissect, libscca, libevt) sur le disque de la VM.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune trace laissée dans la VM au-delà des témoins, sans accumulation.

## Tâches
- [ ] Lancement de WAC32 et attente de sa fin sans agent
- [ ] Relecture des résultats disque éteint, références posées hors ligne
- [ ] Contrôles adaptés à XP dans `check-json.py`

## Journal
- 2026-10-22 : sortie de B-037 à sa clôture.

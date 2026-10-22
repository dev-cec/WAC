# B-055 — Windows XP dans le harnais

| Statut | Priorité | Effort |
|---|---|---|
| fait (ea71b726) | P3 | fort |

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
- [x] Lancement de WAC32 et attente de sa fin sans agent (`run-wac-test-xp.sh` : image CD, `run-xp.cmd` tapé au clavier, étapes sur COM1)
- [x] Relecture des résultats disque éteint (`lib/read-offline.py`)
- [x] Contrôles adaptés à XP dans `check-json.py`

## Journal
- 2026-10-22 : sortie de B-037 à sa clôture.
- 2026-10-22 : **fait** (harnais ea71b726). XP SP1 et SP3 : 82 ✅, 0 ❌ chacun. Défauts de WAC trouvés et corrigés : la console laissée en page 65001, après quoi `cmd.exe` d'avant Windows 8 cessait de lire le script qui avait lancé WAC (08f43029) ; les `.job` de XP déclarés « attendus mais introuvables » alors qu'une installation n'en a aucune (a4f70442) ; sous XP, passerelles et serveur DHCP non lus, connexions de SP2 et SP3 non lues faute de repli, lectures des tables de connexions non bornées par le tampon (7e4b169d). Défauts du harnais : Entrée non prise en fin de texte tapé, lettre du CD (E:), redirection `%errorlevel%> COM1` lue comme celle du descripteur 0, port série d'une VM clonée (celui de l'original), noms 8.3 relus en double. Les redémarrages observés pendant la mise au point (machine figée au logo) ne se sont plus produits une fois le script lu jusqu'au bout.

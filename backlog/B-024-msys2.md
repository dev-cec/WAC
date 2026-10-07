# B-024 — Compilation MSYS2 à éprouver sur un vrai Windows

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | faible |

## Pourquoi
build-windows.sh gère MSYS2 MINGW64 mais n'y a jamais tourné.

## Source
`build-windows.sh`.

## Sortie attendue
WAC.exe fonctionnel, mêmes imports.

## Référence indépendante
Cycle VM avec le binaire compilé sous MSYS2. MSYS2 installé dans un clone de la VM (ou une VM dédiée), jamais dans win11-test : la machine des cycles reste sans outil de développement (décision utilisateur 2026-10-07).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Compilation sans avertissement ; imports identiques ; cycle VM vert.

## Tâches
- [x] Clone de la VM : win11-msys2 (disque système copié, /home/sebastien/vms/win11-msys2.qcow2 ; disque de données, clés USB et ISO de transfert détachés : le clone ne touche aucun témoin)
- [x] MSYS2 MINGW64 installé dans le clone (archive de base épinglée par le SHA-256 de GitHub, e9ea7da6…1290 ; g++ 16.2.0), sources du commit 101bb81 copiées (git archive), build-windows.sh lancé
- [ ] Imports comparés au binaire de Linux, cycle VM avec le binaire de MSYS2

## Journal
- (vide)
- 2026-10-07 : lieu décidé — clone dédié de la VM.
- 2026-10-07 : en cours. win11-test arrêtée proprement pour le clonage, puis redémarrée ; elle ne démarrait plus — son ISO d'installation (Téléchargements/Win11_25H2_French_x64_v2.iso) n'existe plus : support éjecté de sa configuration et de celle du clone (virsh change-media … --eject --config), sans autre changement.
- 2026-10-07 : premier constat — l'aide de build-windows.sh demandait libiconv, qui ne fournit sous MSYS2 que les bibliothèques ; l'exécutable iconv vient de mingw-w64-x86_64-iconv : message corrigé.
- 2026-10-07 : première compilation MSYS2 (g++ 16.2.0) aboutie, mais : (1) wac-version.sh — écrit le jour même — appelait python3, absent de MSYS2 : réécrit avec iconv et sed, qu'exige déjà la compilation ; (2) cinq avertissements absents de g++ 13 : -Wdangling-reference sur une boucle d'authenticode.cpp parcourant une liste entre accolades (tableau nommé désormais), -Wunused-but-set-variable dans SQLite (code amont : seconde exclusion documentée dans build-windows.sh). Non commité ; seconde compilation lancée.

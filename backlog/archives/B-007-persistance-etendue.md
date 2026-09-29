# B-007 — Persistance étendue (registre, BITS)

| Statut | Priorité | Effort |
|---|---|---|
| fait (9c21e1b) | P1 | moyen |

## Pourquoi
Mécanismes de persistance courants absents : IFEO (Debugger, SilentProcessExit), AppInit_DLLs, Winlogon (Shell, Userinit), paquets LSA, moniteurs d'impression, détournements COM (HKCU\CLSID), tâches BITS.

## Source
Ruches SOFTWARE, SYSTEM, NTUSER déjà copiées ; `qmgr.db` (BITS, ESE ou format propre selon version).

## Sortie attendue
`persistence.json` : mécanisme, clé, valeur, date d'écriture de la clé, binaire visé (+ empreintes avec --binary).

## Référence indépendante
Valeurs de test posées par le harnais sur chaque mécanisme.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque mécanisme posé par le harnais retrouvé.

## Tâches
- [x] Liste des clés et de leur sens : table RULES de persistence.cpp (24 règles), sens documenté dans persistence.h
- [x] Collecteur registre : persistence.json, toutes les valeurs (défaut compris), empreintes avec --binary
- [ ] BITS (dépend du lecteur ESE) : reporté dans B-009

## Journal
- 2026-09-29 : décision — émettre toutes les valeurs, celles de Windows comprises ; trier l'ajouté du défaut revient à WAE (une liste filtrée ici cacherait l'inattendu). Témoins inoffensifs (programmes et DLL inexistants) ; aucun paquet LSA ni moniteur ajouté dans la VM : ceux-là sont comparés aux valeurs lues en direct. BITS reporté à B-009 (qmgr.db, ESE). Cycle VM lancé.
- 2026-09-29 : 1er cycle — 7 contrôles sur 8 verts (témoins SilentProcessExit, Active Setup, COM ; Userinit, LSA, 6 moniteurs identiques à Windows). IFEO : GlobalFlag rendu « 0x200 » (to_hex sans zéros) → forme à 8 chiffres de l'éditeur du registre, 0x00000200. 2e cycle lancé.
- 2026-09-29 : 2e cycle vert (8/8). Commité (9c21e1b), fiche archivée ; BITS reporté dans B-009.

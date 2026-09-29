# B-007 — Persistance étendue (registre, BITS)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
- [ ] Liste des clés et de leur sens
- [ ] Collecteur registre
- [ ] BITS (dépend du lecteur ESE pour les versions récentes)

## Journal
- (vide)

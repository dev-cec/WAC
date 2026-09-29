# B-003 — Ruches SECURITY et DEFAULT, RegBack

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | faible |

## Pourquoi
SECURITY porte la politique d'audit (PolAdtEv), le nombre de connexions mises en cache, les noms des secrets LSA ; DEFAULT la configuration du compte système ; RegBack d'anciennes copies des ruches.

## Source
`\Windows\System32\config\SECURITY`, `DEFAULT` et journaux ; `config\RegBack\*`.

## Sortie attendue
Pièces brutes ; JSON à définir : `security.json` (politique d'audit décodée, noms des secrets et dates, nombre de connexions en cache) ; clés utiles de DEFAULT dans les artefacts existants.

## Référence indépendante
`auditpol /get /category:*` dans la VM contre la politique décodée.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune valeur de secret émise : noms et dates seulement (prudence de type LSASS).
- Politique d'audit identique à celle d'auditpol.

## Tâches
- [ ] Prélèvement brut et rejeu
- [ ] Décodage PolAdtEv
- [ ] Secrets : noms et dates
- [ ] Référence auditpol dans le harnais

## Journal
- (vide)

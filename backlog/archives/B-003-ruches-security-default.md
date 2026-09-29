# B-003 — Ruches SECURITY et DEFAULT, RegBack

| Statut | Priorité | Effort |
|---|---|---|
| fait (0c81af8, 6ba853a) | P2 | faible |

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
- [x] Prélèvement brut et rejeu (SECURITY, DEFAULT et leurs journaux ; RegBack prélevé tel quel, jamais rejoué)
- [x] PolAdtEv : octets bruts (format non publié), comparés octet pour octet à Windows
- [x] Secrets : noms et dates (CupdTime, OupdTime) ; connexions en cache : emplacements NL$ et occupés
- [x] Références VM : noms des secrets, PolAdtEv, NL$ lus en direct (SYSTEM) ; valeur Run REG_EXPAND_SZ dans DEFAULT

## Journal
- 2026-09-29 : décisions — PolAdtEv non décodé (pas de spécification sûre ; « objet non décodé = octets bruts »), comparé à Windows plutôt qu'à auditpol ; noms et dates des secrets seulement, jamais les valeurs ; DEFAULT exploité par run.json (Hive=DEFAULT).
- 2026-09-29 : le collecteur Run réécrit au passage : deux copies de la même boucle, ruches NTUSER ouvertes et jamais fermées (deux fois par profil), valeurs REG_EXPAND_SZ ignorées — une seule fonction, ruches refermées, les deux types lus (champs Hive et Type ajoutés).
- 2026-09-29 : dans la VM, secrets CachedDefaultPassword, DefaultPassword (connexion automatique de wac), DPAPI_SYSTEM, NL$KM ; 10 emplacements NL$. Cycle VM lancé.
- 2026-09-29 : cycle VM vert ; seul échec, un faux négatif du contrôle (noms triés avec et sans casse), corrigé en comparant des ensembles et rejoué sur les sorties du cycle. Commité (0c81af8 SECURITY, 6ba853a Run), fiche archivée.

# B-021 — new/delete nus dans reg_shellbags

| Statut | Priorité | Effort |
|---|---|---|
| fait (367372a) | P2 | faible |

## Pourquoi
Règle C++ : pas de new/delete nus (`delete[] data` dans reg_shellbags.cpp) ; à rechercher dans tout le code.

## Source
`sources/reg_shellbags.cpp` et autres occurrences.

## Sortie attendue
std::vector.

## Référence indépendante
Compilation, parsers_test, cycle VM.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun `new`/`delete` nu dans sources/.

## Tâches
- [x] Recensement : la source était getRegBinaryValue (tools.cpp), qui allouait un LPBYTE libéré par chaque appelant (une vingtaine de delete[] : MRU, applications MRU, Shellbags, Shimcache, tâches, comptes)
- [x] Remplacement : getRegBinaryValue remplit un std::vector ; lecture de MRUListEx mise en commun (readMruListEx), bornée — elle lisait 4 octets au-delà d'une valeur de longueur non multiple de 4 ; make_unique dans binaires.cpp
- [x] Contrôle : JSON du registre identiques à ceux du cycle précédent, à l'activité de la VM près

## Journal
- 2026-09-29 : plus aucun new/delete nu dans sources/ ; compilation propre ; cycle VM lancé.
- 2026-09-29 : cycle VM vert ; commité (367372a), fiche archivée.

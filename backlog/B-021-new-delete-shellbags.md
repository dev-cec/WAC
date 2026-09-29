# B-021 — new/delete nus dans reg_shellbags

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | faible |

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
- [ ] Recensement
- [ ] Remplacement

## Journal
- (vide)

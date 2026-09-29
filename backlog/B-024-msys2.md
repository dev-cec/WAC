# B-024 — Compilation MSYS2 à éprouver sur un vrai Windows

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | faible |

## Pourquoi
build-windows.sh gère MSYS2 MINGW64 mais n'y a jamais tourné.

## Source
`build-windows.sh`.

## Sortie attendue
WAC.exe fonctionnel, mêmes imports.

## Référence indépendante
Cycle VM avec le binaire compilé sous MSYS2.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Compilation sans avertissement ; imports identiques ; cycle VM vert.

## Tâches
- [ ] Machine Windows avec MSYS2 (hors VM de test, pour ne pas la polluer)

## Journal
- (vide)

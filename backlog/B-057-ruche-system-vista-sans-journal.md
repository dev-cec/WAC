# B-057 — Ruche SYSTEM de Vista : Windows en perd la moitié sans son journal, WAC ne le rejoue pas

| Statut | Priorité | Effort |
|---|---|---|
| à faire (version 3.0, avant la revue B-050) | P2 | moyen |

## Pourquoi
Le harnais confronte le rejeu des journaux de ruche par WAC à celui de Windows (`hive-recovery-reference.ps1`) : la ruche telle que prélevée, avec ses journaux, chargée par `reg load` (Windows rejoue lui-même), contre la copie que WAC a rejouée, chargée seule. Sous Vista, au cycle du 2026-10-24 11:50, la ruche SYSTEM diffère : Windows 20 621 clés et 47 272 valeurs, WAC 8 403 et 20 628. Les huit cycles Vista précédents concordaient exactement (20 621 / 47 272, ou 20 565 / 47 190).

## Constats (2026-10-24, ruches relues hors ligne sur le disque de la VM éteinte)
- La copie de travail de WAC est identique, octet pour octet, à la pièce prélevée : WAC n'a rien rejoué. Les deux numéros de séquence de la ruche sont égaux (2191, 2191) : ruche dite propre. `SYSTEM.LOG1` porte la même séquence (2191), au format d'avant Windows 8.1 (en-tête `regf` de type 1, bitmap `DIRT`) ; `SYSTEM.LOG2` est vide.
- regipy, implémentation indépendante, parcourt les 20 621 clés dans la pièce prélevée elle-même : la ruche n'est pas tronquée.
- C'est donc Windows qui, chargeant la ruche SEULE (sans journal), n'en garde que 8 403 clés — avec son journal, toutes. Hypothèse : Windows juge une partie de la ruche incohérente et la retranche à l'ouverture (« self-healing »), sauf quand le journal lui donne de quoi la réparer.

## Sortie attendue
La cause établie : ce que Windows trouve d'incohérent dans la ruche, ce que son journal lui apporte, et si WAC doit rejouer un journal de même séquence que la ruche (format ancien). Selon la cause : soit un rejeu de WAC qui donne le même résultat que Windows, soit une explication documentée de l'écart (la ruche lue par WAC est complète ; c'est la référence qui se trompe).

## Référence indépendante
`reg load` de la pièce avec et sans son journal, regipy, et le décompte cellule par cellule des bins de la ruche (cellules marquées libres ou allouées).

## Tâches
- [ ] Reproduire : relancer le cycle Vista et garder les ruches de la pièce quand l'écart revient
- [ ] Comparer cellule par cellule la ruche chargée seule par Windows et regipy
- [ ] Décider : rejeu de WAC, ou référence corrigée

## Journal
- 2026-10-24 : créée. Écart vu une fois, sur la série de non-régression de B-036 (qui ne touche pas au rejeu des ruches).

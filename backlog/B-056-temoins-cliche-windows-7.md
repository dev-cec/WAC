# B-056 — Témoins du cliché instantané peu fiables sous Windows 7

| Statut | Priorité | Effort |
|---|---|---|
| à faire (version 3.0, avant la revue B-050) | P2 | moyen |

## Pourquoi
Le harnais vérifie les clichés instantanés (B-014) avec deux témoins : une valeur Run et un événement d'un journal propre, écrits avant le cliché, effacés après. WAC doit les rendre dans `shadow_copy_registry.json` et `shadow_copy_events.json`. Sous Windows 7, ils manquent de façon intermittente. Or **libvshadow**, implémentation indépendante, lit le cliché comme WAC : ce que WAC rend est ce que le disque porte. Tant que la cause n'est pas établie, un ❌ de ces contrôles sous Windows 7 ne dit rien de WAC, et un vrai défaut de lecture des clichés y passerait inaperçu.

## Source
Constats du 2026-10-22, VM `win7-test` :
- Cycle complet (cycles de B-051) : événement témoin retrouvé, valeur Run absente. Relu hors ligne dans le cliché collecté : la clé Run de SOFTWARE date de 16:05 UTC, sans le témoin, absent aussi de SOFTWARE.LOG1. Le cliché a été pris à 19:09 UTC, 15 s après l'écriture de la valeur.
- Cycle restreint (`--only=shadow_copies,run_keys,events`), collecte 96 s après le cliché : valeur Run ET événement témoin absents, et les 3 000 événements de remplissage écrits **après** le cliché présents dedans. Même lecture par libvshadow, VM éteinte (tout écrit sur le disque).
- Le témoin Run était déjà vidé par une simple attente de 15 s ; le harnais force maintenant l'écriture de la ruche par `RegFlushKey` (`RegistryKey.Flush()`) avant le cliché. Changement en attente, non commité, jugé sur le prochain cycle complet de Windows 7.

## Sortie attendue
La cause établie, puis des témoins qui ne dépendent plus du moment où Windows écrit : par exemple ruche vidée (`RegFlushKey`), journal vidé, volume vidé (`FlushFileBuffers` sur le volume) avant le cliché, et une attente après. Si la cause est dans la façon dont Windows 7 tient ses clichés, documenter ce qu'un cliché récent garantit, ou pas, dans le manuel.

## Référence indépendante
libvshadow (`vmtest/tools/vss-venv`) sur le disque de la VM éteinte, et `certutil -hashfile` sur le périphérique du cliché, VM allumée.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Trois cycles complets de Windows 7 de suite avec les deux témoins retrouvés.
- La cause écrite dans le journal de la fiche, mesures à l'appui.

## Tâches
- [ ] Établir pourquoi des écritures postérieures au cliché y apparaissent (fichier du journal recréé par `Clear-EventLog` sur des clusters libres au moment du cliché ?)
- [ ] Témoins robustes, ou attente mesurée
- [ ] Trois cycles complets de Windows 7

## Journal
- 2026-10-22 : créée. Les cycles de B-051 sous Windows 7 n'ont échoué que sur ce témoin ; analyse ci-dessus.

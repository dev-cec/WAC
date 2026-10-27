# B-056 — Témoins du cliché instantané peu fiables sous Windows 7 et Vista

| Statut | Priorité | Effort |
|---|---|---|
| fait (7cbd961e) | P2 | moyen |

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
- [x] Cause : le cliché saisit le disque, et Windows écrit le registre et les journaux d'événements en retard (mesuré, voir le journal)
- [x] Attente mesurée : 120 s entre la valeur témoin et le cliché (`place-file-artefacts.ps1`)
- [x] Trois cycles complets de Windows 7

## Journal
- 2026-10-22 : créée. Les cycles de B-051 sous Windows 7 n'ont échoué que sur ce témoin ; analyse ci-dessus.
- 2026-10-23 : même symptôme sous Vista, au cycle où le harnais a remplacé l'attente de 15 s par `RegFlushKey` seul : la ruche SOFTWARE du cliché collecté, relue hors ligne, n'a pas la valeur témoin (Run : « Windows Defender » seul), ni son journal. Le cycle précédent de Vista, avec l'attente, la retrouvait. Le délai entre l'écriture et le cliché compte, pas seulement le vidage de la ruche : le harnais fait les deux en attendant la cause.
- 2026-10-23 : avec `RegFlushKey` ET l'attente de 15 s, les deux témoins retrouvés dans les secondes collections de Vista et de Windows 7 (cycles de B-036). À confirmer sur trois cycles complets de suite avant de clore.
- 2026-10-24 : série du correctif de B-036 — le témoin Run manque aussi sous Windows 11 (cliché non purgé cette fois) et encore sous Windows 7 ; trouvé sous Vista. Le vidage et l'attente ne suffisent pas : la cause reste à établir.
- 2026-10-24 : cause établie sous Windows 11, par Windows lui-même, sans WAC : valeur Run écrite et `RegFlushKey`, événement écrit, puis cliché par `Win32_ShadowCopy.Create` ; le cliché lu par son périphérique (lien symbolique temporaire), sa ruche SOFTWARE copiée avec `.LOG1`/`.LOG2` et chargée par `reg load` (qui rejoue les journaux), son `.evtx` lu par `Get-WinEvent`. Cliché 15 s après : valeur ET événement absents ; 90 s après : les deux présents. Le cliché tient ce qui est sur le disque, et Windows y écrit le registre (la ruche principale n'avait pas été écrite depuis 19 h, `RegFlushKey` ne va pas plus vite) et les journaux (le `.evtx` du cliché sans les 3 000 événements écrits deux minutes plus tôt) en retard. WAC et libvshadow lisaient juste : le témoin était trop tôt. Correctif du harnais : 120 s d'attente avant le cliché, `RegFlushKey` retiré (sans effet).
- 2026-10-26 : trois cycles complets de Windows 7 de suite avec l'attente de 120 s : les deux témoins retrouvés à chacun (valeur Run dans shadow_copy_registry.json, événement de WacShadow dans shadow_copy_events.json, absents des JSON du volume), 404 ✅ par cycle ; seuls ❌, le contrôle de version, dont les listes mesurées n'avaient pas suivi cloud_identity et intune_logs (Windows 10 et suivants) — attendu corrigé, rejoué sur les trois collectes : ✅. Fiche close.

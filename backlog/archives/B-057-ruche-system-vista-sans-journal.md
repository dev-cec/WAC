# B-057 — Ruche SYSTEM de Vista : Windows en perd la moitié sans son journal, WAC ne le rejoue pas

| Statut | Priorité | Effort |
|---|---|---|
| fait (08acc70a) | P2 | moyen |

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
- [x] Garder les ruches quand l'écart revient (`-Keep`, `hive-kept/`)
- [x] Reproduire : cinq cycles Vista (2026-10-29), plus deux le 2026-10-27 — non reproduit
- [x] Comparer cellule par cellule : sans objet, aucune ruche divergente gardée
- [x] Décider : ni rejeu ni correctif dans WAC — l'écart venait de la référence

## Journal
- 2026-10-24 : créée. Écart vu une fois, sur la série de non-régression de B-036 (qui ne touche pas au rejeu des ruches).
- 2026-10-26 : la ruche SYSTEM actuelle de Vista (séquences 2201/2201, `.LOG1` à l'ancien format, `DIRT`, 8 secteurs sales), extraite hors ligne et chargée par Windows 11 : 20 621 clés et 47 269 valeurs seule comme avec ses journaux, autant que regipy — l'écart ne se reproduit pas sur elle. Ses secteurs sales, comparés à la ruche : 7 sur 8 identiques, le 8e (en-tête du premier hbin) ne différant que par l'horodatage que Windows récrit après le vidage — un journal de même séquence porte les pages de la ruche, le rejouer ne change que cet horodatage. Hypothèse retenue, à prouver sur la ruche fautive : lecture de la ruche pendant que Vista la vidait, des pages de la ruche principale plus anciennes que celles du journal ; Windows, sans le journal, retranche les cellules incohérentes. Constat au passage : `reg load` récrit la ruche qu'il charge (11,2 Mo réorganisés en 8 Mo) — la référence travaillait déjà sur des copies. Harnais : `hive-recovery-reference.ps1 -Keep` garde, avant tout chargement, les fichiers d'une ruche dont les deux chargements diffèrent, rapatriés dans `hive-kept/` des résultats.
- 2026-10-27 : premier cycle Vista avec `-Keep` : référence vide (« the reference names no hive ») — `Get-ChildItem -File` n'existe pas sous le PowerShell 2 de Vista, le script s'arrêtait là, avant toute ligne. Corrigé (`PSIsContainer`). Cycle interrompu à la demande de l'utilisateur ; les cycles de reproduction sont à relancer.
- 2026-10-27 : deux cycles Vista (lots 1 et 2 de B-050), harnais avec `-Keep` corrigé : ruches rejouées identiques à la récupération de Windows, aucune ruche divergente gardée — non reproduite.
- 2026-10-29 : rappel de l'utilisateur, B-057 est un préalable à la publication de la 3.0.0, comme B-050. Plan : cycles Vista de reproduction après le cycle Windows 11 en cours.
- 2026-10-29 : décision de l'utilisateur : cinq cycles Vista de reproduction. Si l'écart revient, ruches gardées comparées cellule par cellule ; sinon, fiche close et archivée, l'explication (erreur de la référence, lecture pendant le vidage par Vista) consignée dans la fiche seule : rien dans la documentation, le défaut ne venant pas de WAC (précision de l'utilisateur).
- 2026-10-29 : cinq cycles Vista de reproduction (WAC de 754a59a5) : dans les cinq, la ruche SYSTEM rejouée par WAC est identique à la récupération de Windows, ruche et journaux (20 621 clés, 47 272 valeurs, condensat de chaque clé et valeur) ; aucune ruche divergente gardée. Avec les deux cycles du 2026-10-27, sept cycles sans écart. Conclusion : l'écart du 2026-10-24 venait de la référence, pas de WAC — la ruche avait été lue pendant que Vista la vidait (pages de la ruche principale plus anciennes que celles du journal) ; Windows, la chargeant sans son journal, a retranché les cellules incohérentes. La pièce prélevée était complète (regipy, 20 621 clés). Rien dans la documentation (décision de l'utilisateur). Bruit des cycles, sans rapport avec la fiche, corrigé à part (e4ffcebe) : la collecte `split` refusée dans les cinq cycles (deux fichiers laissés ouverts dans qemu-ga par un cycle interrompu le 2026-10-27, `rmdir` muet), et au cinquième un `MANIFEST.json` mal rapatrié par le harnais (lecture relancée sans son positionnement ; la copie dans la VM était conforme à son sceau). Fiche close et archivée.

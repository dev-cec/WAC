# B-022 — Prefetch : métriques absentes sur 124 fichiers sur 279

| Statut | Priorité | Effort |
|---|---|---|
| fait (e1477a0) | P2 | moyen |

## Pourquoi
Limite connue : références $MFT des fichiers chargés absentes pour 124 Prefetch ; cause non établie.

## Source
`sources/prefetchs.cpp`.

## Sortie attendue
Références présentes quand le format les porte.

## Référence indépendante
PECmd sur les mêmes fichiers (B-015).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Cause établie et documentée, ou corrigée.

## Tâches
- [x] Diagnostic par version de format (toutes en version 31 sur la VM)
- [x] Cause établie : références écrites à zéro par Windows
- [x] Découpage de la référence corrigé, contrôle contre mft.json

## Journal
- 2026-10-07 : mesure sur la collecte de la VM : 217 Prefetch sur 455 sans aucune référence, 181 partiels (15 777 références sur 32 565 fichiers chargés). Lecture indépendante du tableau décompressé (outil natif hors WAC, même décompresseur, déjà confronté à Windows) : les références y sont à zéro. Sur les 455 fichiers : un programme lancé une seule fois a toutes ses références nulles (192 sur 192) ; après d'autres exécutions, 25 fichiers restent entièrement nuls et 182 le sont en partie, surtout les entrées de drapeau 0x1 (4 559 nulles contre 1 367 renseignées), sans que le drapeau suffise à le prédire. WAC n'émet pas une référence nulle : comportement juste, documenté dans le code et le manuel.
- 2026-10-07 : recoupement avec mft.json : défaut réel trouvé — la séquence lue sur quatre octets (dont deux de l'entrée suivante, ou au-delà du bloc de références d'un volume) et les 16 bits forts de l'entrée perdus. 14 940 références fausses sur 14 975. Découpage unique `splitNtfsReference` (dix-sept copies à la main ramenées, 07a1376 puis 8dd27d7 dans conversions.h) ; contrôle check-json « références Prefetch contre la $MFT », liens physiques compris ; test unitaire vu échouer sur l'ancien découpage.
- 2026-10-07 : **Close**. Cycle complet : 451 ✅, 15 028 références identiques à la $MFT (entrée et séquence), aucune séquence fausse ; seul écart, la collecte configurée qui prenait les journaux pour `rdp_server` absent de son wac.yml — clé ajoutée au harnais (161391c), règle générale en B-042 ; cycle complet suivant entièrement vert (452 ✅, collecte configurée conforme). Commits : 07a1376, e1477a0, 8dd27d7 ; harnais 35922db, 161391c.

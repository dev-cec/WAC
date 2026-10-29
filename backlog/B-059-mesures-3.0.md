# B-059 — Comparaison à KAPE et aux outils EZ, mesure des traces et dossiers refaits sur la 3.0.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

## Pourquoi
La 3.0.0 est publiée (afd85f44) avec des dossiers dont les mesures datent de la 2.0.0 : la comparaison à KAPE et aux outils EZ et la mesure des traces sur le clone figé (9 octobre 2026), le résultat de référence de la validation (9 octobre). `bump-version.sh` avait en outre réécrit « version 3.0.0 » dans le banc d'essai de la comparaison (corrigé, 836fbad6). Demande de l'utilisateur du 2026-10-29 : recréer le banc, relancer la comparaison à KAPE, et mettre à jour toutes les documentations. L'article de la 3.0.0 (B-058) cite ces chiffres.

## Source
- Cycle complet Windows 11 avec `bin/WAC.exe` 3.0.0 (`run-wac-test.sh`).
- `ez-compare.sh` pour les 11 comparaisons (mft, events, prefetch, recent_documents, jump_lists, shellbags, shimcache, amcache, recycle_bin, srum, registry) sur les pièces de ce cycle ; `lib/timing-table.py`.
- `kape-compare.sh --no-binary` et `kape-compare.sh` (kit livré).
- Clone `win11-footprint` recréé (`footprint/prepare-footprint.sh`, Sysmon de `vmtest/tools/sysmon/download/Sysmon.zip`), `run-footprint.sh`, `footprint-diff.py`.

## Sortie attendue
Dossiers de comparaison, d'innocuité, de validation, de tests et manuels FR et EN à jour, chaque chiffre de la 3.0.0, daté ; banc d'essai disant la version mesurée.

## Référence indépendante
Les outils EZ, KAPE, Sysmon et le journal des modifications NTFS du clone, comme pour la 2.0.0.

## Critères d'acceptation
- Chaque tableau mesuré du dossier de comparaison refait sur la 3.0.0, ou retiré s'il ne se mesure plus.
- Dossier d'innocuité : imports de WAC.exe et WAC32.exe confrontés aux binaires livrés ; mesure face à KAPE de la 3.0.0.
- Documents compilés sans débordement, FR et EN parallèles.

## Tâches
- [x] `bump-version.sh` ne réécrit plus la version mesurée (836fbad6)
- [x] Innocuité : imports d'ADVAPI32 pour XP, WAC32.exe, étape 3 (Windows 11 et 8.1) — non commités
- [x] Cycle Windows 11 sur la 3.0.0 ; résultat de référence de la validation (non commité)
- [ ] 11 comparaisons EZ, tableau des temps
- [ ] KAPE, sans les exécutables et kit livré
- [x] `footprint/hive-diff.py` : ruches avant/après chaque passage, lues hors ligne (non commité)
- [ ] Clone de mesure recréé, mesure des traces (WAC, KAPE cibles, KAPE modules, outils EZ, témoin), registre compris
- [ ] Dossier de comparaison FR/EN
- [ ] Dossier d'innocuité, manuels, tests : relecture et chiffres
- [ ] Compilation des documents, 0 débordement ; commit

## Journal
- 2026-10-29 : créée. Cycle Windows 11 sur `bin/WAC.exe` 3.0.0 lancé ; le clone de mesure n'existe plus (supprimé le 2026-10-09 pour la place) : à recréer depuis win11-test, ~61 Go, 122 Go libres.
- 2026-10-29 : cycle Windows 11 sur la 3.0.0 : 550 ✅, 0 ❌. Résultat de référence de la validation repris. Traces du cycle complet relues : Prefetch, ShimCache, Amcache, SRUM attendus ; audit 4663 posé par le harnais ; RADAR (détecteur de fuites mémoire) a noté WAC.exe le 15/09 et le 15/10, jamais sur la 3.0.0 — ajouté au dossier d'innocuité. Défaut trouvé : heures locales du journal d'investigation à +00:00 avant la lecture du fuseau, corrigé (ec146f1c). Comparaisons EZ lancées.

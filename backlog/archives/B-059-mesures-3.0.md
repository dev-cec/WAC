# B-059 — Comparaison à KAPE et aux outils EZ, mesure des traces et dossiers refaits sur la 3.0.0

| Statut | Priorité | Effort |
|---|---|---|
| fait (6468cd54) | P1 | fort |

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
- [x] 11 comparaisons EZ (452b8f71 : LECmd sur tous les raccourcis, date de volume nulle du Prefetch), tableau des temps
- [x] KAPE, sans les exécutables et kit livré (189baf7e, b24d6793 ; conversion sans --binary mesurée dans la VM)
- [x] `footprint/hive-diff.py` : ruches avant/après chaque passage, lues hors ligne (non commité)
- [x] Clone de mesure recréé, mesure des traces (WAC, KAPE cibles, KAPE modules, outils EZ, témoin), registre compris
- [x] Dossier de comparaison FR/EN
- [x] Dossier d'innocuité, manuels, tests : relecture et chiffres
- [x] Compilation des documents, 0 débordement ; commit

## Journal
- 2026-10-29 : créée. Cycle Windows 11 sur `bin/WAC.exe` 3.0.0 lancé ; le clone de mesure n'existe plus (supprimé le 2026-10-09 pour la place) : à recréer depuis win11-test, ~61 Go, 122 Go libres.
- 2026-10-29 : cycle Windows 11 sur la 3.0.0 : 550 ✅, 0 ❌. Résultat de référence de la validation repris. Traces du cycle complet relues : Prefetch, ShimCache, Amcache, SRUM attendus ; audit 4663 posé par le harnais ; RADAR (détecteur de fuites mémoire) a noté WAC.exe le 15/09 et le 15/10, jamais sur la 3.0.0 — ajouté au dossier d'innocuité. Défaut trouvé : heures locales du journal d'investigation à +00:00 avant la lecture du fuseau, corrigé (ec146f1c). Comparaisons EZ lancées.
- 2026-10-29 : 11 comparaisons EZ refaites ; écarts tous tranchés (SrumECmd : 8 lignes d'énergie décalées, dissect.esedb donne raison à WAC ; RECmd : ruches ramenées à un état ancien ; AmcacheParser : 5 500 valeurs inventées). KAPE sans exécutables : 5 desktop.ini seuls chez KAPE ; WAC 196 s contre 62 s, dont 128 s de fichiers supprimés (13 318, nouveaux en 3.0). Familles et étapes nouvelles classées (189baf7e). Conversion de cette collecte dans la VM : disque plein rendu « données non valides » ; contrôle de place de la conversion et budget des fichiers supprimés dans l'estimation de la collecte (130fc924). À reprendre : section « Place nécessaire » des manuels (chiffres 2.0, et « la conversion lit la consigne » faux), dépannage « Windows 10 ».
- 2026-10-29 : KAPE refait (sans exécutables 226 s dont 156 s de fichiers supprimés, KAPE 53 s ; kit 626 s, KAPE 58 s) ; conversion sans --binary 209 s. Dossier de comparaison : synthèse, précision, temps de collecte et de conversion, pièces prélevées réécrits (non commité). Manuels : « Place nécessaire » refaite (non commité). Clone win11-footprint recréé (win11-test BitLocker « protection désactivée », clé en clair : hive-diff.py ouvre le volume par dissect.fve 4.6, installé dans target-venv) ; Sysmon 15.22 ; prepare-footprint.sh corrigé (feaea918). Mesure des traces lancée. À faire après le banc (il recopie bin/ à chaque exécution) : message « antérieur à Windows 10, première version que le cycle éprouve » faux depuis la 3.0 (VALIDATED_SINCE_BUILD, main.cpp), et la phrase « version 2 éprouvée sous 10 et 11 » des manuels.
- 2026-10-30 : mesure des traces faite (clone recréé, registre relu hors ligne) ; elle a trouvé l'ouverture des processus en accès complet par Toolhelp, corrigée (9cf4642d) et remesurée. Cycle Windows 11 553 ✅ / 0 ❌ ; Vista (WAC32, processus) 30 ✅ / 0 ❌. Dossiers refaits et commités (6468cd54), version 3.0.1 (5232ed95). Fiche close.

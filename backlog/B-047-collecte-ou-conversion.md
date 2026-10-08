# B-047 — Collecte ou conversion, jamais les deux : suppression du mode --full

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Convention des analyses forensiques (décision utilisateur 2026-10-08) : la machine examinée ne sert qu'à prélever ; tout traitement — décodage, rejeu de journaux, conversion en JSON — se fait ailleurs, sur la copie de travail. Le mode `--full` (et `convert: true` dans wac.yml) faisait les deux sur la machine examinée. Question posée par le rejeu des journaux ESE (B-046), qui aurait chargé esent.dll sur la machine examinée.

## Source
`main.cpp` (options, déroulé), `config.cpp` (clé `convert`), `tools.h` (`RunMode`), `translations.cpp` (aide), `sources/wac.yml`, le harnais (`run-wac-test.sh`, étape 4 et la collecte configurée), les documents (manuels, comparaison, innocuité, validation, README).

## Sortie attendue
`WAC.exe` (ou `--collect`) collecte ; `WAC.exe --convert=<dossier>` convertit ; plus de `--full` ni de clé `convert`.

## Référence indépendante
Cycle VM complet : collecte, puis conversion séparée, contrôles inchangés.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune mention d'une conversion sur la machine examinée dans le code, l'aide, wac.yml et les documents.

## Tâches
- [ ] Code (options, configuration, déroulé), aide FR/EN
- [ ] Harnais
- [ ] Documents FR/EN
- [ ] Cycle VM

## Journal
- 2026-10-08 : décision utilisateur, en cours.

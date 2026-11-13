# B-075 — Documentation de la 5.0.0 à jour et article de la 5.0.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Demande de l'utilisateur (2026-11-08) : avant de publier la 5.0.0, toute la documentation est remise à jour et un article de la 5.0.0 est écrit, comme pour la 4.0.0 (B-061). À la clôture de la 4.0.0, une relecture document par document a trouvé des retards qu'aucune fiche n'avait relevés : README sans les rôles, dossier de validation encore sur la 3.0.1, douze harnais de test sans section, couverture ATT&CK sans les nouveaux artefacts, section des limites de l'article dépassée. Cette fiche en fait une étape à part, après la revue, sur le code qui sera livré.

## Ordre
Après B-074 (la revue peut changer le code et ses limites), avant `bump-version.sh --major`, le push et la release.

## Périmètre
Chaque document, relu en entier, pas seulement les passages touchés par une fiche :
- `README.md` (racine) ;
- manuels `doc/user/documentation_FR|EN` : `wac.yml` montré identique à celui de `bin/` (clé à clé), artefacts, limites ;
- guide des tests `doc/tests/testing_FR|EN` : une section par harnais de test (`sources/*_test.*`), chiffres de référence remesurés ;
- dossier de validation `doc/validation/validation_FR|EN` : résultat de référence = série finale de la 5.0.0 ;
- dossier d'innocuité `doc/harmlessness/harmlessness_FR|EN` : nouveaux chemins lus, témoins ;
- dossier de comparaison `doc/comparison/comparison_FR|EN` : ce que la 5.0.0 change face à KAPE ;
- tableaux générés : `doc/artefact-table.py` (depuis le catalogue) et `doc/attack-coverage.py` (même fichier ATT&CK, `vmtest/tools/attack`, empreinte vérifiée ; correspondances des nouveaux artefacts décidées) ;
- `doc/BUILD_FR|EN.md`, `vmtest/README.md` et `README_FR.md` ;
- documentation du code (`doc/html`, Doxygen) régénérée.

## Sortie attendue
- Documents FR et EN à jour, PDF régénérés, 0 Overfull.
- **Article de la 5.0.0** (`doc/article/article_FR_5.0.tex`, `article_EN_5.0.tex`), sur le modèle des articles 3.0 et 4.0 : une page, les nouveautés seules, chaque chiffre tiré des dossiers de validation, d'innocuité et du backlog ; section des limites relue contre le dossier de validation.

## Référence indépendante
Contrôles mécaniques plutôt que relecture seule : clés de `wac.yml` des manuels comparées à `bin/wac.yml` ; liste des `*_test` comparée aux sections du guide des tests ; recherche des versions et formulations provisoires (« en préparation », numéro de version antérieur hors mesures datées) ; tableaux régénérés et comparés ; nombre de pages de l'article.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque document du périmètre relu et à jour, ou l'écart dit.
- Article FR et EN d'une page, chiffres sourcés, 0 Overfull.
- Les PDF joints à la release de la 5.0.0 avec les binaires.

## Tâches
- [x] Contrôles mécaniques (clés, tests, versions, tableaux)
- [x] Le fuseau en vigueur au fil du temps (B-077) dans les manuels et le dossier de validation : `Host.SuspectTimeZone.History`, `ChangesAtUnknownInstant`, `TimeZoneInForce`, `TimeZoneChangedBetween` ; sources par version de Windows (Kernel-General 22/24 depuis Windows 10 ; 6013, 20001 et Kernel-General 1 avant) ; journal Système et journal TZUtil prélevés à chaque collecte
- [ ] Relecture et mise à jour de chaque document
- [ ] Article de la 5.0.0, FR et EN
- [ ] PDF régénérés, 0 Overfull
- [ ] PDF joints à la release

## Journal
- 2026-11-08 : créée à la demande de l'utilisateur, après la revue B-074 et avant la publication de la 5.0.0.
- 2026-11-13 : contrôles mécaniques. Clés de `wac.yml` : les 99 de `bin/wac.yml` dans la copie des manuels FR et EN (il manquait `application_registry` et les onze groupes de traces). Harnais : `application_traces_test`, `application_trace_files_test`, `time_zone_history_test` sans section dans le guide des tests, ajoutées (1 450, 65 et 49 contrôles). Versions : « 4.0.0 » ne reste qu'aux places que `bump-version.sh` réécrit, et dans les mesures datées. Tableaux : `artefact-table.py` traduit les textes des douze nouveaux artefacts (99 artefacts, 153 formes) ; `attack-coverage.py` les rattache (journaux d'applications, connexions, sessions, transcriptions PowerShell, stockage en ligne), 476 techniques sur 479 comme avant. Relu et mis à jour : manuels (sous-section des traces d'applications, `sec:fuseaux` ; le fuseau au fil du temps y était déjà), guide des tests, dossier de validation (contrôles des traces et du harnais, robustesse de la 5.0), dossier d'innocuité (mesure de la série de la 5.0.0), comparaison avec KAPE (encadré : les traces prises et converties, comparaison non refaite), README, README du harnais. Tous les PDF à 0 Overfull. Article de la 5.0.0 écrit en FR et EN, une page chacun ; à compléter du nombre de contrôles du cycle Windows 11 de validation. Reste : le résultat de référence du dossier de validation, `doc/html`, les PDF joints à la release.

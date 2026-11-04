# B-061 — Article de la 4.0.0 : la suite de l'article de la 3.0.0, les nouveautés seules

| Statut | Priorité | Effort |
|---|---|---|
| fait (voir le journal) | P3 | faible |

## Pourquoi
Demande utilisateur du 2026-11-04 : un article pour la 4.0.0, et tous les articles commités (ceux de la 3.0 ne l'étaient pas). Même forme que ceux de la 2.0 (B-018) et de la 3.0 (B-058).

## Sortie attendue
`doc/article/article_FR_4.0.tex`, `article_EN_4.0.tex` et leurs PDF, une page, 0 débordement.

## Référence indépendante
Chaque chiffre recoupé avec sa source : cycles et mesures de B-038, B-035 et B-041, dossiers de validation et d'innocuité, 83 clés sous `artefacts:` de `sources/wac.yml`.

## Journal
- 2026-11-04 : écrit à la demande de l'utilisateur **avant** le passage du numéro de version : `sources/WAC.rc` est encore en 3.0.1 alors que l'article annonce la 4.0.0, et il n'est pas encore publié. Le nombre de contrôles et les mesures sont à reprendre si la revue B-060 change le code. Les cycles serveurs autres que le contrôleur et Server 2022 datent du 31 octobre, avant `web_server` et `active_directory` ; l'article dit la période.

# B-052 — Couverture MITRE ATT&CK des traces prélevées

| Statut | Priorité | Effort |
|---|---|---|
| à faire (avant de clore la 3.0) | P1 | fort |

## Pourquoi
Demande utilisateur du 2026-10-17 : avant de clore la 3.0, vérifier dans MITRE ATT&CK que toutes les traces utiles à la détection sont bien prélevées par WAC. ATT&CK décrit, technique par technique, les sources de données qui permettent de la détecter (Data Sources et Data Components : création de processus, modification de clé de registre, création de tâche planifiée, connexion d'ouverture de session…) ; c'est une liste indépendante de WAC, contre laquelle sa couverture se mesure sans se juger elle-même.

## Source
La matrice Enterprise d'ATT&CK, plateforme Windows, dans sa version publiée (STIX, dépôt `mitre-attack/attack-stix-data`, version citée et figée) : techniques et sous-techniques, leurs Data Components et les artefacts Windows qui les portent.

## Sortie attendue
- Pour chaque technique Windows : les traces sur disque qui permettent de la détecter ou d'en établir l'usage, et pour chacune l'artefact de WAC qui la prélève (clé de `wac.yml`, fichier JSON), ou son absence.
- Les traces manquantes : soit ajoutées (fiche par ajout, avant la 3.0 si utiles à la détection), soit écartées avec leur raison (trace seulement vivante — mémoire, réseau en cours —, hors du périmètre d'une collecte sans trace, etc.).
- **Le résultat dans la documentation** (demande utilisateur) : un tableau de couverture ATT&CK dans les manuels FR et EN — technique, trace, artefact WAC, couvert ou non et pourquoi —, la version d'ATT&CK citée.

## Partage avec WAE
Décision utilisateur du 2026-10-17 : WAC prélève et convertit ; **tout ce qui relève de l'analyse des pièces (les JSON)** — règles de détection par technique, rapprochements entre artefacts, chronologie, scores — revient à **WAE**. Chaque besoin d'analyse que la vérification fait apparaître est consigné, pour le moment, dans `WAE/TODO.txt` (technique ATT&CK, JSON de WAC concernés, ce qu'il faut y chercher) ; seules les traces absentes de la collecte donnent des fiches dans ce backlog.

## Référence indépendante
ATT&CK lui-même (données STIX officielles) ; le tableau est produit depuis ces données et la table des artefacts de WAC, pas écrit à la main, pour pouvoir être refait à la version suivante.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque technique Windows d'ATT&CK a une ligne ; aucune trace « utile à la détection » n'est laissée sans décision.
- Le tableau figure dans la documentation FR et EN, version d'ATT&CK et date citées.

## Tâches
- [ ] Récupérer les données ATT&CK (version figée, empreinte notée)
- [ ] Rapprocher Data Components et artefacts de WAC
- [ ] Traces manquantes : fiches d'ajout ou raisons d'écart
- [ ] Besoins d'analyse (détection sur les JSON) consignés dans `WAE/TODO.txt`
- [ ] Tableau de couverture dans les manuels FR et EN

## Journal
- 2026-10-17 : créée à la demande de l'utilisateur — à faire avant de clore la 3.0 ; le résultat va dans la documentation.
- 2026-10-17 : décision utilisateur — ce qui relève de l'analyse des JSON va dans WAE (`WAE/TODO.txt` pour le moment) ; ici, seulement les traces à prélever.

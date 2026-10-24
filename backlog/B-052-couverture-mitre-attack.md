# B-052 — Couverture MITRE ATT&CK des traces prélevées

| Statut | Priorité | Effort |
|---|---|---|
| en cours (avant de clore la 3.0) | P1 | fort |

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

## Décisions (utilisateur, 2026-10-24)
- Pas de test en VM pour cette fiche : l'analyse du code suffit.
- Le tableau de couverture va dans les manuels FR et EN **et** dans l'article de la 3.0.0 (B-058).
- Les traces manquantes sont ajoutées dans cette fiche (pas de fiche par ajout).
- Ce qui relève des serveurs (IIS, AD FS, contrôleur de domaine, DHCP…) est fait dans la 4.0.

## Prélèvements à ajouter (traces sur le disque que WAC ne prend pas)
1. Journal du pare-feu (`System32\LogFiles\Firewall\pfirewall.log`, chemin lu dans la politique du pare-feu) : seule trace de flux réseau sur le disque — « Network Traffic Flow », « Network Connection Creation ».
2. Démarrage : fichiers de la partition système EFI (sans lettre, FAT lue en brut) avec leurs empreintes, MBR et premier secteur de chaque volume — bootkits (T1542).
3. Fichiers ETW écrits par les sessions configurées pour le disque (`.etl` de `System32\LogFiles\WMI`, `LogFiles\Sum`…), pris bruts.
4. Journaux Intune / MDM (`ProgramData\Microsoft\IntuneManagementExtension\Logs`) — T1098.005.
5. Traces locales des services en nuage : inscription Entra ID (`CloudDomainJoin`, `AAD`), journaux OneDrive (`.odl`) et Teams, cache du TokenBroker — à étudier.
6. Defender for Endpoint, s'il est installé : son dossier local — à étudier (chiffré ?).

Hors de portée d'un prélèvement sur disque : contenu réseau et DNS en vol, journaux d'audit du locataire M365/Azure/AWS, télémétrie d'un EDR tiers, comportement d'un modèle d'IA ; rôles serveur en 4.0.

## Tâches
- [x] Récupérer les données ATT&CK (version figée, empreinte notée) : Enterprise 20.0 du 2026-10-13, SHA-256 81113BA9…5352 (`vmtest/tools/attack`, non versionné)
- [x] Rapprocher Data Components et artefacts de WAC (`doc/attack-coverage.py`)
- [ ] Prélèvements 1 à 6 ci-dessus
- [ ] Besoins d'analyse (détection sur les JSON) consignés dans `WAE/TODO.txt`
- [x] Tableau de couverture dans les manuels FR et EN (section « Couverture de MITRE ATT&CK », produite par `doc/attack-coverage.py`) ; dans l'article : B-058

## Journal
- 2026-10-17 : créée à la demande de l'utilisateur — à faire avant de clore la 3.0 ; le résultat va dans la documentation.
- 2026-10-17 : décision utilisateur — ce qui relève de l'analyse des JSON va dans WAE (`WAE/TODO.txt` pour le moment) ; ici, seulement les traces à prélever.
- 2026-10-24 : ATT&CK 20.0 lu : depuis la 18, une technique est détectée par des stratégies faites d'analytiques, chacune nommant ses sources (composant de données, source de journal). `doc/attack-coverage.py` décide une fois chaque source de journal (un journal d'événements Windows est pris quel qu'en soit le canal, même déplacé) et chaque composant (artefacts qui en gardent la trace sur le disque) ; une source ou un composant non décidé arrête le script. 479 techniques et sous-techniques Windows : 475 avec au moins une trace prélevée, 4 dont toutes les sources sont hors du disque, 6 sans analytique Windows décidées d'après la technique. Écarts : journal du pare-feu, journaux Intune ; puis, à la demande de l'utilisateur, la liste des prélèvements à ajouter ci-dessus.
- 2026-10-24 : tableau dans les manuels : décisions par source de journal et par composant, puis une ligne par technique (trace dans un journal, trace sur le disque, sources non prises) — la liste des artefacts par technique faisait 57 pages ; 15 pages ajoutées, 0 débordement.

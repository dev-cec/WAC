# B-058 — Article de la 3.0.0 : la suite de l'article de la 2.0.0, les nouveautés seules

| Statut | Priorité | Effort |
|---|---|---|
| fait (22566c5c) | P3 | moyen |

## Pourquoi
Demande utilisateur du 2026-10-24 : un article pour la 3.0.0, écrit **après sa publication**. Il fait suite à l'article de la 2.0.0 (B-018, `doc/article/article_FR_2.0.tex` et `article_EN_2.0.tex`) : il ne reprend **que les nouveautés** de la 3.0.0, sans redire ce que le premier article présentait (principe de la collecte sans trace, prélèvement brut, consigne scellée, séparation collecte et conversion…), auquel il renvoie.

## Source
- L'article de la 2.0.0 : ce qu'il a déjà dit, à ne pas répéter.
- Les fiches closes entre la 2.0.0 et la 3.0.0 (`backlog/archives/`) et l'historique Git entre les deux étiquettes : ce qui est nouveau.
- Les dossiers de validation, d'innocuité, de tests et de comparaison de la 3.0.0 : les chiffres, datés.

## Nouveautés à couvrir (à confirmer à la rédaction, d'après les fiches)
- Tous les clients, de Windows XP SP1 à Windows 11, et le harnais qui les teste (XP au clavier, Vista par l'agent).
- Les clichés instantanés lus en brut, sans le service VSS : ruches et journaux tels que chaque cliché les gardait.
- Les fichiers supprimés : $MFT, index $I30, carving (PE, ZIP, PDF), volumes FAT et exFAT — et ce qu'un SSD avec TRIM ne rend plus.
- Sysmon (configuration, archives) et les journaux d'événements déplacés.
- La couverture MITRE ATT&CK des traces prélevées (B-052) : **son tableau de couverture figure dans l'article** (décision utilisateur du 2026-10-24), produit par `doc/attack-coverage.py` — dans une forme résumée si la place manque, le tableau complet restant dans les manuels.
- Les autres artefacts ajoutés depuis la 2.0.0 (liste tirée de la table des artefacts).

## Sortie attendue
Article FR et EN (`doc/article/article_FR_3.0.tex`, `article_EN_3.0.tex`, et leurs PDF), même forme que celui de la 2.0.0, qui y renvoie dès son chapô.

## Référence indépendante
Relecture par un tiers ; chaque chiffre recoupé avec le dossier dont il vient.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune redite de l'article de la 2.0.0 hors d'un renvoi.
- Chiffres cités tirés des dossiers de la 3.0.0, datés.
- Écrit après la publication de la 3.0.0 : la version décrite est celle publiée.

## Tâches
- [x] Relire l'article de la 2.0.0 : liste de ce qu'il a déjà dit
- [x] Liste des nouveautés de la 3.0.0 (notes de version, fiches closes)
- [x] Rédaction FR et EN, chiffres datés (non commités : fichiers de l'utilisateur)
- [x] Relecture (utilisateur, 2026-10-30)

## Journal
- 2026-10-24 : créée à la demande de l'utilisateur — après la publication de la 3.0.0 ; suite de l'article de la 2.0.0, nouveautés seules.
- 2026-10-29 : 3.0.0 publiée (tag sur afd85f44, release GitHub avec les 9 fichiers de bin/, vérifiés). Rédaction lancée à la demande de l'utilisateur, FR et EN.
- 2026-10-30 : `doc/article/article_FR_3.0.tex` et `article_EN_3.0.tex` écrits et compilés (une page chacun, 0 débordement), chapô renvoyant à l'article de la 2.0. Nouveautés : XP SP1 à 11 (WAC32), table par version, clichés instantanés sans VSS, fichiers supprimés (12 529 récupérés en 156 s, TRIM), onze artefacts (80 contre 69), ATT&CK résumé (475/479 : 463 journaux et disque, 7 journaux, 5 disque, 4 aucune), sceau au procès-verbal, mesure des traces des 29 et 30 octobre (0 fichier, 0 valeur, ruches relues ; ouverture en accès complet trouvée et corrigée, 9cf4642d), 550 contrôles sous Windows 11. Reste la relecture par l'utilisateur ; le nombre de contrôles à confirmer par le cycle Windows 11 en cours.
- 2026-10-30 : relecture validée par l'utilisateur. Reste à confirmer le nombre de contrôles du cycle Windows 11 en cours, puis archiver.
- 2026-10-30 : cycle Windows 11 : 553 contrôles, repris dans l'article. Fiche close ; les fichiers de l'article restent hors du dépôt.

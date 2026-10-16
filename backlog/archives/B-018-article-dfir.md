# B-018 — Article de présentation (2 pages, magazine DFIR)

| Statut | Priorité | Effort |
|---|---|---|
| fait (ea0222d8, 36b7001a) | P3 | moyen |

## Pourquoi
Faire connaître et relire WAC par des pairs : c'est aussi la meilleure validation externe.
À faire après la version 2.0.0 (B-025) et avant la version 3.0 (rétrocompatibilité, B-037, B-038, B-039).

## Source
Dossiers de validation et d'innocuité, mesures du cycle VM.

## Sortie attendue
Article FR et EN.

## Référence indépendante
Relecture par un tiers.

## Modèles relevés (2026-10-09)
Deux supports possibles, de format très différent.

**MISC (Éditions Diamond), en français.** Revue de sécurité offensive et défensive, rubrique « Forensic ». Modèle le plus proche : « Collecte d'artefacts en environnement Windows avec DFIR-ORC », Quentin Lemaire, MISC HS n° 23 (février 2021), <https://connect.ed-diamond.com/MISC/mischs-023/collecte-d-artefacts-en-environnement-windows-avec-dfir-orc>. Autre : « Forensic Corner : Windows Shellbags », Cédric Pernet, MISC n° 61 (mai 2012).
- Forme : titre, **chapô** de 4 à 6 phrases (le problème du praticien, puis ce que l'outil y répond, puis ses limites — « ORC n'effectue pas d'analyse »), puis des parties numérotées (« 1. Présentation », « 2. Intérêt… »).
- Ton : technique et direct, « nous » de l'auteur ou impersonnel, une interpellation du lecteur pour l'exemple ; on part d'un cas concret du métier.
- Longueur : pas de gabarit imposé (« un article d'une page sur CFS serait frustrant, un de 12 pages sur pico soporifique ») ; sujet, plan ou brouillon proposés à la rédaction, relecture technique et deux relectures de langue ; publication rémunérée. Les articles du genre font plusieurs pages, plus que 2.

**DFIR Review (DFRWS), en anglais.** Revue à comité de lecture rapide, pour des travaux de praticiens déjà publiés en blog ; DOI attribué ; soumission mensuelle (EasyChair), fichier .docx ; relecteurs non anonymes, leurs avis publiés avec l'article. Modèles : « Is that Windows Notepad window really empty? » (ogmini, 2024, ~3 700 mots) ; « Validation of X-Ways Forensics Evidence File Containers » (L. Jones, 2021).
- En-tête obligatoire : **Synopsis**, **Forensics Question** (la question à laquelle l'article répond), **OS Version**, **Tools** (versions).
- Corps : Background, puis le fond (artefacts, formats, tests), Scenarios / validation, Conclusion ; les relecteurs ajoutent « DFIR Review » et « Future Work ».
- Grille de relecture : contenu et organisation 60 %, usage des sources 30 %, langue 10 % ; la meilleure relecture est une **validation sur des données que le relecteur produit lui-même** — d'où l'intérêt de livrer le banc et ses jeux de données.
- Pas de limite de longueur ; un format « 2 pages » n'existe pas ici.

Conséquence pour WAC : l'angle « question du praticien » (que garantit une collecte : rien d'écrit, chaque valeur juste, chaque écart tranché) convient aux deux ; les chiffres viennent des dossiers de comparaison, de validation et d'innocuité, datés.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chiffres cités tirés des dossiers, datés.

## Tâches
- [x] Plan : chapô ; ce qui est prélevé ; une procédure respectée (consigne scellée, journal d'investigation) ; du JSON ; aucune trace, mesurée ; des tests qui savent échouer ; en chiffres ; disponibilité
- [x] Rédaction : `doc/article/article_FR.tex` et `article_EN.tex`, une page A4 à deux colonnes chacune, compilées par `doc/build-docs.sh`
- [x] Relecture : article validé par l'utilisateur

## Journal
- (vide)
- 2026-10-07 : décision utilisateur — l'article suit la montée en 2.0.0 et précède la rétrocompatibilité, qui fera la version 3.0.
- 2026-10-09 : modèles d'articles relevés (MISC, DFIR Review) ; à décider : le support visé, qui fixe la longueur — « 2 pages » ne correspond à aucun des deux.
- 2026-10-12 : décision utilisateur — FR et EN, une page ; mettre en avant les artefacts prélevés, la conversion JSON, l'absence de trace, les tests, et le respect de la procédure (consigne, journal des actions). Premier jet écrit, chiffres repris des dossiers (mesures du 9 octobre, version 2.0.0). Reste la relecture.
- 2026-10-16 : l'utilisateur déclare l'article validé « pour le moment » ; fiche close et archivée. Les fichiers de l'article sont tenus par l'utilisateur (renommés `article_*_2.0.*`).

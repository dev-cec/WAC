# B-039 — Artefacts organisés par version de Windows et par disponibilité

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | moyen |

## Pourquoi
Chaque artefact n'existe que sur certaines versions de Windows, à un emplacement et dans un format qui changent d'une version à l'autre : `.evt` puis `.evtx`, Prefetch v17 puis v30, `index.dat` puis WebCache, Chronologie sous Windows 10 seulement, SRUM et Amcache depuis 8, jump lists depuis 7, index de recherche en ESE puis en SQLite. Aujourd'hui, cette connaissance est dispersée dans le code de chaque collecteur. Demande utilisateur du 2026-10-06 : réorganiser les artefacts par version et disponibilité. Prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP) ; B-038 (versions serveur) s'appuie aussi sur elle.

Elle doit surtout **faciliter l'arrivée des prochaines versions de Windows et des nouveaux formats d'artefacts** (demande utilisateur du 2026-10-06) : Windows change un format (Chronologie retirée de 11, index de recherche passé d'ESE à SQLite) sans prévenir, et chaque changement ne doit coûter qu'un ajout localisé, pas une reprise de chaque collecteur.

## Source
Le code de chaque collecteur, les fiches archivées et leurs mesures, la documentation publique des formats.

## Sortie attendue
- Une table unique, dans le code et dans la documentation FR et EN : pour chaque artefact (clé de `wac.yml`), les versions de Windows client et serveur où il existe, son emplacement et son format selon la version, et son absence en Server Core.
- WAC détermine la version de la machine examinée, et pour un artefact absent de cette version émet un `CollectionStatus` qui le dit (absent de cette version, et non échec ni zéro trouvé).
- Le format attendu est choisi d'après la version, ou reconnu sur la pièce quand la version ne suffit pas.
- **Ajouter une version de Windows** = ajouter ses lignes à la table (disponibilité, emplacement, format) ; **ajouter un format** = un décodeur enregistré pour ce format, reconnu par sa signature ou sa version interne. Aucune autre modification dispersée.
- **Une version inconnue** (plus récente que la table) n'empêche pas la collecte : elle est traitée comme la dernière version connue, et signalée comme telle dans le journal d'investigation et le `CollectionStatus`.
- **Garde-fou avant tout prélèvement** (demande utilisateur du 2026-10-06) : un artefact coché dans `wac.yml` alors qu'il n'existe pas sur la version examinée n'est ni lancé ni compté en échec. WAC vérifie sa présence avant de le prélever — d'abord la table (l'artefact existe-t-il sur cette version ?), puis la machine (sa source est-elle là ?) —, l'annonce dès le début de la collecte (console et journal d'investigation) et l'inscrit dans le `CollectionStatus`. Deux cas distingués, car ils ne disent pas la même chose :
  - **absent de cette version** : normal, rien à signaler à l'analyse (ex. Chronologie sous Windows 11, SRUM sous XP) ;
  - **attendu sur cette version mais introuvable** : anormal, signalé comme tel — une source effacée ou un service désactivé est lui-même une trace (ex. Amcache.hve absent d'un Windows 10).
- **Un format inconnu** (nouvelle version interne d'un fichier, schéma de base changé) est reconnu comme tel : la pièce est collectée brute, le JSON dit « format non pris en charge » avec la version rencontrée, jamais une conversion fausse ni un silence.

## Référence indépendante
Les VM de B-037 et B-038 : sur chacune, chaque artefact est soit collecté, soit déclaré absent conformément à la table, jamais en échec.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque clé de `wac.yml` figure dans la table.
- Aucun collecteur ne garde pour lui seul une condition de version que la table ne porte pas.
- Garde-fou démontré : sur une VM d'une version où un artefact coché n'existe pas, il n'est pas lancé, et il est déclaré « absent de cette version » ; une source attendue retirée d'une VM est déclarée « attendue mais introuvable ».
- Démontré par l'exemple : une version fictive ajoutée à la table et un format interne inconnu présenté à un décodeur (test unitaire) — la première est collectée comme la dernière connue et signalée, le second est collecté brut et déclaré non pris en charge.

## Tâches
- [x] Inventaire, par artefact, des versions, emplacements et formats : 69 artefacts, 113 formes, de XP à Windows 11 et Server 2025
- [x] Table dans le code (`artefact_catalogue.cpp`, portable) et dans les manuels FR et EN, générée par `doc/artefact-table.py` depuis l'export du test (le script refuse un texte sans traduction française)
- [x] Détection de la version de la machine examinée dans la ruche SOFTWARE copiée (`readExaminedVersion`) : build, serveur, Server Core
- [x] `CollectionStatus` `AbsentFromThisVersion`, avec la version et le build
- [x] Garde-fou avant prélèvement, côté table (`applyArtefactCatalogue`, décision `absentAmong` testée nativement) : annoncé en console, consigné au journal, artefact ni lancé ni compté en échec
- [x] Garde-fou côté machine : « attendu mais introuvable » (`expectedOn`, `reportUnread`, statut `ExpectedButMissing` avec la version, le build et l'emplacement attendu ; console et journal de conversion) — éditions client, les serveurs restant à mesurer
- [x] Repli d'une version inconnue sur la dernière connue, signalé (console, journal ; test : build 31000)
- [ ] Reconnaissance des formats par signature ou version interne ; « format non pris en charge » avec la pièce brute
- [x] Guide « ajouter une version de Windows / un format » (doc/BUILD_FR.md et BUILD_EN.md), test décrit dans le guide des tests
- [ ] Conditions de version encore portées par des collecteurs, à ramener à la table (Prefetch < 30 refusé dans prefetchs.cpp, ShimCache « 10ts », etc.)

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur — prérequis de B-035 (web côté serveur) et de B-037 (compatibilité XP).
- 2026-10-06 : objectif précisé par l'utilisateur — la fiche doit faciliter l'arrivée des prochaines versions de Windows et des nouveaux formats d'artefacts.
- 2026-10-06 : demande utilisateur — garde-fou vérifiant la présence d'un artefact avant de le prélever, pour un artefact coché dans `wac.yml` qui n'existe pas sur la version examinée.
- 2026-10-07 : décision utilisateur — version 3.0 ; prérequis aussi de B-041 (Active Directory).
- 2026-10-13 : démarrage (version 3.0). Choix : un module portable `artefact_catalogue` (table unique : clé, première et dernière version par numéro de build, formes successives — emplacement, format, décodé ou non par WAC —, source attendue). L'ordre des versions est celui des builds (2600 XP < 3790 Server 2003 < 6000 Vista < 7600 < 9200 < 9600 < 10240… < 22000 Windows 11), client et serveur confondus. Règle de prudence : une absence n'est déclarée que si elle est certaine — une absence à tort perd une pièce, une présence à tort ne coûte qu'un « attendu mais introuvable » ; Server Core et les cas douteux restent « présents », à valider dans les VM de B-037 et B-038. Constat mesuré : ActivitiesCache.db existe toujours sous Windows 11 (build 26200, 3 lignes lues) — la table ne le retire pas.
- 2026-10-13 : premier incrément écrit. Test natif `artefact_catalogue_test` : 722 contrôles (clés identiques à wac.yml, formes ordonnées, cas connus, garde-fou sous Windows 7 = 5 artefacts écartés — Chronologie, BAM, Defender, PSReadLine, SRUM —, sous XP 14, sous Windows 11 aucun ; version fictive 31000 traitée comme la dernière connue et signalée) ; vu échouer avec SRUM déclaré présent depuis XP. Banc : `reference/windows-version.txt` (build et type que Windows donne de lui-même) confronté à la version que WAC consigne — cycle court vert (Windows 11, build 26200, aucun artefact écarté). La démonstration sur une VM d'une version ancienne attend B-037 : WAC refuse encore de se lancer sous Windows 10. Cycle complet lancé.
- 2026-10-13 : cycle complet en machine virtuelle (Windows 11, build 26200) : 494 contrôles réussis, version examinée lue et consignée dans les deux collectes, aucun artefact écarté. Un seul échec, étranger à la fiche : 5 références `$MFT` de Prefetch dont la séquence n'était pas celle de l'enregistrement. Cause établie par le journal USN : les fichiers ont été supprimés depuis (version de Chrome retirée par sa mise à jour, EdgeUpdate, image de l'écran de verrouillage), sous la séquence même que porte le Prefetch ; NTFS relève la séquence d'un enregistrement qu'il libère. Règle ajoutée au contrôle (enregistrement supprimé : séquence moins un ; un fichier en service l'emporte sur un enregistrement supprimé du même chemin), rejouée sur les deux collectes du cycle : verte. Premier incrément commité.
- 2026-10-13 : « attendu mais introuvable » écrit. Décision portable `expectedOn(clé, version)` ; côté WAC, `reportUnread` remplace `writeNotCollected` dans `convertArtefact` et pour les tâches planifiées : source introuvable + source toujours présente sur la version = statut `ExpectedButMissing`, annoncé en console et consigné. Prudence appliquée à la liste des sources « toujours présentes » : retirés USBSTOR et les périphériques (la clé n'existe qu'après un premier branchement), les partages réseau, les états du système en marche (processus, sessions, connexions) et les métafichiers du volume ($MFT, $LogFile, $Secure, $Boot) — non lus, ce sont des lectures ratées, jamais des traces. Limite assumée et écrite dans la note du JSON : la conversion sait que la collecte scellée ne contient pas la source ; que la machine ne l'avait pas se lit dans `investigation.json` (extraction du dossier consignée avec son résultat). Test natif : 730 contrôles, vu échouer (serveur attendu, USBSTOR attendu). Harnais : étape 9, fichier `hosts` écarté le temps d'une collecte de ce seul artefact puis remis ; référence indépendante = manifeste de la consigne (4 autres fichiers du dossier, aucun `hosts`) ; cycle court vert, contrôle vu échouer sur une collecte ordinaire ; VM vérifiée après coup (fichier remis, rien laissé). Manuels FR et EN (section « Source attendue mais introuvable »), guide des tests, guide BUILD, tableau régénéré.

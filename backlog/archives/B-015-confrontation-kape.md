# B-015 — Confrontation à KAPE et aux outils Zimmerman

| Statut | Priorité | Effort |
|---|---|---|
| fait (e5fa138 ; comparaisons 594a700 à 951837b) | P1 | moyen |

## Pourquoi
Mesure indépendante de la couverture (quels fichiers KAPE prend que WAC ne prend pas) et de la justesse des JSON (MFTECmd, EvtxECmd, RECmd, PECmd… sur les mêmes pièces).

## Source
Collecte KAPE !SANS_Triage de la VM de test, au même instant qu'une collecte WAC.

## Sortie attendue
Rapport de couverture et d'écarts ; contrôle automatisable dans check-json si possible. Rendu : dossier `sources/doc/comparison/comparison_FR/EN` (temps, précision, formats).

## Référence indépendante
C'est elle-même la référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque écart de couverture classé : ajouté au backlog ou écarté avec sa raison.
- Chaque écart de valeur expliqué ou corrigé.

## Tâches
- [x] Installer KAPE et les outils EZ sur la VM (vmtest/install-tools.sh, .NET 9.0.20)
- [x] Collectes successives WAC puis KAPE, chronométrées (vmtest/kape-compare.sh)
- [x] Comparaison fichiers et empreintes : 1 130 fichiers communs, SHA-1 identiques sauf ceux écrits entre les deux collectes ; couverture manquante : B-032 ; temps : B-033
- [x] Comparaison des JSON (vmtest/ez-compare.sh <clé> : temps et écarts, vmtest/lib/ez-compare.py) :
  - [x] mft.json / MFTECmd : 362 081 enregistrements, 8 dates, chemins, états identiques ; tailles : 1 490 WOF et 3 EVTX où WAC a raison (Windows), 5 métafichiers de convention. A révélé la fusion d'extensions périmées (fix).
  - [x] events.json / EvtxECmd : 190 613 événements, champs système identiques ; valeurs EventData expliquées (conventions d'EvtxECmd, chacune vérifiée contre le XML de Windows ; FILETIME nul non émis par WAC) ; 6 erreurs d'EvtxECmd confirmées par Windows ; 335 Perflib lus par WAC et Windows, pas par EvtxECmd. A révélé 4 défauts de rendu (flottants, binaire, ProcessingErrorData ignoré, hexa/GUID) et les événements des journaux vidés (EvtRecovered).
  - [x] prefetchs.json / PECmd (--mp) : 379 fichiers, exécutable, compteur, 8 exécutions, volumes, répertoires et fichiers chargés identiques ; 19 empreintes où PECmd retire le zéro de tête (WAC comme le nom du fichier) ; un .pf entièrement nul, rejeté et journalisé par les deux.
  - [x] raccourcis et jump lists / LECmd (--dt à 7 décimales : --mp est ignoré dans son CSV), JLECmd (--mp --ld) : 3 raccourcis, 8 entrées DestList, 5 raccourcis de listes personnalisées ; tous les champs identiques au 100 ns, après ajout à WAC des blocs ExtraData, du suivi (machine, DROID, date et adresse du GUID v1), de la taille de la cible, du nombre d'ouvertures et du rang MRU. Convention : nom de dossier connu canonique (JLECmd « Personal ») ou affiché (WAC « Documents »). A révélé 3 défauts : URI collée au bloc suivant, décalage de 2 octets sans liste d'ID, DROID nuls émis.
  - [x] shellbags / SBECmd : 27 dossiers ; rang MRU, sous-dossiers, dates de clé, nom, dates et entrée MFT identiques. WAC publie désormais la date de la clé propre du dossier, le rang et NodeSlot : les « FirstInteracted/LastInteracted » de SBECmd se vérifient comme simples lectures de ces dates (28/28). SBECmd : NodeSlot 0 pour les dossiers de premier niveau (le registre porte 1, 2, 3, 6…), HasExplored toujours faux en ligne de commande. A révélé : dossier perdu avec sa descendance si sa clé ne s'ouvrait pas ; dossier « Accueil » de Windows 11 sans nom.
  - [x] Amcache / AmcacheParser : WAC ne lisait que 2 tables et 4 à 6 valeurs ; désormais toutes les tables et valeurs, SHA-1 compris — 124 colonnes identiques ; AmcacheParser écrit 2 340 valeurs par défaut absentes de la ruche ; SHA-1 limité aux 30 premiers Mio, signalé par WAC seul (Sha1CoversBytes).
  - [x] ShimCache / AppCompatCacheParser : 232 entrées, position, chemin, date identiques (tabulations des applications empaquetées rétablies). Indicateur d'exécution non relevé par WAC : « Yes » juste 12 fois sur 13, « No » faux pour 105 des 117 binaires dont le Prefetch prouve l'exécution.
  - [x] corbeille / RBCmd : 19 fichiers $I, chemin, taille, date de suppression identiques.
  - [x] SRUM / SrumECmd : 60 804 lignes de 7 tables appariées par AutoIncId ; valeurs identiques, sauf 17 lignes d'énergie sur 887 où SrumECmd se trompe (dissect.esedb donne raison à WAC) : 15 lignes portant le contenu d'une autre (toutes les 8 : 11, 19, 27…), 2 identifiants absents de la table (7 et 131 pour 1 et 5). SrumECmd écrit 0 ou -1 pour 7 086 valeurs absentes ; WAC couvre 2 tables de plus (21 692 + 2 lignes). A révélé : dates FILETIME (EndTime, StartTime, ConnectStartTime, EventTimestamp) laissées en nombres, Tag UTF-16 lu comme de l'ANSI.
  - [x] registre / RECmd (lot Kroll) : UserAssist, BAM, USBSTOR, comptes SAM, Run, MuiCache, TypedPaths, WordWheelQuery, documents approuvés d'Office identiques. RECmd applique les entrées restantes d'une génération précédente des journaux APRÈS les plus récentes : il ramène SYSTEM, SECURITY, DEFAULT et NetworkService à un état plus ancien (SYSTEM : 0x3618 au lieu de 0x3620 ; 4 heures BAM en retard de 13 min) — vérifié sur les journaux eux-mêmes, sommes Marvin32 comprises. A révélé côté WAC : BAM limité aux SID ayant un profil (compte supprimé perdu), durée de premier plan UserAssist non lue. Couverture manquante : B-031.

## Journal
- 2026-09-29 : décision utilisateur — les outils Zimmerman (et .NET) installés dans la VM de test ; KAPE écarté (inscription chez Kroll).
- 2026-09-30 : KAPE fourni par l'utilisateur : `vmtest/kape.zip` (exclu du dépôt par .gitignore, licence Kroll). La comparaison avec KAPE redevient possible.
- 2026-09-30 : temps, même $MFT de 380 Mo dans la VM : WAC convertit C: et G: en 7,3 s, MFTECmd C: seul en 8,1 s (CSV).
- 2026-09-30 : temps, mêmes pièces, 305 journaux : WAC convertit events.json (messages en clair compris) en 16,8 s, EvtxECmd produit son CSV en 22,0 s.
- 2026-09-30 : temps prefetch, 380 fichiers : WAC 3,6 s, PECmd 0,7 s. Coût fixe de toute conversion WAC ≈ 3,4 s (mesuré avec la seule clé hosts) : copie de travail vérifiée des ruches, rejeu de leurs journaux, fuseau et profils du suspect — ce qui donne l'heure locale datée et la lettre de volume, que PECmd ne donne pas. Le prefetch lui-même : ≈ 0,1 s.
- 2026-09-30 : temps raccourcis/jump lists (3 + 9 fichiers) : WAC 1,8 s par clé, LECmd et JLECmd 0,3 s chacun ; coût fixe de WAC sans ruche ≈ 1,5 s.
- 2026-09-30 : temps registre (clé registry entière, toutes les ruches) : WAC 2,0 s ; AmcacheParser 0,5 à 0,9 s, AppCompatCacheParser 1,4 s, SBECmd 1,3 s, chacun pour son seul artefact.
- 2026-09-30 : temps corbeille : WAC 1,9 s, RBCmd 0,5 s ; SRUM : WAC 3,2 s (base de 21 Mo, toutes les tables, identités résolues), SrumECmd 2,5 s.
- 2026-10-01 : temps registre : WAC 2,0 s (clé registry entière, toutes les ruches rejouées) ; RECmd, lot Kroll, 7,6 à 13,6 s.
- 2026-10-01 : collecte complète, VM, KAPE cible KapeTriage (40 s, 0,91 Go, 1 198 fichiers dont 296 dédupliqués). WAC, configuration du kit : 454 s, 61 294 pièces (binary: unverified vérifie la signature de chaque exécutable) ; sans binaires : 197 s, 2 463 pièces (1,63 Go de pièces, dont 680 Mo de binaires fournisseurs de messages) ; sans journaux d'événements, 18 s. Chaque pièce de WAC porte MD5, SHA-1, SHA-256, les huit dates NTFS et son entrée MFT ; KAPE donne SHA-1 et trois dates.
- 2026-10-01 : dossier FR/EN « Face à KAPE et aux outils EZ » écrit (e5fa138). Écarts de couverture classés dans B-031 (registre), B-032 (fichiers), B-016 et B-010 (navigateurs, chronologie) ; clés maîtresses DPAPI écartées (règle : aucun secret). Temps de collecte : B-033. Fiche close.

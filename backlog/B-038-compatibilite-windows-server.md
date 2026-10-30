# B-038 — Collecte compatible avec les versions serveur de Windows, de Server 2003 à 2026

| Statut | Priorité | Effort |
|---|---|---|
| en cours (4.0 : écarts de Server 2022 à départager) | P3 | fort |

## Pourquoi
Les serveurs sont une cible de premier ordre (contrôleurs de domaine, serveurs web, de fichiers, d'applications), et beaucoup tournent sous des versions anciennes. WAC est développé et éprouvé sur Windows 10 et 11, des postes clients. Demande utilisateur du 2026-10-06 : la collecte doit fonctionner sur les versions serveur, de Windows Server 2003 à 2026. Les artefacts sont sensiblement les mêmes que ceux du client de la même génération. Prérequis de B-035 (web côté serveur).

## Source
Ce qui distingue un serveur du client de même noyau :
- **les versions et leur client jumeau** : Server 2003 (NT 5.2, XP), 2008 (Vista), 2008 R2 (7), 2012 (8), 2012 R2 (8.1), 2016, 2019, 2022 et 2025 (10 et 11), 2026 ;
- **les rôles** : IIS (journaux, configuration — B-035), DNS, DHCP, partages de fichiers, services Bureau à distance (connexions RDP entrantes nombreuses), Hyper-V ;
- **le mode Server Core**, sans interface graphique : pas d'Explorateur, donc pas de ShellBags, de jump lists, de Chronologie ni d'index de recherche — artefacts absents, à déclarer comme tels ;
- **un contrôleur de domaine** : comptes du domaine dans `NTDS.dit` et non dans la SAM (qui n'y contient que le compte de restauration) ; SYSVOL et stratégies de groupe ;
- **les profils** : nombreux comptes de service et d'administrateurs, connexions de nombreux utilisateurs.

## Sortie attendue
Le même WAC.exe (64 bits, et WAC32.exe pour Server 2003 et 2008 en 32 bits) collecte chaque version serveur. Chaque artefact absent d'une version ou d'une installation Server Core le dit (`CollectionStatus`) au lieu d'échouer, d'après la table de B-039.

## Référence indépendante
Une VM par version serveur passée par le harnais (création sans interaction, comme `create-vm.sh`), avec les outils de référence déjà utilisés (EZ, plaso/libyal) sur les mêmes pièces, et un rôle IIS témoin pour B-035.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Cycle VM vert sur au moins une version de chaque génération (2003, 2008/2008 R2, 2012/2012 R2, 2016 et suivantes).
- Une installation Server Core collectée sans erreur, ses artefacts absents déclarés.

## Tâches
- [x] Images des versions serveur (2012 R2 à 2025, évaluation) et profils de create-vm.sh ; Server 2022 créée
- [ ] Cycle du harnais sous chaque génération (2012 R2, 2016+), écarts départagés
- [ ] Artefacts propres aux rôles (à répartir avec B-035 pour IIS)
- [ ] Server Core
- [ ] Contrôleur de domaine : `NTDS.dit` (à étudier)

## Point ouvert
Server 2003 a le noyau de XP (NT 5.2) : il demande la version 32 bits de WAC et la compatibilité des API de B-037, qui est planifiée en dernier. À décider : avancer cette partie de B-037, ou traiter d'abord Server 2008 et suivants et faire suivre Server 2003 avec B-037.

## Journal
- 2026-10-06 : créée à la demande de l'utilisateur — compatibilité avec les versions serveur de Windows, de 2003 à 2026, avant B-035 ; les artefacts sont sensiblement ceux du client de même génération.
- 2026-10-07 : décision utilisateur — version 3.0, avec les artefacts de compromission d'Active Directory (B-041).
- 2026-10-15 : profils srv2012r2 à srv2025 dans create-vm.sh (médias d'évaluation : édition Standard avec interface, index 2, sans clé ; mot de passe synthétique complexe, le serveur refusant « wac ») ; Server 2022 créée sans interaction (ServerStandardEval, build 20348). Premier cycle du harnais lancé (WAC_VM=srv2022-test).
- 2026-10-15 : **premier cycle sous Server 2022 : 438 ✅, 18 ❌**, à départager quand les versions clientes seront finies (décision utilisateur : les clientes d'abord). Écarts : BAM sans l'exécution de taskkill.exe ; clés DPAPI et raccourcis du compte wacrdp (créé par le témoin RDP) « en trop » ; fichier hosts « NotCollected » au lieu de « ExpectedButMissing » ; 3 désaccords mft/manifeste ; Prefetch sans aucune référence $MFT (Prefetch désactivé par défaut sur les éditions serveur ?) ; témoin Run du profil Default ; ShellBags d'archive libarchive (7z, propre à Windows 11) ; SRUM sans ligne réseau ; miniature témoin absente.
- 2026-10-16 : décision utilisateur — le ShimCache de Server 2003 sera traité avec les autres serveurs, ici. Le point ouvert sur Server 2003 se règle ainsi : la compatibilité des API de XP (B-037) est faite, WAC32 tourne de XP SP1 à SP3 ; Server 2003 (ISO dans `~/Téléchargements`) vient avec les serveurs. Une VM Server 2012 R2 existe désormais, mais comme serveur RDP du banc (`wac-rdp-server`, `create-rdp-server.sh`), pas comme machine examinée.
- 2026-10-17 : décision utilisateur — les serveurs passent en **version 4.0** ; la 3.0.0 se limite aux versions clientes, de XP à 11.
- 2026-10-30 : **la 4.0.0 commence** (demande utilisateur, après la 3.0.1). Place faite : seules win11-test (non-régression cliente), win11-footprint, wac-rdp-server et srv2022-test restent ; résultats anciens supprimés. ISO présentes : Server 2003 (`~/Téléchargements`, Standard et SP1), 2012 R2, 2016, 2019, 2022, 2025 (`vmtest/tools/isos`) ; **manquent 2008, 2008 R2 et 2012** (génération 2008 exigée par les critères). Les 18 écarts du 15/10 se réduisent à 9 sujets, à départager sur un nouveau cycle Server 2022 avec la 3.0.1 :
  1. Prefetch sans aucune référence $MFT (Prefetch désactivé par défaut sur les éditions serveur ?) ;
  2. 3 pièces de mft.json en désaccord avec le manifeste ;
  3. compte `wacrdp` créé par le témoin RDP sur le serveur lui-même : son profil, copié de Default, donne raccourcis et clé DPAPI « en trop » et porte le témoin Run du profil Default (harnais) ;
  4. ShellBags : dossier d'archive libarchive (7z) propre à Windows 11 (harnais) ;
  5. SRUM sans ligne réseau ;
  6. BAM sans l'exécution de taskkill.exe ;
  7. miniature témoin absente ;
  8. hosts « NotCollected » au lieu de « ExpectedButMissing » : la table ne dit pas hosts toujours présent sur un serveur, le harnais l'attend.
  Ordre prévu : cycle Server 2022 (2016+), puis 2012 R2, 2025, Server Core, 2003 (WAC32, piloté comme XP), 2008 dès les ISO fournies.

# Ce que WAC fait déjà — inventaire pour qui reprend le projet

La chronologie est dans `git log`. Ce document dit **ce qui existe**, **pourquoi
c'est fait ainsi** — les décisions, souvent prises après un défaut réel — où
le trouver et comment c'est vérifié. Avant de « simplifier » un de ces points,
lire sa raison : la plupart protègent contre un défaut qui a déjà eu lieu.

Chaque entrée : **Capacité** — Décision et raison — *Code* — *Vérification* — commits.

---

## 0. La version d'origine (2025, versions 1.0 à 1.3.1)

WAC est né en mai 2025 (6508455 … 5ee5a1c) : un exécutable Visual Studio qui
extrayait **vite**, en **JSON**, les artefacts d'une machine Windows 10 ou
ultérieure en marche, pour les intégrer à un outil de surveillance ou
d'analyse. La migration de 2026 a gardé tous ces artefacts et leur fichier de
sortie, mais a changé **la façon de les lire** : plus de cliché instantané ni
d'API, lecture brute du disque et des copies (sections suivantes).

| Artefact (fichier JSON) | Ce qu'il prouve | Lu en 2025 par | Lu aujourd'hui par | Code |
|---|---|---|---|---|
| Informations système (`OperatingSystem.json`) | nom, version, domaine, fuseau, démarrage | API Win32 | ruches SYSTEM et SOFTWARE copiées, noyau pour le démarrage | system.cpp |
| Tâches planifiées (`ScheduledTasks.json`) | persistance, commandes lancées | COM du Planificateur | XML de `System32\Tasks` et TaskCache, en brut | scheduledTasks.cpp |
| Sessions ouvertes (`Sessions.json`) | qui est connecté, depuis quand | LSA | LSA, en instantané scellé | sessions.cpp |
| Processus (`processes.json`) | ce qui tourne, parent, propriétaire | API, ouverture de chaque processus | instantané du noyau et WTS, sans `OpenProcess` | processes.cpp |
| Comptes locaux (`users.json`) | comptes, dernières connexions, échecs | API | ruche SAM copiée | users.cpp |
| Services et pilotes (`services.json`) | persistance, binaires chargés | gestionnaire de services, service par service | ruche SYSTEM copiée + une énumération de l'état | services.cpp |
| Journaux d'événements (`events.json`, option) | toute l'activité journalisée | API `EvtQuery` (jusqu'à 20 min) | lecteur EVTX maison, fichiers copiés en brut | evtx.cpp, event_messages.cpp |
| UserAssist (`userassists.json`) | programmes lancés par l'interface, compteur | registre via VSS | ruche NTUSER copiée | reg_userassists.cpp |
| MUICache (`muicache.json`) | programmes exécutés, nom affiché | registre via VSS | ruche UsrClass copiée | reg_muicache.cpp |
| BAM (`bams.json`) | dernière exécution par programme et utilisateur | registre via VSS | ruche SYSTEM copiée | reg_bams.cpp |
| USBSTOR (`Usbstor.json`) | clés USB branchées, première et dernière fois | registre via VSS | ruche SYSTEM copiée ; numéro de série, fabricant, produit ajoutés | reg_usbstors.cpp |
| MountedDevices (`mounted_device.json`) | lettres de lecteur et volumes | registre via VSS | ruche SYSTEM copiée ; chaque forme de valeur décodée | reg_mounted_devices.cpp |
| Shellbags (`shellbags.json`) | dossiers parcourus, y compris disparus | registre via VSS | ruche UsrClass copiée | reg_shellbags.cpp, idList.cpp |
| MRU (`mrus.json`, `mruApps.json`) | fichiers et applications récents | registre via VSS | ruche NTUSER copiée | reg_mru.cpp, reg_mru_apps.cpp |
| Clés Run (`run.json`) | lancement au démarrage | registre via VSS | ruches copiées | reg_run.cpp |
| Shimcache (`shimcache.json`) | présence d'un binaire | registre via VSS | ruche SYSTEM copiée ; UTC réel, sans faux indicateur d'exécution | reg_shimcache.cpp |
| Amcache (`amcache_applications.json`, `amcache_application_files.json`) | inventaire des programmes, empreinte SHA-1 | ruche via VSS | Amcache.hve copiée en brut | reg_amcache_\*.cpp |
| Listes de sauts (`jumplistAutomaticDestinations.json`, `jumplistCustomDestinations.json`) | fichiers ouverts par application | fichiers via VSS | copies brutes ; 15 premières entrées et DestList retrouvés | jumplist_\*.cpp, oleparser.cpp |
| Prefetch (`prefetchs.json`) | exécutions, compteur, fichiers chargés | fichiers via VSS | copies brutes ; décompression, nom de l'exécutable | prefetchs.cpp |
| Documents récents (`recentdocs.json`) | documents ouverts, même effacés | fichiers `.lnk` via VSS | copies brutes ; cible Unicode, horodatages UTC | recent_docs.cpp, idList.cpp |

Autres acquis de 2025, conservés :
- **dates de dernière écriture des clés de registre** pour les artefacts qui
  en dépendent (ee3aafe) ;
- **noms des GUID** connus (table `trans_id.cpp`, 4b59ba3 puis étendue) ;
- **empreintes des fichiers cités** (option `--md5`, e462c83) — remplacée en
  2026 par `--binary` (trois empreintes, lecture brute, prélèvement) ;
- **valeur brute hexadécimale** des shellbags et raccourcis (`--dump`) ;
- **dossier de sortie** (`--output`), **journal texte** par niveaux
  (`--loglevel`), exécution depuis une clé USB (286230f).

Ce que la migration a retiré de 2025, et pourquoi : le cliché instantané VSS
(traces dans les journaux, service sollicité), COM et WMI, l'ouverture des
processus et des services un par un, l'API des journaux d'événements, la
lecture du registre vivant, `offreg.dll` et la compilation Visual Studio.

---

## 1. Lecture du disque

**Lecture NTFS brute, sans VSS ni API de fichiers.** WAC ouvre `\\.\X:` en
lecture seule, parcourt la `$MFT` et les index de répertoires lui-même. Raison :
le cliché VSS, COM et WMI laissaient des traces dans les journaux ; ouvrir un
fichier par Windows change sa date d'accès.
*raw_hive.cpp, raw_collect.cpp* — *raw_hive_test (VM), cycle VM : empreintes
identiques à une lecture par Windows* — f3a6b3a, 39e4407.

**Volume lu sans cache (`FILE_FLAG_NO_BUFFERING`).** Raison : un descripteur
de volume tamponné peut resservir un secteur lu plus tôt ; sans cache, chaque
lecture atteint le disque et la collecte ne remplit pas la mémoire de la
machine. Même durée mesurée. *raw_hive.cpp (NtfsVolume::open, readBytes)* —
cycle VM — 01549c7.

**Compression NTFS (LZNT1), Compact OS / WOF (XPRESS 4K à 16K, LZX).** Raison :
Windows 11 compresse les journaux d'événements et les binaires système ; un
lecteur qui l'ignore ne rendait rien (400 journaux sur 404). *lznt1.cpp,
xpress.cpp, lzx.cpp* — *lznt1_test, xpress_test, lzx_test contre les
compresseurs de Microsoft, octet pour octet* — 6a61a8e, d812e20, 5c12c3a.

**Longueur de données valides, `$ATTRIBUTE_LIST`, `$INDEX_ROOT` déplacé, blocs
d'index libres.** Raison : au-delà de la longueur valide NTFS rend des zéros —
les lire copiait du code machine d'une DLL disparue dans un journal ; attributs
et index éclatés rendaient des milliers de répertoires WinSxS illisibles.
*raw_hive.cpp* — *CRC des morceaux EVTX, cycle VM* — cd27837, 70e24f0.

**Enregistrements NTFS déchirés refusés (fixups).** Raison : une écriture
interrompue mélange deux versions d'un enregistrement ; lu tel quel, il donne
une donnée plausible et fausse. *raw_hive.cpp (applyNtfsFixup)* —
*ntfs_fixup_test, 44 610 contrôles* — 66e5567.

**Plusieurs volumes, lettre système détectée.** Raison : Windows n'est pas
toujours sur C:, un profil peut être sur D:. *tools.cpp (volumeOfPath,
extractedPath), running_machine.cpp (fixedNtfsVolumes)* — cycle VM — 39e4407.

## 2. Registre

**Lecteur de ruches propre à WAC (plus d'`offreg.dll`).** Raison : Windows 11
fournit offreg.dll dans System32 — WAC lisait les preuves par une DLL de la
machine examinée. Mêmes fonctions `OR*`. *offline_registry.cpp* —
*offline_registry_test contre offreg.dll, 0 écart sur 1,27 M clés* — 5eabec8.

**Rejeu des journaux de transaction `.LOG1`/`.LOG2` sur la copie, avec journal
d'annulation.** Raison : la ruche sur disque n'a pas les dernières
modifications ; le rejeu se fait sur la copie de travail, jamais sur l'original,
et reste réversible à l'octet. *hive_recover.cpp, raw_collect.cpp* —
*consigne_test, cycle VM (reg load refuse puis accepte)* — 958d35b.

**Aucune clé du registre vivant ouverte.** La liste des profils vient de la
ruche SOFTWARE copiée (extraction en deux passes). *raw_collect.cpp* — contrôle
des imports (aucune fonction `Reg*`) — 78e573f.

**Comptes (SID) et GUID nommés hors ligne.** Raison : `LookupAccountSid` peut
interroger le contrôleur de domaine — une trace sur une autre machine ; la
compilation refuse ces imports. *account_names.cpp, trans_id.cpp* —
*check-json (comptes, GUID), garde de build-windows.sh* — a3e27ec, 305156c.

## 3. Consigne et chaîne de preuve

**Consigne scellée et copie de travail.** Chaque pièce copiée deux fois : la
consigne (brute, jamais rouverte en écriture) et la copie de travail où l'on
rejoue et lit. Manifeste avec MD5, SHA-1, SHA-256, tailles déclarée et valide,
dates `$STANDARD_INFORMATION` **et** `$FILE_NAME`, entrée MFT ; sceau
`MANIFEST.sha256`. Scellement en dernière opération. *consigne.cpp* —
*consigne_test, check-json (consigne confrontée à son contenu réel)* —
6a41ed5, 1a0e616, 5eb3517.

**Collecte séparée de la conversion (`--collect` / `--convert`).** Raison :
collecter vite sur la machine examinée, convertir sur un poste d'analyse. La
conversion vérifie le sceau et chaque empreinte avant toute lecture ; les
relevés en direct sont eux-mêmes des pièces scellées. *main.cpp,
exhibit_reader.cpp, live_snapshot.cpp* — *cycle VM : collecte séparée, pièce
retouchée refusée, deux conversions identiques à l'octet* — bae8b85, 37bfea4.

**Journal d'investigation (`investigation.json`, `conversion.json`).** Chaque
opération, sa cible, son résultat et la trace qu'elle laisse (`Footprint`).
*audit.cpp* — relecture, dossier d'innocuité.

**Scripts de vérification de la consigne sans WAC.** `.ps1` (Windows) et `.sh`
(Linux, recommandé : rupture technologique), messages FR et EN, livrés dans
`bin/`. Le manifeste est hostile : un chemin qui sort de la collecte est
refusé sans être lu. *sources/doc/user/\*.ps1, \*.sh* —
*verify_exhibits_test.sh (23), cycle VM, contre-épreuve VM* — bf0d8ac,
49d27d3, 2901062.

## 4. Binaires

**`--binary` : empreintes par lecture brute des fichiers cités, prélèvement des
exécutables, scripts et documents à macros.** Documents et données seulement
hachés (pas une copie des fichiers de l'utilisateur). Un même contenu n'est
consigné qu'une fois. *binaires.cpp* — cycle VM — e6bf86f, 1e64424, 65d1191.

**Authenticité vérifiée en mémoire, sans API ni service.** Microsoft :
catalogues et signatures intégrées, scripts PowerShell compris ; tiers : chaîne
jusqu'au programme racine de Microsoft, horodatage, CRL, certificats
désapprouvés, pilotes vulnérables. Un binaire authentique n'est pas copié.
*authenticode.cpp, rsa.cpp, trust_set.cpp* — *authenticode_test,
third_party_chain_test, vulnerable_drivers_test, check-json contre
Get-AuthenticodeSignature* — 5934a3b, 886a765, 3d06aa1, c341d31, fc0610b,
9dba0bb.

**`--update-trust` : jeu de confiance préparé sur le poste d'analyse.** Seul
mode réseau ; WinHTTP chargée dynamiquement là seulement. *trust_update.cpp,
http_client.cpp, cab.cpp, zip.cpp, inflate.cpp, csv_reader.cpp* —
*trust_list_test, trust_set_test, cab_test, zip_test, inflate_test* — 2d13f42,
eed5a4c, b426f50.

**`--binary-all`, analyse parallèle, clé du serveur de symboles.** *binaires.cpp*
— check-json — 5eb3517, 73c23d0.

## 5. Artefacts

**Journaux d'événements lus hors ligne, messages reconstitués.** Raison :
`EvtQuery` prenait 20 minutes sous Windows 11 et sollicitait le service ; le
lecteur maison lit plus d'enregistrements que l'en-tête n'en annonce (journaux
fermés brutalement). *evtx.cpp, event_messages.cpp, wevt.cpp* — *evtx_test
contre python-evtx, wevt_test, event_messages_test* — 1aab531, 042d617, 3eab3dc.

**Registre : UserAssist, MUICache, BAM, USBSTOR, MountedDevices, Shellbags,
MRU, Run, Shimcache, Amcache.** Chaque valeur décodée selon son format
(MountedDevices : GPT, MBR, chemin) ; USBSTOR : numéro de série, fabricant,
produit ; Shimcache sans faux indicateur d'exécution. *reg_\*.cpp, idList.cpp* —
*check-json contre reg.exe, Get-Partition* — 673f0d9, 349304a, f341198.

**Fichiers : Prefetch, listes de sauts, documents récents, tâches planifiées.**
Lectures bornées contre les données forgées ; listes de sauts : les 15
premières entrées et le DestList retrouvés ; tâches lues en XML, sans COM.
*prefetchs.cpp, jumplist_\*.cpp, oleparser.cpp, recent_docs.cpp,
scheduledTasks.cpp* — *parsers_test, lnk_test (bornes, sanitizers)* —
d88a4b5, 6f903a8, 973f5d0.

**Relevés en direct : processus, sessions, état des services, réseau
(connexions, voisins, interfaces, routes), horloge.** Instantanés scellés ;
aucun `OpenProcess` ; iphlpapi chargée seulement pour le réseau. *processes.cpp,
sessions.cpp, services.cpp, network.cpp, system.cpp* — *check-json contre
netstat* — c993162.

**`$MFT` et journal USN.** mft.json : chaque fichier, supprimés compris, dates
`$SI` et `$FN`, liens physiques ; usn_journal.json : chemins par la $MFT ;
`$LogFile` brut. *mft.cpp, usn_journal.cpp* — *mft_test contre ntfs-3g (275),
usn_journal_test (26), check-json : 61 242 pièces confrontées au manifeste* —
92b14e9.

**Système, services et pilotes, utilisateurs locaux.** Hors ligne depuis les
ruches. *system.cpp, services.cpp, users.cpp* — check-json.

## 6. Dates, textes, JSON

**UTC exact et heure locale du suspect, heure d'été comprise.** Chaque champ
interprété selon son encodage natif ; le fuseau est celui de la ruche SYSTEM,
pas celui de l'analyste ; une date ne porte que la précision de sa source ;
heure de démarrage lue dans le noyau. *time_zone.cpp, tools.cpp* — *check-json
contre la base IANA* — 50537d5, 0d6779c, c95d7ca, 6d09457.

**Textes décodés dans la page de code de la machine examinée.** Deux
conversions au lieu de six, dont deux fausses. *tools.cpp (decodeText)* —
2e7c537.

**JSON : aucun champ vide, clés en anglais sans abréviation.** Règle appliquée
une fois, dans `Json::add`. *json.h* — *json_test* — 4f7666c, 4dc5db2.

## 7. Configuration, console, compilation

**`wac.yml` à côté de WAC.exe.** La procédure écrite une fois ; une clé
inconnue refuse la collecte ; fichier appliqué consigné. *config.cpp,
yaml_light.cpp, libyaml 0.2.5* — *config_test, yaml_light_test* — 9fefefc.

**Console en français ou en anglais.** Table vérifiée à la compilation ; JSON
et journaux restent en anglais. *translations.cpp, tools.cpp (writeConsole)* —
config_test — 2742bbb.

**Version dans WAC.rc seul, `bump-version.sh`, compilation reproductible.**
c6f1b57.

**Une seule compilation MinGW-w64 (Linux et MSYS2), MSVC retiré.** Gardes :
runtime statique, aucune bibliothèque réseau ni résolution de noms importée.
*build-windows.sh* — 84e60e7, f989656.

**Arborescence : `sources/`, `bin/` (dernière compilation, scripts,
SHA256SUMS), `backlog/`.** 5d1a0e9, ec795f5.

## 8. Vérification et documentation

**Cycle VM automatique.** Collecte complète, collecte séparée, conversion,
contre-épreuves, contrôle d'innocuité par fichiers témoins, `check-json.py`
qui confronte les sorties entre elles et à des sources externes. *vmtest/* —
654e2b8.

**Documentation FR et EN.** Manuel, guide des tests, dossier de validation,
dossier d'innocuité, guide de compilation, documentation doxygen.
*sources/doc/* — 7fba566, 88508c2, bb84afd, 42a10df, 654e2b8.

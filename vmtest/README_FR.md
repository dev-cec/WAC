# VM de test Windows 11 — pilotage autonome de WAC

*English version: [README.md](README.md)*

Permet de tester WAC sur un vrai Windows 11 (vrai NTFS) **sans aucune interaction** :
build sur Linux → exécution dans la VM en SYSTEM → rapatriement des JSON sur l'hôte.

Le pilotage passe par le **qemu-guest-agent** (canal virtio-serial), donc pas besoin
de réseau, de partage de fichiers, ni de cliquer dans la VM (les commandes tournent
en SYSTEM : droits admin, aucun UAC).

## Fichiers
| Fichier | Rôle |
|---|---|
| `create-vm.sh` | Crée la VM de zéro, sans interaction : autounattend + UEFI Secure Boot + TPM 2.0 + canal guest-agent, déblocage du boot par injection de touches, puis attente que l'agent réponde. |
| `autounattend.xml` | Install Windows muette (FR, Win11 Pro, compte admin local `wac`/`wac`, OOBE zappée, autologon) **et auto-installation du guest-agent** au 1er logon depuis le CD virtio-win. |
| `qga.py` | Helper guest-agent : `ping`, `run` (exécuter), `read`/`write` (échanger des fichiers). |
| `run-wac-test.sh` | Cycle de test complet : build → branchement d'une clé USB virtuelle (`~/vms/wac-usb-test.img`, numéro de série `WACUSB0001`, pour que USBSTOR soit peuplé même sur une VM recréée) → envoi des binaires → validation `raw_hive` (extraction brute + `reg load`) → exécution de WAC → rapatriement du log et des JSON dans `results/<horodatage>/`. |
| `register-test-guids.ps1` | Enregistre dans la VM, à chaque cycle, trois GUID que la table de WAC ignore — un par source où WAC lit les noms de GUID —, chacun référencé par une tâche ComHandler désactivée. |
| `check-json.py` | Contrôle les sorties : validité JSON, chemins Windows, et **contrôles croisés** (cf. ci-dessous). S'utilise aussi seul : `python3 check-json.py results/<horodatage>`. |

## Ce que le harnais valide — et ce qu'il ne valide pas

Il valide la **compilation**, la **terminaison** de WAC (code de retour, absence
de `terminate called` / `Unhandled exception`), la **validité JSON** de chaque
sortie et la **cohérence des chemins** Windows.

Il ne valide **ni l'exactitude ni la complétude** des valeurs : un mauvais champ
publié sous une bonne clé, une date mal interprétée ou un décalage de parsing
produisent du JSON parfaitement valide. Un artefact à « 0 entrée » est par
ailleurs indiscernable, à l'analyse, de « aucune trace sur la machine ».

**C'est à quoi servent les contrôles croisés** : comparer une donnée *calculée
par WAC* à une donnée *indépendante* de la même collecte. Ce sont eux qui ont
révélé des valeurs fausses dans du JSON valide :

| Contrôle | Ce qu'il a trouvé |
|---|---|
| `Hash` d'un Prefetch vs suffixe de son nom de fichier | 65 hash faux sur 270 (formatage hexadécimal sans remplissage) |
| couples `X` / `XUtc` (et listes, `Runs` / `RunsUtc`) désignant le même instant | double décalage horaire (`sessions`, `.lnk`, `InstallDate`) ; `RunsUtc` des Prefetch étiquetés `+02:00` (1 273 heures d'exécution fausses de 2 h) |
| décalage de chaque date locale / base tz (zoneinfo) | toutes les dates étiquetées avec le décalage du jour de collecte (106 dates d'hiver à `+02:00`) ; dates de changement d'heure de la ruche SYSTEM lues dans le mauvais format |
| aucune session antérieure au démarrage du système | le premier de ces décalages — puis une heure de démarrage en retard de 3,5 s, estimée par `GetTickCount64` |
| heure de démarrage vs événement Kernel-General 12 | deux sources indépendantes de l'instant du démarrage : 0,00 s d'écart depuis que la valeur vient du noyau |
| états de service impossibles, taux de `*_UNKNOWN`, présence de pilotes | convertisseurs comparant des filtres d'énumération à des états |
| `RID` retrouvé à la fin du `SID` reconstruit | validation de la lecture du SAM |
| aucun processus ne porte `WAC.exe` parmi ses modules | le processus Idle héritait des modules de l'outil de collecte |
| `EvtSystemComputer` confronté au nom de machine de `OperatingSystem.json` | contrôle du décodage BinXML des journaux : deux sources sans rapport (fichier `.evtx` et ruche SYSTEM) |
| identifiants d'enregistrement uniques par canal | WAC parcourt **tous** les chunks physiques d'un `.evtx`, pas ceux déclarés par l'en-tête — c'est ce qui lui fait lire les enregistrements qu'un journal mal fermé ne compte pas ; le risque propre à ce choix est de relire un chunk périmé d'un journal circulaire, et ce contrôle le verrait |
| aucun événement postérieur à l'horodatage de collecte | décalage ou mauvaise lecture d'un `FILETIME` d'événement |
| une référence `%%nnnn` restée dans un message | fichier de paramètres d'un fournisseur non chargé (3 780 messages de Security avant correction) — distinguée d'une marque `%N`, qui signale seulement une donnée absente de l'événement |
| aucune ruche à la fois rejouée ET patchée | deux opérations indépendantes du journal d'audit : un rejeu abouti rend la ruche propre, donc le patch ne doit plus s'appliquer |
| un journal d'annulation nommé pour chaque rejeu | sans lui la copie brute n'est plus reconstructible, et la promesse du rapport serait fausse |
| `mounted_device.json` / `reg query` de la même clé (décodée par une implémentation distincte) et `Get-Partition` | 6 montages sur 7 publiés comme `\` : les chemins de périphérique actuels (`\??\...`) étaient décodés comme du texte ANSI et s'arrêtaient au premier octet nul |
| dates FAT des shell items sans fraction et à secondes paires ; dates Amcache lues en texte sans fraction | toutes les dates écrites avec sept chiffres de fraction — `…:30.0000000` pour une date FAT précise à deux secondes (808 dates) |
| BAM (`taskkill.exe` lancé par le harnais), UserAssist (exécutions Prefetch), USBSTOR (`Get-PnpDeviceProperty` sur la clé USB virtuelle que branche le harnais), Amcache `LinkDate` (en-têtes PE) | les quatre stockent de l'UTC, lu comme une heure locale : toutes les dates fausses de 2 h ; BAM et UserAssist ensuite vidés par une régression de la lecture des valeurs |
| noms des SID / `Get-LocalUser`, `Get-LocalGroup`, et S-1-5-18 = `SYSTEM` | noms demandés au système en marche (LookupAccountSidW, qui peut interroger le contrôleur de domaine) et traduits dans sa langue (`Système`) |
| trois GUID inconnus de la table de WAC, enregistrés par `register-test-guids.ps1` (classes de la machine, classes utilisateur, dossiers connus), nommés exactement ; aucun « Unmapped GUID » | le texte de remplacement « Unmapped GUID » publié comme un nom — 18 gestionnaires COM des tâches de la VM elle-même, tous décrits dans sa ruche SOFTWARE |
| `MANIFEST.sha256` porte l'empreinte réelle de `MANIFEST.json` | seul contrôle qui détecte une retouche du manifeste, lequel est précisément ce qui atteste des pièces |
| chaque pièce collectée porte ses trois empreintes | une pièce sans empreinte n'est pas identifiée, donc inutilisable |
| le lecteur système d'`OperatingSystem.json` figure dans les volumes lus du manifeste | deux sources indépendantes de la même information |
| les fichiers réellement présents dans `exhibits/` sont exactement ceux du manifeste | 209 pièces ajoutées après le scellement, identifiées par rien, alors que tous les autres contrôles étaient verts |
| exécutables de System32/SysWOW64 listés par Windows, tous présents dans le manifeste d'un `--collect --binary` | 6 446 manquants sur 8 540 : répertoires dont le `$INDEX_ROOT` est dans un enregistrement d'extension (4 569 illisibles), et noms de liens physiques non déclarés |
| SHA-256 de fichiers lus en brut (petit, gros, WOF) comparé à `Get-FileHash` | garde-fou de la lecture par lots de clusters contigus, introduite pour la vitesse |
| date de modification des Prefetch comparée à celle que donne Windows | 0 sur 335 conformes : les dates étaient celles de la copie de travail, soit la minute de la collecte |
| tout catalogue cité dans un verdict « Microsoft (catalog …) » présent dans la consigne | 170 sur 170 absents : le préfixe cherché (« catalogue ») ne correspondait plus au libellé (« catalog ») |
| binaires déclarés authentiques Microsoft par WAC confirmés par `Get-AuthenticodeSignature` | un mauvais verdict laisserait un binaire malveillant hors de la consigne |
| copie d'un paquet du Store : fichier intact authentifié, fichier modifié et fichier ajouté prélevés | vérification des paquets par la carte des blocs signée |
| identifiants d'enregistrement uniques dans CHAQUE fichier journal | l'invariant réel : un même canal peut être porté par plusieurs fichiers dont les numéros se recouvrent légitimement. Un doublon dans un même fichier, en revanche, signale un chunk périmé relu — le risque propre au parcours de tous les chunks physiques |
| nom de machine MAJORITAIRE des événements conforme à `OperatingSystem.json` | un renommage de machine laisse légitimement d'anciens noms dans les journaux : c'est la majorité qui doit correspondre, pas la totalité |

**Le journal de WAC s'accumule.** Il est ouvert en mode ajout : sans purge, il
grossit d'un test a l'autre — 636 Mio constatés après une série de runs, ce qui
rend son rapatriement inutilisable et noie les traces du run courant sous celles
des précédents. `run-wac-test.sh` le supprime désormais avant chaque exécution.

**Le harnais peut manquer de mémoire.** `qga.py read` accumulait le fichier
entier avant de l'écrire : avec un `events.json` de 28 Mo, le cumul des réponses
base64 et de leur décodage a suffi, la VM tournant à côté, pour que le système
tue le harnais en pleine collecte. Les morceaux partent désormais directement
dans le fichier. `check-json.py`, lui, charge toujours `events.json` en entier —
à revoir si les journaux grossissent encore.

**Le harnais peut être la cause du défaut qu'il signale.** Un run de 604 s a été
coupé par le timeout de 600 s de `qga.py` juste avant l'écriture des deux
derniers JSON : le rapport disait « collecte probablement incomplète » — ce qui
était exact — mais WAC était allé au bout. Le journal de collecte (`run.log`,
qui se termine par `END, Time elapsed`) tranche entre les deux. Timeout porté à
30 min ; il faudra le revoir si la collecte s'allonge encore.

**L'authenticité Microsoft se confronte à Windows.** `WAC/authenticode_test.cpp`
vérifie les catalogues d'un dossier puis rend un verdict par fichier ; compilé
pour Windows, il tourne dans la VM sur les binaires prélevés par une collecte,
et ses verdicts se comparent à ceux de `Get-AuthenticodeSignature` sur les mêmes
fichiers. Sur 2 233 binaires : 2 126 authentifiés par les deux, 99 prélevés par
les deux, et aucun fichier accepté par WAC que Windows refuserait — le seul
écart qui compterait. Pour les scripts : 462 scripts PowerShell et 11 WSH, tous
authentifiés comme par Windows, et un script signé modifié d'un mot est refusé.
Le programme lit les fichiers par l'API : c'est un outil
de test, jamais employé pendant une collecte.

**Le manifeste est confronté au contenu réel de la consigne.** Le harnais
relève dans la VM la liste des fichiers de `exhibits/` (`LIST.txt`), et
`check-json.py` vérifie que chaque fichier présent est au manifeste, et
réciproquement. Sans ce contrôle, 209 pièces — les binaires de ressources des
fournisseurs d'événements, extraits après le scellement — sont restées dans la
consigne sans rien qui les identifie, alors que tous les autres contrôles
(sceau, empreintes, décomptes) étaient verts : ils ne portaient que sur le
manifeste lui-même.

**La consigne se valide hors VM elle aussi.** `WAC/consigne_test.cpp` rejoue la
chaîne de production (empreintes, manifeste, copie vérifiée, rejeu) sur des
ruches fournies en argument, et vérifie ce qu'aucune compilation ne révèle : que
la consigne reste intacte octet pour octet pendant que le travail est modifié.
`WAC/sha_test.cpp` confronte les empreintes aux vecteurs de FIPS 180-4 et aux
longueurs 55 à 128, qui exercent le remplissage — seul endroit où une
implémentation correcte par ailleurs se trompe. Les deux compilent nativement
sous Linux.

**Le parseur EVTX se valide hors VM.** Le décodage BinXML est trop fragile pour
n'être éprouvé que sur les journaux d'une VM neuve, tous écrits par la même
version de Windows et tous propres. `WAC/evtx_test.cpp` (exclu du build par le
motif `_test.cpp`) lit un `.evtx` et rend soit un bilan, soit le XML de chaque
enregistrement (`--dump`) ; il tourne sous `wine`, ce qui permet de le confronter
à des journaux réels — dont des journaux volontairement abîmés — et de comparer
enregistrement par enregistrement à une implémentation indépendante
(`python-evtx`). C'est ce qui a montré qu'un chunk à signature fausse arrêtait
la lecture de tout le fichier : 14 enregistrements lus sur 270. Les journaux
extraits sont aussi confrontés au CRC32 que porte chaque chunk EVTX : les 1 505
chunks des 404 journaux de la VM de test sont conformes.

Le mode `--collect` execute la chaine complete (fichier brut -> BinXML ->
`xml_light` -> `Event` -> JSON en flux) sur une arborescence imitant une
extraction, et `--collect-memory` la meme chose en accumulant tout en memoire
comme le faisait la collecte par API. C'est ce qui rend l'argument memoire
verifiable au lieu d'affirme : memes enregistrements, meme binaire, meme hote,
seule la strategie d'ecriture change — 1 281 Mo contre 26 Mo de pic, pour un
`events.json` identique octet pour octet (ce qui valide au passage
`EcrivainJsonTableau` contre `writeJsonFile`).

**Après tout changement, comparer les compteurs d'entrées au run précédent**, pas
seulement les pastilles vertes — et écrire un contrôle croisé pour chaque défaut
trouvé : c'est ce qui empêche la régression.

## Utilisation
```bash
# Créer la VM (une fois, ~15-25 min, zéro interaction)
ISO_WIN=~/Téléchargements/Win11_25H2_French_x64_v2.iso ./create-vm.sh

# Tester WAC (à chaque itération de code)
./run-wac-test.sh --build        # rebuild + test complet
./run-wac-test.sh --raw-only     # juste la validation raw_hive
./run-wac-test.sh --no-split     # sans l'étape 7 (--collect puis --convert, ~1 h)
python3 qga.py ping              # l'agent répond ?
python3 qga.py run --shell "dir C:\\"
```

## Prérequis hôte
`qemu-system-x86 libvirt-daemon-system libvirt-clients virtinst ovmf swtpm swtpm-tools xorriso`
plus `~/vms/virtio-win.iso` (guest-agent + drivers) et l'ISO Windows 11.

## Note
`virt-install --noautoconsole` ne relance pas la VM après le premier redémarrage de
Setup : `create-vm.sh` la redémarre au besoin et considère l'install terminée quand
le guest-agent répond (pas de capture d'écran à interpréter).

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
| `run-wac-test.sh` | Cycle de test complet : build → envoi des binaires → validation `raw_hive` (extraction brute + `reg load`) → exécution de WAC → rapatriement du log et des JSON dans `results/<horodatage>/`. |
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
| couples `X` / `XUtc` portant la même heure murale | double décalage horaire (`sessions`, `.lnk`, `InstallDate`) |
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
| `MANIFESTE.sha256` porte l'empreinte réelle de `MANIFESTE.json` | seul contrôle qui détecte une retouche du manifeste, lequel est précisément ce qui atteste des pièces |
| chaque pièce collectée porte ses trois empreintes | une pièce sans empreinte n'est pas identifiée, donc inutilisable |
| le lecteur système d'`OperatingSystem.json` figure dans les volumes lus du manifeste | deux sources indépendantes de la même information |
| les fichiers réellement présents dans `consigne/` sont exactement ceux du manifeste | 209 pièces ajoutées après le scellement, identifiées par rien, alors que tous les autres contrôles étaient verts |
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
relève dans la VM la liste des fichiers de `consigne/` (`LISTE.txt`), et
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

Le mode `--collecte` execute la chaine complete (fichier brut -> BinXML ->
`xml_light` -> `Event` -> JSON en flux) sur une arborescence imitant une
extraction, et `--collecte-memoire` la meme chose en accumulant tout en memoire
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

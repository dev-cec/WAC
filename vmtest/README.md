# VM de test Windows 11 — pilotage autonome de WAC

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
| aucune session antérieure au démarrage du système | le premier de ces décalages |
| états de service impossibles, taux de `*_UNKNOWN`, présence de pilotes | convertisseurs comparant des filtres d'énumération à des états |
| `RID` retrouvé à la fin du `SID` reconstruit | validation de la lecture du SAM |
| aucun processus ne porte `WAC.exe` parmi ses modules | le processus Idle héritait des modules de l'outil de collecte |
| `EvtSystemComputer` confronté au nom de machine de `OperatingSystem.json` | contrôle du décodage BinXML des journaux : deux sources sans rapport (fichier `.evtx` et ruche SYSTEM) |
| identifiants d'enregistrement uniques par canal | WAC parcourt **tous** les chunks physiques d'un `.evtx`, pas ceux déclarés par l'en-tête — c'est ce qui lui fait lire les enregistrements qu'un journal mal fermé ne compte pas ; le risque propre à ce choix est de relire un chunk périmé d'un journal circulaire, et ce contrôle le verrait |
| aucun événement postérieur à l'horodatage de collecte | décalage ou mauvaise lecture d'un `FILETIME` d'événement |

**Le harnais peut être la cause du défaut qu'il signale.** Un run de 604 s a été
coupé par le timeout de 600 s de `qga.py` juste avant l'écriture des deux
derniers JSON : le rapport disait « collecte probablement incomplète » — ce qui
était exact — mais WAC était allé au bout. Le journal de collecte (`run.log`,
qui se termine par `END, Time elapsed`) tranche entre les deux. Timeout porté à
30 min ; il faudra le revoir si la collecte s'allonge encore.

**Le parseur EVTX se valide hors VM.** Le décodage BinXML est trop fragile pour
n'être éprouvé que sur les journaux d'une VM neuve, tous écrits par la même
version de Windows et tous propres. `WAC/evtx_test.cpp` (exclu du build par le
motif `_test.cpp`) lit un `.evtx` et rend soit un bilan, soit le XML de chaque
enregistrement (`--dump`) ; il tourne sous `wine`, ce qui permet de le confronter
à des journaux réels — dont des journaux volontairement abîmés — et de comparer
enregistrement par enregistrement à une implémentation indépendante
(`python-evtx`). C'est ce qui a montré qu'un chunk à signature fausse arrêtait
la lecture de tout le fichier : 14 enregistrements lus sur 270.

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

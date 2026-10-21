# B-014 — Clichés instantanés lus en brut

| Statut | Priorité | Effort |
|---|---|---|
| en cours (version 3.0, après le harnais Vista) | P3 | fort |

## Pourquoi
Les anciennes versions des ruches et fichiers retrouvent ce qu'un intrus a effacé ; KAPE les parcourt avec --vss. WAC y a renoncé par principe (pas de service VSS).

## Source
Zone de différences du volume, lue sans le service : en-tête VSS à 0x1E00 du volume, catalogue (`System Volume Information\{3808876b-c176-4e48-b7ae-04046e6cc752}`), magasins (`{GUID}{3808876b-…}`) : en-tête du magasin (identifiant du cliché, du jeu, attributs, machines), liste des descripteurs de blocs de 16 Kio (bloc d'origine → copie dans le magasin ; relais, superpositions de 512 octets, blocs ignorés), bitmaps courante et précédente. Vista et suivants ; XP n'a pas de cliché persistant (ses points de restauration `_restore{…}` sont un autre artefact).

## Sortie attendue
- `shadow_copies.json` : un objet par cliché et par volume — volume, identifiant du cliché, du jeu, du magasin, instant de création (UTC), taille du volume, contexte et attributs nommés, machines d'origine et de service, nombre de blocs conservés.
- **Pièces** : pour chaque cliché, les fichiers que la collecte prend sur le volume courant (ruches, journaux, artefacts de fichiers selon `wac.yml`), relus à travers la vue du cliché, rangés sous `exhibits/vss/<instant>-<identifiant>/` avec leurs trois empreintes. Un fichier identique (SHA-256) à la version courante ou à celle d'un cliché plus récent n'est pas recopié : le manifeste le dit.
- **Conversion** : les pièces d'un cliché converties comme celles du volume courant (même JSON, sous `vss/<instant>-<identifiant>/`), pour que WAE compare les états.
- Une clé `shadow_copies` sous `artefacts:` de `wac.yml`.

## Conception
La vue d'un cliché s'insère sous le lecteur NTFS existant : `NtfsVolume::readBytes` lit, pour chaque bloc de 16 Kio, soit la copie que le magasin conserve, soit le volume courant — selon l'algorithme de libvshadow (magasins appliqués du plus récent au plus ancien, relais vers le magasin suivant, superpositions par secteur, bloc libre au moment du cliché rendu nul). Tout le reste (résolution des chemins, `$DATA`, décompression, empreintes) est inchangé. Le décodeur du format (`vss.cpp`) est du C++ portable, sans `windows.h`, testé sur une image réelle.

## Référence indépendante
- **libvshadow** (pyvshadow) sur l'image du volume de test : liste des clichés (identifiants, instants), et contenu de chaque cliché comparé bloc à bloc (SHA-256 de volumes entiers) ;
- **Windows lui-même** dans le harnais : un témoin écrit, un cliché créé (`Win32_ShadowCopy.Create`, le harnais peut user du service, WAC non), le témoin modifié ensuite ; sa version d'avant, lue par Windows via `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`, doit être celle que WAC rend.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun appel au service VSS ni à son API ; aucune écriture.
- Tous les clichés de la machine de test retrouvés, chacun identique à libvshadow bloc à bloc.
- Le témoin modifié après le cliché rendu dans son état d'avant, identique à Windows.

## Tâches
- [x] Décision de principe (2026-10-17 : lecture brute, sans le service)
- [x] Format du magasin de clichés (documentation et sources de libvshadow)
- [x] Image de test : volume de données d'une VM avec plusieurs clichés et fichiers modifiés entre eux ; référence pyvshadow
- [x] Décodeur `vss.cpp` : catalogue, en-têtes de magasins, descripteurs, bitmaps, lecture d'un cliché ; test synthétique (Wine) et image réelle
- [x] Vue cliché sous `NtfsVolume` (volumes partagés par lettre et cliché, `RawShadowCopies`, `ExtractFilesRaw` et `RawReader` par cliché)
- [x] Extraction des cibles par cliché (ruches, profils, `.evtx`), double lecture sur listes rafraîchies, dédoublonnage par SHA-256 (pièce partagée au manifeste, `ShadowCopyId`)
- [x] `shadow_copies.json` (relevé de collecte scellé, catalogue copié brut), clé `shadow_copies` de `wac.yml`, catalogue des artefacts par version
- [ ] Conversion des pièces de chaque cliché
- [x] Témoin et contrôles du harnais ; documentation FR et EN

## Journal
- 2026-10-07 : reportée en 3.0 (décision utilisateur).
- 2026-10-17 : décision utilisateur — à faire pour la 3.0.0, après le harnais sous Vista et avant les fichiers supprimés (B-036). Le principe reste : lecture brute de la zone de différences, sans le service VSS.
- 2026-10-21 : format étudié dans la documentation et les sources de libvshadow (Joachim Metz) ; sortie proposée sur le modèle de KAPE `--vss` (mêmes cibles relues par cliché, doublons écartés par empreinte), avec conversion pour comparer les états dans WAE.
- 2026-10-21 : **décodeur écrit et validé**. `vss.cpp` suit l'algorithme de libvshadow (descripteurs fusionnés : relais, superpositions par secteur, entrées ignorées ; magasins appliqués du plus récent au plus ancien ; bloc inutilisé du cliché le plus récent rendu nul). Test synthétique `vss_test` (26 contrôles aux réponses fixées à la main ; vu échouer sur trois défauts réintroduits : superposition appliquée à tous les clichés, blocs inutilisés non nuls, chaîne de relais non fusionnée). **Image réelle** : disque de 2 Gio ajouté à la VM Windows 8.1, NTFS, deux clichés (`Win32_ShadowCopy.Create`) avec un fichier témoin réécrit, un fichier supprimé, un fichier créé et 1 Mio d'un fichier de 24 Mio réécrit entre chacun. WAC et libvshadow (pyvshadow 20260714) : mêmes deux clichés, mêmes identifiants (magasin, cliché, jeu), instants, nombre de blocs (79 et 82), et **SHA-256 identique du volume entier reconstitué** pour chacun. Windows lui-même (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`) et dissect.ntfs sur les volumes reconstitués rendent les mêmes témoins (version 1 puis 2, fichier supprimé présent dans le premier seul, empreintes du gros fichier). Vue cliché branchée sous `NtfsVolume::readBytes` : la résolution des chemins et l'extraction ne changent pas.
- 2026-10-21 : **collecte par cliché écrite**, cycles VM en cours (Windows 11, 8.1, Vista, 7). Premier cycle Windows 11 : le cliché créé par le harnais est retrouvé (identifiant et instant identiques à `Win32_ShadowCopy`), 434 fichiers lus à travers lui, 36 stockés parce qu'ils diffèrent, 398 identiques à leur version actuelle et inscrits comme partagés. Observé : le fichier de base de `SOFTWARE` est le même dans le cliché et sur le volume (non réécrit depuis le 13/10), seul `SOFTWARE.LOG1` diffère — Windows 8.1 et suivants écrivent d'abord dans les journaux de la ruche. Défauts du harnais corrigés : l'empreinte de Windows à travers le périphérique du cliché ne sortait pas (`certutil` appelé depuis PowerShell, désormais par `cmd`) ; les contrôles qui cherchent une pièce par son chemin source tombaient sur la version d'un cliché (le manifeste chargé met désormais les pièces des clichés à part).
- 2026-10-21 : **Windows 8.1** : les 3 clichés de C: retrouvés (dont celui que Windows avait pris le 13/10), et les 4 fichiers lus en brut dans le cliché du harnais au SHA-256 identique à la lecture de Windows par le périphérique du cliché. **Vista** : création de cliché possible ; WAC voyait un cliché de plus que Windows — celui du cycle précédent, supprimé au début de celui-ci. Mesuré dans le catalogue (disque de la VM lu sur l'hôte) : son entrée de type 2 porte les drapeaux 0x140, les autres 0x40 ; c'était le plus récent quand il a été supprimé, et un cliché plus ancien se lit à travers son magasin, que Windows garde donc. Sous 8.1, le plus ancien de deux clichés supprimé : son entrée quitte le catalogue. Le bit 0x100 marque un cliché supprimé dont le magasin est gardé (inconnu de libvshadow, qui le listerait comme les autres) : rendu `Deleted`, lu comme les autres, son magasin étant intact. Le `certutil` de Vista ne calcule que le SHA-1 : le harnais s'y rabat.
- 2026-10-21 : **premier volet validé** (collecte des clichés et liste). Cycles : Vista 355 ✅ 0 ❌, Windows 7 378 ✅ 0 ❌ ; Windows 8.1 et 11 : contrôles des clichés verts, leurs échecs restants dus au harnais et corrigés (rejoués verts). Partout, les fichiers lus en brut dans le cliché du harnais ont l'empreinte que Windows calcule à travers le périphérique du cliché (SHA-256, SHA-1 sous Vista). Le bit 0x100 (cliché supprimé, magasin gardé) vu sous Vista et Windows 7. Windows purge de lui-même le plus ancien cliché quand leur place est pleine (VolSnap 33, Vista) : le harnais relève la liste avant et après la collection. Reste le second volet : conversion des pièces de chaque cliché.

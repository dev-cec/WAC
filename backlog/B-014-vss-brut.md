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
- [ ] Image de test : volume de données d'une VM avec plusieurs clichés et fichiers modifiés entre eux ; référence pyvshadow
- [ ] Décodeur `vss.cpp` : catalogue, en-têtes de magasins, descripteurs, bitmaps, lecture d'un cliché ; test sur l'image (Wine)
- [ ] Vue cliché sous `NtfsVolume` ; extraction des cibles par cliché, dédoublonnage par SHA-256
- [ ] `shadow_copies.json`, clé `wac.yml`, catalogue des artefacts par version
- [ ] Conversion des pièces de chaque cliché
- [ ] Témoin et contrôles du harnais ; documentation FR et EN

## Journal
- 2026-10-07 : reportée en 3.0 (décision utilisateur).
- 2026-10-17 : décision utilisateur — à faire pour la 3.0.0, après le harnais sous Vista et avant les fichiers supprimés (B-036). Le principe reste : lecture brute de la zone de différences, sans le service VSS.
- 2026-10-21 : format étudié dans la documentation et les sources de libvshadow (Joachim Metz) ; sortie proposée sur le modèle de KAPE `--vss` (mêmes cibles relues par cliché, doublons écartés par empreinte), avec conversion pour comparer les états dans WAE.

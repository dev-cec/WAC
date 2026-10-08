# B-036 — Récupération des fichiers supprimés par lecture brute du disque

| Statut | Priorité | Effort |
|---|---|---|
| à décider (étude, reportée en 3.0) | P2 | fort |

## Pourquoi
mft.json liste déjà les fichiers supprimés dont l'enregistrement n'est pas encore réutilisé (`Deleted`), et usn_journal.json les suppressions, mais pas leur **contenu**. Or l'outil, le script ou l'archive qu'un intrus a effacés sont souvent encore sur le disque : le contenu reste dans des clusters libres tant que NTFS ne les a pas réattribués. Le récupérer **en lisant le volume en brut** (`\\.\X:`, comme $MFT et $UsnJrnl aujourd'hui) ne laisse aucune trace sur la machine examinée : aucun fichier ouvert par le système, aucun outil de récupération installé ou lancé dessus, aucune écriture sur le volume. Demande utilisateur du 2026-10-01.

## Source
Trois niveaux, à étudier dans cet ordre :
1. **Enregistrements supprimés de la $MFT** : un enregistrement `Deleted` garde son attribut `$DATA` — résident (contenu dans l'enregistrement même, ≤ ~700 octets) ou non résident (liste de plages de clusters). Les plages sont relues sur le volume, après vérification dans `$Bitmap` que les clusters sont toujours libres. Un cluster réattribué depuis appartient à un autre fichier : le contenu récupéré serait faux et valide en apparence.
2. **Entrées supprimées des index de répertoires** (slack des `$INDEX_ALLOCATION`) : noms et références d'enregistrements déjà réutilisés.
3. **Découpage de l'espace libre par signatures** (carving : PE `MZ`, ZIP/Office, PDF, scripts…) : des fichiers dont même l'enregistrement a disparu. Volumineux et peu sûr ; à décider séparément.
Les volumes FAT/exFAT (fat_volumes.json, entrées supprimées déjà relevées) suivent les mêmes niveaux : premier cluster et taille dans l'entrée, chaîne de la FAT effacée.

## Sortie attendue
À définir par l'étude. Piste : un artefact à sa clé de `wac.yml` (`deleted_files`), qui copie dans la consigne le contenu récupéré de chaque fichier supprimé retenu, avec son empreinte, la part récupérée (clusters libres / réattribués), et un JSON qui les relie à leur enregistrement de mft.json (Volume + Entry + Sequence). Un binaire récupéré passe par le même traitement que les autres (signature, chaîne, liste de confiance) ; un malveillant suit la règle de la quarantaine (copie chiffrée, jamais en clair sur le support).

## Référence indépendante
Dans la VM : des fichiers de contenu connu (texte, exécutable, archive, un fichier fragmenté, un fichier résident) créés puis supprimés, le cache du volume écrit ; leur SHA-256 relevé avant suppression doit être retrouvé. Puis un fichier supprimé dont les clusters sont réécrits ensuite : il doit être déclaré non récupérable, jamais rendu faux. Recoupement avec `ntfsundelete` (ntfs-3g) sur l'image du volume, et photorec pour le niveau 3.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Décision de principe avant tout développement : quels niveaux, quels fichiers (tous les supprimés, ou filtrés par type, taille, date), plafond de taille et de durée, sort des malveillants.
- Lecture seule du volume, rien d'écrit sur la machine examinée : contrôle d'innocuité vert, dossier d'innocuité mis à jour.
- Un contenu n'est jamais publié comme récupéré si un de ses clusters est réattribué : récupération partielle signalée comme telle.
- Lectures bornées : une liste de plages forgée (longueur, décalage hors volume, boucle) est refusée.
- Limites documentées : SSD et TRIM (clusters libérés remis à zéro par le disque), fichiers compressés ou chiffrés (EFS), BitLocker (volume lu déchiffré par le système, comme aujourd'hui).

## Tâches
- [ ] Étude : volumes de données en jeu sur une machine réelle (nombre de supprimés récupérables, taille), effet de TRIM sur la VM et sur un SSD
- [ ] Décision de principe (niveaux, filtres, plafonds, malveillants)
- [ ] Niveau 1 : $DATA résident des enregistrements supprimés
- [ ] Niveau 1 : $DATA non résident, contrôle par $Bitmap
- [ ] Niveau 2 : slack des index
- [ ] Niveau 3 : carving (si retenu)
- [ ] FAT/exFAT

## Journal
- 2026-10-01 : créée à la demande de l'utilisateur — récupérer le contenu des fichiers supprimés par lecture brute du disque, pour ne laisser aucune trace sur la machine examinée.
- 2026-10-08 : reportée en 3.0 (décision utilisateur).

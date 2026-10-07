# B-026 — Cache des miniatures (thumbcache)

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | moyen |

## Pourquoi
Les miniatures d'images et de documents vus dans l'Explorateur restent dans le cache après la suppression du fichier : elles montrent ce qu'un utilisateur a eu sous les yeux.

## Source
`AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db` de chaque profil (format CMMM).

## Sortie attendue
`thumbcache.json` (identifiant, taille, empreinte de chaque miniature) ; miniatures extraites en pièces.

## Référence indépendante
Image vue dans l'Explorateur de la VM, sa miniature retrouvée ; thumbcache_viewer ou implémentation publiée sur les mêmes fichiers.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- lectures bornées (en-têtes CMMM forgés) ;
- miniature témoin retrouvée.

## Tâches
- [x] Format CMMM (versions Windows 10/11) — étudié sur des fichiers de la VM, sommes de contrôle identifiées
- [ ] Prélèvement brut, conversion, pièces

## Journal
- 2026-09-29 : détaché de B-012.
- 2026-10-07 : en cours — étude du format (CMMM) et de la référence indépendante.
- 2026-10-07 : format relevé sur trois fichiers de la VM (copies brutes, retirées ensuite). En-tête de fichier, 24 octets : « CMMM », version 0x20 (Windows 10/11), type (0 = 16 px, 2 = 48, 4 = 256…), inconnu, décalage de la première entrée (0x18), de la première place libre. Entrée, 56 octets : « CMMM », taille, hachage 64 bits, longueur de l'identifiant (octets UTF-16), bourrage, taille des données, largeur, hauteur, inconnu, somme des données, somme de l'en-tête ; puis identifiant (le hachage en hexadécimal), bourrage, image (BMP, PNG, JPEG). Les iconcache_*.db ont le même format.
- 2026-10-07 : sommes de contrôle — CRC-64 octet par octet, polynôme réfléchi 0x92C64265D32139A4 (table de thumbcache.dll, selon thumbcache_viewer). En-tête : sur les 48 premiers octets, valeur initiale −1. Données : jusqu'à 1 024 octets, CRC des données (initiale 0) ; au-delà, CRC des 1 024 premiers octets XOR un second CRC (initial 0) qui ne prend que 4 octets toutes les 400 positions à partir de 1 024. Vérifié : 322 entrées sur 322 (iconcache_48.db), 7 sur 7 (thumbcache_16.db). Ce sera la référence de format ; le témoin, une image vue dans l'Explorateur dont Windows donne System.ThumbnailCacheId.

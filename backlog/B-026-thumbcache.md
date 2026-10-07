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
- [ ] Format CMMM (versions Windows 10/11)
- [ ] Prélèvement brut, conversion, pièces

## Journal
- 2026-09-29 : détaché de B-012.
- 2026-10-07 : en cours — étude du format (CMMM) et de la référence indépendante.

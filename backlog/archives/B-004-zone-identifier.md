# B-004 — Flux Zone.Identifier (Mark of the Web)

| Statut | Priorité | Effort |
|---|---|---|
| fait (581c377) | P2 | faible |

## Pourquoi
Donne l'origine d'un fichier téléchargé (ZoneId, ReferrerUrl, HostUrl) : relie un binaire suspect à son URL.

## Source
Flux nommés `Zone.Identifier` repérés dans la $MFT (champ `Streams` de mft.json).

## Sortie attendue
`zone_identifiers.json` : fichier, ZoneId, ReferrerUrl, HostUrl ; clé `zone_identifiers`.

## Référence indépendante
Fichier téléchargé par le harnais avec `Invoke-WebRequest` puis marqué ; `Get-Content -Stream Zone.Identifier` en référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Tous les flux Zone.Identifier du volume système lus en brut, sans ouvrir de fichier.

## Tâches
- [x] Contenu lu dans la copie de la $MFT (flux résident) ; non résident signalé avec sa taille (ContentNotResident)
- [x] Décodeur (UTF-8 ou UTF-16), noms de zones — file_artefacts_test 37/0
- [x] Témoin VM : fichier marqué téléchargé par Set-Content -Stream, relu par Windows

## Journal
- 2026-09-29 : décision — lire le flux dans la copie de la $MFT (il y est résident) plutôt qu'extraire chaque flux : aucune lecture de plus sur la machine examinée. `Mft::forEachFile` ajouté (parcours public avec chemin) ; clé `zone_identifiers` ; la $MFT est prélevée dès que cet artefact est demandé. Cycle VM lancé.
- 2026-09-29 : cycle VM vert (témoin retrouvé, zone 3, HostUrl) ; commité (581c377), fiche archivée.

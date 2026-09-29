# B-004 — Flux Zone.Identifier (Mark of the Web)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | faible |

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
- [ ] Lecture brute des flux nommés résidents et non résidents
- [ ] Décodeur INI
- [ ] Témoin VM

## Journal
- (vide)

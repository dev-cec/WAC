# B-045 — Scripts de WinSxS et de WindowsApps en échec 0x80004005 à la lecture des exécutables

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | faible |

## Pourquoi
Mesure de l'empreinte (B-027), collecte seule avec `binary: unverified` (réglage par défaut) : sur 67 882 pièces du manifeste, 144 sont en échec `0x80004005 Erreur non spécifiée` — 110 scripts d'un paquet de `C:\Program Files\WindowsApps` (MicrosoftWindows.Client.WebExperience), des `winrm.cmd` et `.js` de `C:\Windows\WinSxS`, de `SystemApps`, d'`EdgeCore`. Le cycle de la VM ne les voit pas : il ne lit pas chaque exécutable de cette façon. Un fichier non lu est une pièce manquante, et l'erreur ne dit pas pourquoi.

## Source
`binaires.cpp` (lecture de chaque exécutable, prélèvement des non authentifiés), lecture brute NTFS ; les fichiers en cause sont peut-être compressés (WOF) ou des liens physiques de WinSxS.

## Sortie attendue
Chaque script lu, ou son échec nommé (cause précise dans `Result`).

## Référence indépendante
`Get-FileHash` dans la VM sur les mêmes fichiers ; attributs NTFS (`fsutil file layout`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Plus aucun `0x80004005` sur ces fichiers, empreintes égales à `Get-FileHash`.

## Tâches
- [ ] Reproduire sur un fichier, trouver la cause
- [ ] Corriger, contrôle dans le cycle (collecte avec lecture de chaque exécutable)

## Journal
- 2026-10-08 : créée pendant B-027.
- 2026-10-08 : en cours — recherche de la cause.

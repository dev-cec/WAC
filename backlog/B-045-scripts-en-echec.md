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
- [x] Reproduire sur un fichier, trouver la cause
- [ ] Corriger, contrôle dans le cycle (collecte avec lecture de chaque exécutable)

## Journal
- 2026-10-08 : créée pendant B-027.
- 2026-10-08 : en cours — recherche de la cause.
- 2026-10-08 : cause trouvée. Les 144 fichiers sont de petits scripts à nombreux liens physiques (winrm.cmd : 7 liens, 33 octets) : leurs $FILE_NAME débordent l'enregistrement, NTFS déplace des attributs dans un enregistrement d'extension listé par $ATTRIBUTE_LIST — dont le $DATA RÉSIDENT. extractDataUnchecked ne cherchait dans la liste que des fragments non résidents : E_FAIL. Correctif : findResidentAttr, qui servait à $INDEX_ROOT, prend un nom de flux et sert aussi à $DATA. Vérifié sur le clone de mesure : collecte seule, plus aucun 0x80004005, les 144 fichiers au SHA-256 de Get-FileHash. Témoin du cycle : C:\wactest\b045\wac-links.cmd (8 liens à noms longs, $ATTRIBUTE_LIST vérifié par fsutil), cité par une valeur Run ; contrôle check-json (collecte seule) : échoue avec le binaire d'avant (0x80004005), passe avec le correctif. Cycle complet de non-régression lancé.

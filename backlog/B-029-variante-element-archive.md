# B-029 — Variante d'élément d'archive mal décodée

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | faible |

## Pourquoi
Dans la collecte réelle du 15/09 (ravenwood), certains éléments de shell classés ARCHIVE_FILE_CONTENT (types 0x3b, 0x00) sortent avec un nom illisible (« \x10\x01 01/01/1980  00:00:00 »). La date sous forme de texte est lue à la place du nom : c'est une variante dont les décalages diffèrent. Vu dans B-028.

## Source
Shellbags d'une machine réelle. Les ruches brutes de ravenwood n'ont pas été gardées : il faut une nouvelle collecte réelle qui conserve sa consigne.

## Sortie attendue
Nom et date de l'élément justes, ou l'élément signalé non décodé.

## Référence indépendante
ShellBagsExplorer / SBECmd (outils Zimmerman) sur la même ruche.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les éléments de la variante lus comme SBECmd les lit.

## Tâches
- [x] Cause trouvée sans nouvelle collecte : octets lus dans la VM (BagMRU) et formats de libfwsi et de Lnk (Zimmerman)
- [x] Décodeur réécrit : ZIP (Windows 10+ et XP, date en texte), archives lues par libarchive (7z, tar : FILETIME UTC) ; tailles, méthode, CRC-32
- [x] Test shell_items_test (éléments réels de la VM, synthétiques, troncatures sous page de garde) ; dates en texte sans secondes dans system_conversions_test
- [ ] Témoin 7z / tar.gz dans la VM (section 16), contrôle check-json, cycle VM, comparaison SBECmd
- [ ] Documentation (manuels FR/EN), commit, archivage

## Journal
- 2026-09-30 : sorti de B-028, qui traitait les fuseaux ; ce défaut est de décodage.
- 2026-10-07 : en cours — recherche d'un échantillon de la variante et lecture du décodeur.
- 2026-10-08 : cause trouvée. L'élément ZIP de la VM (dossier winterdir, lu dans BagMRU) porte sa date en texte à 0x24 et son nom à 0x5C ; selon libfwsi, 0x08 et 0x10 sont les tailles de l'entrée. WAC prenait 0x08 pour une date FAT et 0x10 pour un FILETIME : un fichier du ZIP (tailles non nulles) donnait une date tirée de ses tailles et, nom lu à 0x20, « \x10\x01 » suivi de la date en texte — exactement ravenwood. Un dossier, sans tailles, passait : défaut invisible en VM. La forme FILETIME existe pourtant : c'est celle des archives que Windows 11 lit par libarchive (7z et tar.gz mesurés : FILETIME UTC à 0x10, nom à 0x20). Essai sans suite : un ZIP dans un ZIP, que l'Explorateur n'ouvre pas.

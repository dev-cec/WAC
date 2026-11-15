# B-089 — Contexte de liaison : système de fichiers

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
MFT, journal USN, fichiers supprimés, corbeille, FAT.

## Contexte à écrire
`Kind` `Presence`, `Creation`, `Modification`, `Deletion` (tiré des `Reasons` de l'USN) ; `Subject.Path` et `Subject.Ntfs` ; propriétaire (`$Secure`) en `Actor.Sid` quand il est lu ; renommage : ancien nom en `Related`.

## Référence indépendante
Cycle `win11-test` : fichier témoin créé, renommé, supprimé : la même référence NTFS d'un bout à l'autre ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Ce qui est écrit
| JSON | `Kind` | Sujet | `Related` | `Evidence` |
|---|---|---|---|---|
| `mft.json` | `Presence`, ou `Deletion` pour un enregistrement libre | `Path` (s'il est complet), `Ntfs` | `HardLink` : les autres noms | `C:\$MFT` |
| `usn_journal.json` | `Deletion` si `FILE_DELETE`, `Creation` si `FILE_CREATE`, sinon `Modification` | `Path` (s'il est complet), `Ntfs` | — | `C:\$Extend\$UsnJrnl:$J` |
| `deleted_files.json` | `Deletion` ; `Modification` pour un nom de l'index `$I30` que le fichier porte autrement aujourd'hui | `Path`, `Ntfs` (NTFS), `Sha256` seulement si le contenu est revenu entier (`Recovered`, ou taillé `Carved`) | `CurrentName` | `C:\$MFT`, le dossier `:$I30`, ou `\\.\C:` (FAT, taille) |
| `recycle_bin.json` | `Deletion` | `OriginalPath` | `RecycledCopy` : le `$R`, ou le `D<lettre><n>` d'INFO2 | le `$I` ou INFO2 ; acteur : le SID du dossier |
| `fat_volumes.json` | `Presence`, ou `Deletion` | `Path`, sauf nom amputé de sa première lettre | — | `\\.\I:` |

Pas d'empreinte pour un contenu `Partial`, ni pour un fichier FAT lu en
supposant ses grappes contiguës (`RecoveredIfContiguous`) : ce ne serait pas
celle du fichier, et elle le relierait à un autre. Le propriétaire (`$Secure`)
n'est pas lu par WAC (`SecurityId` seul) : pas d'`Actor.Sid` dans la MFT ni
l'USN. Un renommage de l'USN est deux enregistrements (`RENAME_OLD_NAME`,
`RENAME_NEW_NAME`) de la même identité NTFS : WAE les relie par `Ntfs`.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit dans les cinq JSON (tableau ci-dessus) ;
  `addDeletedContext` commun aux quatre sources des fichiers supprimés,
  `rawVolumeEvidence` dans `context.cpp`. Tests : `usn_journal_test`
  (création, modification, suppression), `file_artefacts_test` (MFT, fichiers
  supprimés, corbeille Vista et XP, FAT). Contrôle `check_context_filesystem`
  écrit ; rejoué sur une collecte d'avant : il échoue sur chaque
  enregistrement, comme attendu. Compilation avec mutation en cours.

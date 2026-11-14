# B-081 — Amcache sur Windows 11 récent : l'inventaire passé en bases SQLite (`Inventory*.db`)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Trouvé par l'étude B-078 sur `win11-test` (Windows 11 26H2, build
26300), le 2026-11-14 : `amcache_applications.json` et
`amcache_inventory.json` sont vides, alors que la tâche d'évaluation de
compatibilité (`Microsoft Compatibility Appraiser Exp`, nom de cette
version) est passée. Ce n'est pas une VM trop neuve : Windows écrit
désormais l'inventaire dans des **bases SQLite** à côté de la ruche, dans
`C:\Windows\appcompat\Programs\` :

| Base | Table | Exemple de contenu (relevé) |
|---|---|---|
| `InventoryApplication.db` | `InventoryApplication_0` (113 lignes) | `ProgramId`, `Name`, `Version`, `Publisher`, `InstallDate`, `UserSid`, `Source`, `PackageFullName`, `ManifestPath`… |
| `InventoryApplicationShortcut.db` | `InventoryApplicationShortcut_0` (44) | `ShortcutPath`, `ShortcutTargetPath`, `ShortcutAumid`, `ShortcutProgramId`, `LastModified` (FILETIME) |
| `InventoryApplicationFile.db` | (ouverte en exclusif par Windows : lecture brute NTFS) | — |
| `InventoryDevicePnp.db` | `InventoryDevicePnp_2` (102) | `Model`, `Manufacturer`, `ParentId`, `InstallDate`, `FirstInstallDate`… |
| `InventoryDriverBinary.db` | `InventoryDriverBinary_2` (400) | `DriverName`, `DriverCompany`, `DriverVersion`, `DriverSigned`, `DriverTimeStamp`… |
| `InventoryApplicationAppV`, `…Driver`, `…Framework`, `InventoryDevice*` (Container, Interface, MediaClass, Pci, Sensor, UsbHubClass), `InventoryDriverPackage`, `InventoryAcpiPhat*`, `InventoryMiscellaneous*`, `DeviceCensus`, `DriverPackageExtended`, `Mare`, `MareBackupApps` | une table `<Nom>_N` + `Metadata_N` | à relever |

`Amcache.hve` garde `InventoryApplicationFile` (387 entrées converties
dans `amcache_application_files.json`) ; les programmes, raccourcis,
appareils et pilotes n'y sont plus. Sur ces versions, WAC perd donc
l'inventaire des logiciels installés et des appareils : la date et le SID
d'installation d'un programme, le lien raccourci → exécutable → programme
(`ProgramId`), indispensables au dossier d'un logiciel (B-078, WAE E-014).

Le suffixe de table (`_0`, `_2`) varie d'une base à l'autre : il se lit
dans `sqlite_master`, jamais en dur.

## À faire
- Prélever `appcompat\Programs\*.db` (avec leurs `-wal`/`-journal` s'ils
  existent) par lecture brute, comme la ruche, sous la clé `amcache` de
  `wac.yml` (dépendance de l'artefact, pas une clé de plus).
- Convertir par `sqlite_reader` : une entrée par ligne, colonnes nommées
  comme dans la base, valeurs vides non émises ; FILETIME (`LastModified`)
  en UTC ; `InstallDate` gardée telle qu'écrite (format local, pas un
  instant) avec son format relevé.
- Sortie : remplir `amcache_applications.json` et `amcache_inventory.json`
  avec la même forme que depuis la ruche, champ `Source` indiquant la base
  — ou un JSON par famille : à décider en regardant les deux formes.
- Relever le format sur une collecte réelle (versions de Windows qui ont
  les bases : à dater par build), et sur les versions qui ont les deux
  (ruche et bases) : pas de doublon, pas de perte.

## Référence indépendante
Le module `sqlite3` de Python lit les bases copiées depuis `working/` :
nombre de lignes par table et valeurs, comparés au JSON de WAC ligne à
ligne dans `check-json.py`.

## Journal
- 2026-11-14 : fiche créée (étude B-078) ; bases listées et quatre
  d'entre elles lues sur `win11-test` 26300.

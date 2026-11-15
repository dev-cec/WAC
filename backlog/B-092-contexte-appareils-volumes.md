# B-092 — Contexte de liaison : appareils et volumes

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
USBSTOR, `devices`, `setupapi`, `mount_points`, `mounted_device`, `ntfs_volumes`, `fat_volumes`, `shadow_copies`.

## Contexte à écrire
`Kind` `Installation` (appareil) ou `Access` (volume) ; `Subject.Device` (identifiant d'instance) et `Subject.Serial` ; `Related` le volume (GUID, lettre, numéro de série) : la chaîne appareil ↔ volume ↔ lettre ↔ numéro de série que lisent les raccourcis (B-090).

## Référence indépendante
Cycle `win11-test` : clé USB virtuelle du harnais : même numéro de série de l'appareil aux raccourcis qui en ouvrent un fichier ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Ce qui est écrit
| JSON | `Kind` | Sujet | Autres |
|---|---|---|---|
| `Usbstor.json` | `Installation` | `Device`, `Serial` | SYSTEM |
| `devices.json` | `Installation` | `Device` (clé d'`Enum`, chemin d'interface, appareil portable), `Serial` ; rien pour `VolumeInfoCache` | SYSTEM ou SOFTWARE |
| `mounted_device.json` | `Configuration` | `Device` | `Related` `Volume` : son GUID ou sa lettre |
| `mount_points.json` | `Access` | `Volume` (GUID), ou l'hôte d'un partage | acteur ; `NTUSER.DAT` |
| `setupapi.json` | `Installation` | `Device`, ou le chemin d'un paquet de pilote | le journal |
| `ntfs_volumes.json` | aucun | le volume (`C:\`), `Serial` (celui des raccourcis et du Prefetch) | `$Boot` |
| `shadow_copies.json` | aucun | le volume | — (lu en direct dans VSS) |
| événements PnP, Amcache `InventoryDevicePnp` | (B-086, B-081) | `Device` et `Serial` ramenés à la même forme | |

**Une seule forme d'appareil** (`contextDevice`) : `enumérateur\appareil\instance`
en majuscules, depuis la clé du registre, l'événement PnP, Amcache
(`usbstor/disk&…`), un chemin d'interface (`##?#USBSTOR#…#{GUID}`) ou un
appareil portable (`SWD#WPDBUSENUM#_??_USBSTOR#…`). Mesuré sur la collecte
du cycle de B-089 : `devices.json` citait le même témoin sous cinq formes.
Le numéro de série vient de l'instance (`deviceSerial`, une fonction aussi
pour `Usbstor.json`), en majuscules (`contextSerial`).

**Ajout au schéma** : `Volume`, le GUID d'un volume (`{…}` en minuscules),
dans `ContextObject`. B-078 nomme ce GUID parmi les identités d'un volume ;
aucun champ ne le portait. Validé par l'utilisateur le 2026-11-15.

**Renommage préalable** : trois JSON avaient déjà un champ `Context` à eux,
que le bloc de liaison aurait doublé : `shadow_copies.json` (contexte VSS →
`SnapshotContext`), `dns_server.json` (colonne du journal → `DnsContext`),
`intune_logs.json` (attribut CMTrace → `LogContext`). Ni WAE ni le harnais
ne les lisaient sous ce nom. Validé par l'utilisateur le 2026-11-15.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [x] Témoins et contrôles du harnais ; cycle vert
- [x] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit (tableau ci-dessus), tests dans
  `file_artefacts_test` ; contrôle `check_context_devices` préparé : la
  chaîne WACUSB0001 ↔ `{9bbdb386-…}` ↔ `I:` d'après `Win32_Volume`
  (`reference/volumes.txt`), le numéro de série de chaque volume NTFS, et
  la forme unique de chaque appareil cité. Mutation vue échouer
  (majuscules retirées de `contextDevice` : trois tests), restauration,
  `bin/WAC.exe` identique.
- 2026-11-15 : cycle `win11-test` (`abfbf7d9`) : `check_context_devices` vert — WACUSB0001 ↔ `{9bbdb386-…}` ↔ `I:`, WACUSB0002 ↔ `{9bbdb391-…}` ↔ `J:`, les numéros de série de `C:` et `H:`, 272 appareils sous une seule forme.
- 2026-11-15 : l'utilisateur valide l'ajout du champ `Volume` au schéma et
  les renommages `SnapshotContext`, `DnsContext`, `LogContext`.

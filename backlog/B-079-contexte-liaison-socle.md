# B-079 — Contexte de liaison : socle commun (`Context`, volumes, profils)

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

## Pourquoi
Ce que toutes les familles de B-078 partagent, fait une fois : l'écriture du
bloc `Context` (une fonction, comme `Json::add`, champs vides non émis), la
carte des volumes et celle des profils, l'origine de chaque enregistrement.

## Contenu
- `Context` : type et écriture communs, appelés par chaque collecteur ;
  schéma arrêté par B-078.
- `investigation.json` → `Host.Volumes` : lettre, nom de périphérique
  (`\Device\HarddiskVolumeN`), GUID de volume, numéro de série (NTFS et FAT),
  relevés au moment de la collecte ; `Host.Profiles` : SID ↔ dossier de
  profil ; la résolution des chemins de périphérique et `\VOLUME{…}` par
  cette carte.
- `Evidence.Path` : le fichier source de l'enregistrement, distinct du sujet.
- `EnablePrefetcher` relevé (le Prefetch est désactivé par défaut sur les
  serveurs : son absence se lit, elle ne se devine pas).

## Référence indépendante
La carte des volumes égale à `mountvol`/`Get-Volume` dans la VM ; les
profils à `ProfileList` lue par l'hôte ; témoins des chemins de périphérique
résolus.

## Tâches
- [x] Type `Context` (`context.h`/`.cpp` : `ContextKind`, `ContextObject`,
      `RecordContext`, `addContext`), écriture commune, test unitaire
- [x] `Host.Volumes` (relevé : nom de périphérique par `QueryDosDeviceW`,
      GUID), `Host.Profiles`, `onDriveLetter` (périphérique, GUID ; test)
- [x] Contrôle du harnais : `Host.Volumes` contre `Win32_Volume` (référence
      `volumes.txt` prise dans la VM) et chemins de BAM présents dans la MFT
- [x] `Evidence.Path` (dans le type ; écrit par chaque famille)
- [x] `EnablePrefetcher` : déjà écrit dans `OperatingSystem.json` (relevé)

## Journal
- 2026-11-14 : fiche créée avec B-078.
- 2026-11-14 : type `Context`, `Host.Volumes`, `Host.Profiles`,
  `onDriveLetter` écrits avec leurs tests (non compilés : cycle B-081 en
  cours) ; `EnablePrefetcher` déjà relevé. Reste : compiler, mutation,
  contrôle du harnais (après le cycle), cycle.
- 2026-11-14 : compilé sans avertissement, `file_artefacts_test` 341/341 ;
  mutations vues échouer (préfixe de périphérique sans séparateur :
  `HarddiskVolume3` prenait `HarddiskVolume31` ; SysWOW64 rendu à
  System32), restaurées, recompilées, `bin/` = compilation. Aides du socle
  ajoutées : `contextPath` (forme unique d'un chemin), `contextNtfs`,
  `setFileObject`, `knownFolderPath`, `systemHiveEvidence`,
  `userHiveEvidence`. Manuels FR et EN (section « Le contexte de
  liaison »). Reste : cycle VM.

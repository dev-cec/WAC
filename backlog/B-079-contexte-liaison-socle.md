# B-079 — Contexte de liaison : socle commun (`Context`, volumes, profils)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
- [ ] Après B-078 : type `Context`, écriture commune, test unitaire
- [ ] `Host.Volumes`, `Host.Profiles`, résolution des chemins de périphérique
- [ ] `Evidence.Path`, `EnablePrefetcher`

## Journal
- 2026-11-14 : fiche créée avec B-078.

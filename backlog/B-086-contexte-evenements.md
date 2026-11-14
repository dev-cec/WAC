# B-086 — Contexte de liaison : événements

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
`events`, `rdp_server`, `shadow_copy_events` (Security, Sysmon, SCM, BITS, PowerShell, TaskScheduler, sessions de bureau, WMI, Defender, MSI, PnP).

## Contexte à écrire
la table des rôles de B-078 (identifiant → `Kind`, `Subject`, `Actor`, `How`) ; `LogonId` et `ProcessGuid` en clés ; le compte du fournisseur n'est pas l'acteur ; une ligne par identifiant de la table, rien deviné pour les autres (`Kind` seul quand il est sûr).

## Référence indépendante
Cycle `win11-test` : événements du harnais de valeur connue (4720 du compte témoin, 7045 du service témoin, 4688 d'un processus lancé, Sysmon 1) : rôles égaux aux valeurs posées ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-14 : `event_roles` (table des rôles : Security 4624/4625/4634/
  4647/4648/4672/4688/4697/4698/4702/4716-4718/4719/4720…4738/4728…4757/
  4781, Sysmon 1/3/5/11/23/26, SCM 7045, Eventlog 1102/104, BITS 59/60/
  16403, PowerShell 4104, TaskScheduler 106/200/201, sessions de bureau,
  Defender 1116/1117, PnP, Partition 1006, MSI) ; un identifiant hors table :
  pas de Context ; `-` et le SID nul ne sont pas des valeurs ; le compte du
  fournisseur n'est l'acteur que là où la table le dit. `Evidence` = le
  journal d'origine (courant, déplacé ou d'un cliché). `commandProgram`
  (socle) : le programme d'une commande sans ses arguments. Tests (rôles
  4688, 4624, 4732, 7045, Sysmon 1, hors table ; `commandProgram`) ;
  mutation (valeurs fictives prises pour des valeurs) vue échouer ; 348/348,
  `bin/` = compilation. Contrôle du harnais : rôles recalculés en Python
  pour chaque 4688, 4624, 4732, 7045 de la collecte ; témoin Sysmon (chemin,
  SHA-256 de Sysmon, GUID) ; rejoué sur la collecte sans Context : ❌ (vu).

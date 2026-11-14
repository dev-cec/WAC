# B-086 — Contexte de liaison : événements

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

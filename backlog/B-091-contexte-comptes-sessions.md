# B-091 — Contexte de liaison : comptes et sessions

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
`users`, `local_groups`, `Sessions`, `rdp_client`, `security`, `cloud_identity`, `dpapi_master_keys`.

## Contexte à écrire
`Kind` `Account` ou `Logon` ; `Subject.Sid` ; `Related` les membres d'un groupe ; `Actor.LogonId` d'une session ; `How.RemoteAddress`, `How.LogonType`.

## Référence indépendante
Cycle `win11-test` : compte témoin créé et ajouté à un groupe : `users`, `local_groups` et 4720/4732 (B-086) nomment le même SID ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Ce qui est écrit
| JSON | `Kind` | Sujet | Autres |
|---|---|---|---|
| `users.json` | `Account` | `Sid` | `Related` `Profile` : le dossier du profil ; `Evidence` : la SAM |
| `local_groups.json` | `Account` | `Sid`, `Name` | `Related` `Member` : chaque membre par son SID ; la SAM |
| `Sessions.json` | `Logon` | `Sid` | `Actor.LogonId` (`0x3e7`, la forme des événements), `How.LogonType` ; lu dans LSA : pas d'`Evidence` |
| `rdp_client.json` | `Logon` (connexion sortante) | la machine distante : `Host` ou `Address` | `Related` `Account` : le nom donné (`UsernameHint`, `username`) ; acteur ; la ruche ou le `.rdp` |
| `security.json` | `Account` (droits), `Configuration` (secrets LSA) | `Sid` ; `Name` du secret (`_SC_<service>`) | la ruche SECURITY |
| `cloud_identity.json` | `Account` | `User` (`UserEmail`), `Name` (la sous-clé) | acteur (WorkplaceJoin) ; SYSTEM ou `NTUSER.DAT` |
| `dpapi_master_keys.json` | aucun | `Sid` du propriétaire | le fichier de la clé |

`setRemoteObject` range une machine distante en nom ou en adresse IP, au
seul vu du texte : `inet_pton` viendrait de `ws2_32`, et la compilation
vérifie qu'aucune bibliothèque réseau n'est importée. `urlHost` sert d'unique
analyseur de `user@`, du port et de `[IPv6]`.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit (tableau ci-dessus), tests dans
  `file_artefacts_test` ; contrôle `check_context_accounts` préparé :
  `wacpw` dans `users.json` et membre de ses groupes ; les sessions
  interactives de LSA retrouvées par le `LogonId` de leur 4624 ; le serveur RDP
  témoin. Mutation vue échouer (`isIpv4` toujours faux), restauration,
  `bin/WAC.exe` identique.

# B-094 — Contexte de liaison : traces d'applications et serveurs

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
`server_logs`, `system_traces`, `remote_administration`, `messaging`, `ssh`, `vpn`, `file_transfer`, `cloud_storage`, `virtualisation`, `application_registry`, `intune_logs`, Active Directory, DNS, DHCP, serveurs web, `user_access_log`, `group_policies`.

## Contexte à écrire
`Evidence.Path` toujours (le fichier lu, **jamais** le sujet) ; `Subject` seulement où la ligne nomme un objet (hôte distant, SID d'un objet AD, bail DHCP adresse ↔ machine, client d'un site web) ; sinon `Kind` `Configuration`.

## Référence indépendante
Cycle `win11-test` : témoins des traces d'applications : `Evidence` égal au fichier posé, aucun `Subject` inventé ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Ce qui est écrit
| JSON | `Kind` | Sujet | Autres |
|---|---|---|---|
| les onze groupes de traces (`server_logs`, `system_traces`, `remote_administration`, `messaging`, `ssh`, `vpn`, `file_transfer`, `cloud_storage`, `virtualisation`, `antivirus`, `server_applications`), `intune_logs.json` | aucun | aucun : une ligne de texte libre ne nomme pas d'objet que WAC sache dire | `Evidence` : le fichier ; acteur : le compte du profil qui le contient (`profileOwner`) |
| `application_registry.json` | `Configuration` | la machine distante d'une session (`HostName`) | `Related` `Account` (`UserName`) ; acteur ; `NTUSER.DAT` |
| `active_directory_objects.json` | `Account` | `Sid`, `User` (`sAMAccountName`), `Name` (nom distinctif) | `ntds.dit` |
| `active_directory_links.json` | `Account` | l'objet | `Related` `Linked` : l'objet lié (membre, responsable…) |
| `dns_server_records.json` | `Configuration` | le nom défini | `Related` `Address` (A, AAAA) ; le fichier de zone |
| `dns_server_log.json` | `Network` | le client par son adresse | `Related` `Question` : le nom demandé |
| `dhcp_server_leases.json`, `dhcp_server_log.json` | `Network` | l'adresse attribuée | `Related` `Machine` : le client |
| `user_access_log.json` | `Access` | le client par son adresse | acteur : le compte, son SID s'il est local |
| `web_server_logs.json` (IIS, Apache, nginx) | `Access` | le client par son adresse | `How.Url` (la page), `How.Host` ; acteur : l'utilisateur |
| `web_server_sites.json` | `Configuration` | le site par son nom et son dossier racine | `applicationHost.config` |
| `web_server_connection_strings.json` | `Configuration` | la base par son fichier | le `web.config` |
| `group_policies.json` | `Configuration` | `Name` : le GUID de la stratégie | son dossier de SYSVOL |
| `hyperv_machines.json` | `Configuration` | — | le fichier de configuration |

Laissés sans `Context` : `web_server_application_pools`, `_modules`,
`_accounts`, `_installations`, `_database_engines`, `active_directory_replication`,
`_security_descriptors`, `dns_server_configuration`, `_zones`,
`dhcp_server_configuration`, `_scopes` : des réglages d'ensemble, qui ne
nomment ni fichier, ni compte, ni machine qu'un autre artefact cite.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit (tableau ci-dessus), tests dans
  `file_artefacts_test` ; contrôle `check_context_traces` préparé : chaque
  ligne des traces lue dans son propre fichier, aucun sujet inventé, le
  compte du profil d'après `Host.Profiles`. Défaut évité : le nom d'un
  enregistrement DNS est déjà absolu, sa zone ne s'y ajoute pas. Mutation
  vue échouer (`profileOwner` sans la borne du dossier : `C:\Users\wacky`
  pris pour le profil `C:\Users\wac`), restauration.

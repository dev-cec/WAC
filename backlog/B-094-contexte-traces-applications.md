# B-094 — Contexte de liaison : traces d'applications et serveurs

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

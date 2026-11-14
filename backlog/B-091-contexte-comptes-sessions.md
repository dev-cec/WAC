# B-091 — Contexte de liaison : comptes et sessions

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

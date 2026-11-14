# B-089 — Contexte de liaison : système de fichiers

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
MFT, journal USN, fichiers supprimés, corbeille, FAT.

## Contexte à écrire
`Kind` `Presence`, `Creation`, `Modification`, `Deletion` (tiré des `Reasons` de l'USN) ; `Subject.Path` et `Subject.Ntfs` ; propriétaire (`$Secure`) en `Actor.Sid` quand il est lu ; renommage : ancien nom en `Related`.

## Référence indépendante
Cycle `win11-test` : fichier témoin créé, renommé, supprimé : la même référence NTFS d'un bout à l'autre ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

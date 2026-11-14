# B-087 — Contexte de liaison : arrivées

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
Zone.Identifier, BITS, `web_client` (téléchargements et visites), courriels.

## Contexte à écrire
`Kind` `Arrival` ; `Subject` le fichier arrivé (chemin résolu, `Ntfs`) ; `How.Url`, `How.Host`, référent ; `Related` les fichiers d'un travail BITS, les pièces jointes ; `Actor.Sid` du profil.

## Référence indépendante
Cycle `win11-test` : téléchargement témoin (URL et chemin connus) : Zone.Identifier, `web_client` et MFT nomment le même `Subject` ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

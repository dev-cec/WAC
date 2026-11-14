# B-090 — Contexte de liaison : accès

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
raccourcis, jump lists, RecentDocs, shellbags, chemins tapés, recherches, Office, `activities_cache`, `search_index`, vignettes.

## Contexte à écrire
`Kind` `Access` ; `Subject` le fichier ou le dossier ouvert (cible du raccourci, `%USERPROFILE%` résolu) ; `How.VolumeSerial` (volume d'origine : amovible ou non) ; `Related` l'application (`Target` d'une jump list) ; `Actor.Sid` du profil.

## Référence indépendante
Cycle `win11-test` : document témoin ouvert : raccourci, jump list et RecentDocs nomment le même `Subject` ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

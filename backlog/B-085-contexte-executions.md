# B-085 — Contexte de liaison : exécutions

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
Prefetch, BAM, UserAssist, MUICache, SRUM, `program_usage`, `processes`, Amcache, ShimCache, `error_reports`.

## Contexte à écrire
`Kind` `Execution` (ou `Presence` pour Amcache et ShimCache : présence, pas exécution) ; `Subject` l'exécutable (chemin résolu : `\Device\HarddiskVolumeN`, dossiers connus de UserAssist, `.FriendlyAppName` de MUICache retiré, identité SRUM `!!exe!…` décodée ; chemin de l'image pour `processes`) ; `Related` les fichiers chargés du Prefetch ; `Actor.Sid` (BAM, UserAssist, MUICache, SRUM) ; empreintes complètes seulement (le SHA-1 d'Amcache tronqué au-delà de 30 Mio n'est pas `Sha1`).

## Référence indépendante
Cycle `win11-test` : témoin exécuté de chemin et d'empreinte connus : un même `Subject.Path` dans Prefetch, BAM, Amcache et `processes` ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

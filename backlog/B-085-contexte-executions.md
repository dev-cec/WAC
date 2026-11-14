# B-085 — Contexte de liaison : exécutions

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

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
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [x] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-14 : `Context` écrit pour Prefetch (sujet + fichiers chargés en
  `Related`, références NTFS), BAM (périphérique → lettre ; paquet →
  `Software`), UserAssist (dossier connu → dossier réel ; `UEME_CTL…` sans
  Context), MUICache (suffixe retiré ; `Evidence` = la ruche lue :
  UsrClass.dat, NTUSER.DAT avant Vista), SRUM (chemin, nom seul ou
  application ; tables réseau `Network`), processus (**chemin de l'image
  relevé** : premier module, ou `PROCESS_QUERY_LIMITED_INFORMATION` pour
  les processus protégés), Amcache (présence, installation, pilote,
  raccourci, appareil ; SHA-1 seulement s'il couvre tout le fichier),
  ShimCache (présence), `program_usage` (exécution ou réglage selon la
  source), rapports d'erreur. Constat : UserAssist nomme « System32 »
  System32 et SysWOW64 (`trans_id`) — le `Context` les distingue, le
  champ `Name` garde le défaut (à corriger à part). Contrôle du harnais :
  WAC lui-même pour témoin (chemin et SHA-256 du binaire calculé sur
  l'hôte, dans son processus et son Prefetch) ; aucun chemin laissé en
  `\Device\…` ou en variable. Reste : cycle VM.

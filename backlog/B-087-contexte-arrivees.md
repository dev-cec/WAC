# B-087 — Contexte de liaison : arrivées

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

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
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit : Zone.Identifier (le fichier, son
  `HostUrl` et son hôte ; `Evidence` = le flux), BITS (fichiers de
  destination, source, programme notifié en `Related`, propriétaire),
  `web_client` (téléchargement = arrivée du fichier ; visite, URL, recherche,
  cache, cookie = accès à un hôte ou à un fichier local `file:///` ; login
  enregistré, saisie, prédiction, icône = réglage ; **téléchargement
  d'Internet Explorer : URL et chemin dans l'objet `Download` imbriqué**),
  courriels PST et mbox (pièces jointes par nom et SHA-256, expéditeur ;
  `Evidence` = la boîte). `urlHost` (socle). Tests ; **leur premier jet
  gardait des pointeurs sur des objets temporaires** (`toJson().find(…)`) :
  plantage, et le débogueur de Wine a bloqué la chaîne trois heures ; corrigé,
  ainsi qu'un pointeur pendant ancien (ligne 1338) ; test désormais borné
  (5 min, débogueur coupé) et contrôles sûrs (`at`). Mutations vues échouer
  proprement ; 356/356, `bin/` = compilation. Contrôle du harnais :
  téléchargements du harnais (URL et chemin connus) et Zone.Identifier ;
  pièces jointes du PST de test contre `pypff` ; rejoué sur la collecte sans
  Context : ❌ (vu). Reste : cycle VM.

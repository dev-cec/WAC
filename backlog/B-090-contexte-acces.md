# B-090 — Contexte de liaison : accès

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

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

## Ce qui est écrit
| JSON | `Kind` | Sujet | Autres |
|---|---|---|---|
| `recentdocs.json`, `jumplistAutomaticDestinations.json` (chaque élément) | `Access` | la cible du raccourci : chemin de LinkInfo, sinon `%USERPROFILE%…` sur le profil ; une URL en `How.Url`/`How.Host` | `How.VolumeSerial`, l'hôte d'un partage ; `Related` `Application` (jump list) ; acteur : le SID ; `Evidence` : le `.lnk` ou la jump list |
| `shortcuts.json`, `jumplistCustomDestinations.json` | aucun | la cible, comme ci-dessus | idem |
| `explorer_recent_docs.json` | `Access` | `Name` : le nom seul, la liste ne garde pas le dossier | acteur, `NTUSER.DAT` |
| `office_trust_records.json` | `Access` | le document (`%USERPROFILE%/…`, `file:///…`, ou URL) | acteur, `NTUSER.DAT` |
| `typed_paths.json` | `Access` | le chemin tapé, ou l'hôte d'un partage ; sinon `Name` | acteur, `NTUSER.DAT` |
| `word_wheel_query.json` | `Access` | `Name` : le texte cherché, jamais un chemin | acteur, `NTUSER.DAT` |
| `shellbags.json` | `Access` | le dossier : chemin reconstitué du volume vers le bas (noms longs du bloc `0xbeef0004`), `Ntfs` par sa référence MFT ; sinon `Name` | acteur, la ruche |
| `activities_cache.json` | `Execution` (type 6), `Access` (type 5) ; aucun pour les autres | le programme d'`AppId` (`x_exe_path`, `windows_win32`) | acteur, la base |
| `search_index.json` | `Presence` | le chemin d'`ItemUrl` (`file:C:/…`) | la base |
| `thumbcache.json` | aucun ; `Presence` du fichier pour `Thumbs.db` (XP) | — (`ThumbnailCacheId` seul) | acteur, le cache |

**Écarts au tableau de B-078, à signaler à l'utilisateur** :
- `shortcuts.json` et les jump lists personnalisées : pas de `Kind`. Un
  raccourci du Bureau ou du menu Démarrer, posé par un installateur, et ce
  qu'une application met dans sa propre liste (tâches, épinglés) n'attestent
  aucune ouverture.
- `search_index.json` : `Presence`, pas `Access` : l'indexeur a vu le
  fichier, personne ne l'a ouvert. `ItemPathDisplay` est traduit (« Menu
  Démarrer » pour `Start Menu`, mesuré) : le chemin vient d'`ItemUrl`.
- `thumbcache.json` : pas de chemin dans le cache. La vignette se relie par
  `ThumbnailCacheId`, que partage l'index de recherche : c'est à WAE de la
  relier, pas à WAC.
- `activities_cache.json` : Windows 11 n'écrit plus que des réglages
  synchronisés (type 11), qui ne nomment aucun fichier. Les types 5 et 6
  (Windows 10) ne sont prouvés que par le test unitaire.
- Shellbags : un chemin n'est écrit que s'il part d'un volume (`C:\`) ou
  d'un partage. Sous un dossier connu (par GUID), une bibliothèque ou dans
  une archive, seul le nom est écrit : deviner le chemin nommerait un autre
  dossier que celui parcouru.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit (tableau ci-dessus). Fonctions communes :
  `setCitedLocation` (chemin, variable d'utilisateur, `file:` codée ou brute,
  URL, partage), `userPath` (séparée de `userCommandProgram`, qui coupait un
  document à son premier espace), `RecentDoc::context`, `stepShellItemPath`.
  Tests écrits dans `file_artefacts_test` ; contrôle `check_context_accesses`
  préparé. Compilation après le cycle de B-089.
- 2026-11-15 : mutation vue échouer (`/` non converti : emplacements, Office,
  index de recherche), restauration, `bin/WAC.exe` identique ; tests verts.
  `check_context_accesses` inséré dans `check-json.py`. Commit `3986452d`.
- 2026-11-15 : cycle `win11-test` (avec la correction de B-089) : 312 ✅,
  1 ❌ : `check_context_accesses`, 5 témoins sur 6. Le shellbag du ZIP n'avait
  pas de chemin : Explorer l'a enregistré sous « Ce PC\Documents », un
  dossier racine désigné par le CLSID `{D3162B92-…}`, inconnu de la table
  des dossiers connus. Corrigé : la table connaît les dossiers de
  l'utilisateur (KNOWNFOLDERID et CLSID de « Ce PC » : Documents, Images,
  Musique, Vidéos, Téléchargements, Bureau, profil), chacun suivant sa
  redirection (`User Shell Folders`) ; la racine d'un shellbag se place par
  cette table. Mutation vue échouer (CLSID de Documents retiré).
  Remarque : une redirection vers un partage n'est pas distinguée d'une
  absence de redirection par `redirectedShellFolder` ; le dossier par défaut
  est alors pris.

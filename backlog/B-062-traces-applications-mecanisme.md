# B-062 — Traces d'applications : mécanisme commun, une option `wac.yml` par produit

| Statut | Priorité | Effort |
|---|---|---|
| en cours (compilé, tests verts ; témoin et cycles à faire) | P1 | moyen |

## Pourquoi
Décision de l'utilisateur du 2026-11-05 : une option distincte par produit, regroupées par type, pour la 5.0.0. La comparaison à KAPE a montré des manques, sur les clients autant que sur les serveurs. Écrire un collecteur par produit serait disproportionné pour des dossiers à copier : une table suffit.

## Source
`sources/application_traces.{h,cpp}` : groupes, produits, dossiers (depuis la racine du volume système ou chaque profil, composant `*` possible), filtre, profondeur.

## Sortie attendue
Mécanisme partagé par B-063 à B-073 : filtre à motifs `*` dans `extensionMatches` (`raw_hive.cpp`), expansion des dossiers par lecture brute, `ListDirectoryRaw` qui distingue absent et illisible, `readProductSwitches` (`config.cpp`), entrées du catalogue, section par groupe dans `wac.yml`. `application_registry` (B-073) en réutilise les options.

## Référence indépendante
Test natif `application_traces_test` : motifs, options, règles de la table (clés uniques, aucun filtre ne prend une clé privée SSH). Cycle VM : témoins posés aux chemins de la table et leurres hors filtre, SHA-256 confronté à `Get-FileHash` côté invité.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Test vu échouer par mutation du filtre à motifs et de la lecture des options.
- `artefact_catalogue_test` et `config_test` verts avec les nouvelles clés.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table, test natif (1 429 contrôles, 0 échec)
- [x] Filtre à motifs, expansion, options, catalogue : écrits, non compilés
- [x] Section `wac.yml` (après la série en cours)
- [x] Compilation sans avertissement, tests sous Wine
- [x] Mutations vues échouer
- [x] `config_test` : option de produit, groupe coupé, clé inconnue
- [x] Script témoin commun (`guest/application-traces-witness.ps1`) et contrôle dans `check-json.py`
- [ ] Documentation FR et EN, tableau des artefacts
- [ ] Série complète de cycles, clients et serveurs

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Écrit le 2026-11-05 pendant la série finale : aucun fichier compilé ni utilisé par les cycles n'a été modifié dans `build-windows/`, `bin/` ni dans `sources/wac.yml`. Chemins issus des cibles de KAPE, à l'exception de ceux signalés dans les fiches.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- Décisions à prendre avant de clore ces fiches : copie brute sans JSON (écart au point 5 de la définition de « fini ») ; JSON de l'autorité de certification ; clés privées SSH exclues ; vidages de plantage activés par défaut. Le bloc `wac.yml` reste à écrire, la table donne ses clés.
- 2026-11-08 : code repris du stash sur la 4.0.0 (sans conflit) et compilé pour la première fois. Corrigé : ordre des libellés de `translations.cpp` ; `wildcardMatch` sorti de `application_traces` vers un en-tête portable `wildcard.h` (le lecteur NTFS en dépendait à l'envers, et `raw_hive_test` ne se liait plus). Section `wac.yml` écrite depuis la table (11 groupes, 97 produits, `application_registry` et ses 4 produits) : 99 artefacts, `artefact_catalogue_test` 1 074 contrôles verts. `application_traces_test` ajouté à `build-windows.sh` (1 429 contrôles). `config_test` : produit coupé et voisin pris, groupe coupé, registre coupé, fichier de référence tout actif, clé inconnue refusée (84 contrôles) ; au passage, ses messages d'échec perdaient l'erreur (argument construit avant l'appel), corrigé. Mutations vues échouer : filtre sensible à la casse (3 échecs), produit coupé ignoré (2 échecs) ; restauré, recompilé, `bin/` identique. Compilation sans avertissement, tests Wine verts.
- 2026-11-08 : décisions de l'utilisateur : clés privées SSH exclues ; vidages de plantage (`crash_dumps`, `minidumps`) et cache des documents Office (`office_cache`) **coupés par défaut**, dans la table elle-même (`TraceProduct::onByDefault`), réactivables dans `wac.yml` — sans quoi un `wac.yml` muet sur `system_traces` les aurait pris ; autorité de certification laissée brute. Copie brute sans JSON **remplacée** par une conversion générique (B-076) : l'utilisateur a demandé dans quel format étaient ces fichiers — la plupart sont des journaux texte, une ligne par événement. Au passage, une seconde `wildcardMatch` (web_installations.cpp, avec `?`, arguments inversés) fusionnée dans `wildcard.h` : une seule fonction de motifs.
- 2026-11-12 : témoin commun complété : chaque groupe a désormais au moins un fichier de valeur connue (67b22c22). Défaut trouvé au passage : `application_registry` et `cloud_identity` seuls ne faisaient pas copier les ruches des utilisateurs (92e04fdc). Reste : la documentation et la série complète de cycles.
- 2026-11-12 : cycle complet sur `win11-test` : 675 ✅, 4 ❌ (2 défauts, chacun compté en natif et en conversion), conversion déterministe. (1) `application_registry.json` écrivait `Sid` sans nom, quand les autres artefacts par utilisateur donnent `SID` et `SIDName` : corrigé par `addUser` (ea3d293e), le contrôle exige désormais le nom « wac » ; cycle ciblé 59 ✅, 0 ❌. (2) `known_networks` : une signature sans passerelle (l'adaptateur de Tailscale installé pour la mesure) n'a pas d'adresse, WAC ne l'émet pas et le registre n'en a pas ; le contrôle comptait une chaîne vide (b9c86c61), rejoué vert. Avertissement laissé : 6 chemins « doublement échappés » dans `vpn.json` sont le texte de Tailscale lui-même, qui écrit du JSON dans ses lignes.

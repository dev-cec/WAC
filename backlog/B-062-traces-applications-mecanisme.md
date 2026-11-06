# B-062 — Traces d'applications : mécanisme commun, une option `wac.yml` par produit

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | moyen |

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
- [ ] Section `wac.yml` (après la série en cours)
- [ ] Compilation sans avertissement, tests sous Wine
- [ ] Mutations vues échouer
- [ ] `config_test` : option de produit, groupe coupé, clé inconnue
- [ ] Script témoin commun (`guest/application-traces-witness.ps1`) et contrôle dans `check-json.py`
- [ ] Documentation FR et EN, tableau des artefacts
- [ ] Série complète de cycles, clients et serveurs

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Écrit le 2026-11-05 pendant la série finale : aucun fichier compilé ni utilisé par les cycles n'a été modifié dans `build-windows/`, `bin/` ni dans `sources/wac.yml`. Chemins issus des cibles de KAPE, à l'exception de ceux signalés dans les fiches.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- Décisions à prendre avant de clore ces fiches : copie brute sans JSON (écart au point 5 de la définition de « fini ») ; JSON de l'autorité de certification ; clés privées SSH exclues ; vidages de plantage activés par défaut. Le bloc `wac.yml` reste à écrire, la table donne ses clés.

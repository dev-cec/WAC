# B-048 — Navigateurs : sessions, onglets, favicons et fichiers annexes

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
La confrontation du 2026-10-09 (`vmtest/kape-compare.sh --no-binary`, 1 419 fichiers KAPE, 2 148 WAC, 1 381 communs) montre que KapeTriage prend encore 22 fichiers de navigateurs que WAC ne prend pas, hors `desktop.ini`. Plusieurs ont une vraie valeur d'enquête :
- **sessions et onglets** (Chromium `Sessions\Session_*`, `Tabs_*` ; Firefox `sessionstore-backups\*.jsonlz4`) : les pages ouvertes au moment de la collecte ou de la dernière fermeture, même hors historique (navigation privée exceptée) ;
- **Favicons** (Chromium `Favicons`, Firefox `favicons.sqlite`) : des sites visités restent cités après l'effacement de l'historique ;
- **Network Action Predictor** (Chromium) : les saisies de la barre d'adresse et l'URL choisie ;
- Firefox `bookmarkbackups\*.jsonlz4`, `protections.sqlite`, fichiers `-shm` des bases déjà prises ;
- Internet Explorer : `brndlog.txt/.bak`, `ie4uinit-*.log`, `iecompatdata.xml`, `DomainSuggestions`, `INetCookies\deprecated.cookie`.

## Source
Les profils de navigateur déjà trouvés par `web_client` (B-016), lus en brut par le même RawReader.

## Sortie attendue
Prélèvement brut de chacun ; dans `web_client.json`, les onglets et sessions (URL, titre, date), les favicons (URL de page ↔ URL d'icône, dates), le prédicteur (texte saisi, URL, compteurs). Les fichiers sans décodage utile (journaux d'IE) : copie brute justifiée, ou écartés avec leur raison.

## Référence indépendante
Sessions SNSS lues par un décodeur tiers (ou `chrome://` de la VM) ; bases SQLite relues par le SQLite de Python ; jsonlz4 décompressé par `lz4` de Python.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- `kape-compare.sh --no-binary` : plus aucun fichier de navigateur « KAPE seul » non classé.

## Tâches
- [ ] Prélèvement des fichiers annexes
- [ ] Décodage sessions et onglets (SNSS, jsonlz4)
- [ ] Favicons, Network Action Predictor
- [ ] Journaux d'IE : prendre ou écarter
- [ ] Dossiers FR/EN, comparaison comprise

## Journal
- 2026-10-09 : fiche ouverte depuis la confrontation à KAPE (mise à jour du dossier de comparaison).

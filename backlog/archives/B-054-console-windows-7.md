# B-054 — Bannière illisible dans la console de Windows 7

| Statut | Priorité | Effort |
|---|---|---|
| fait (76a7b58a) | P3 | faible |

## Pourquoi
Sous Windows 7, la bannière de WAC sort en caractères illisibles : elle est dessinée avec des caractères de cadre (`█`, `╔`, `═`) que la police par défaut de la console (police raster) ne sait pas afficher. Le reste du texte, accents compris, sort juste (UTF-8, `WriteConsoleW`).

## Source
Constaté lors des passages manuels de WAC sous Windows 7 (B-037, archivée). Probablement aussi sous Vista et XP, dont la console a la même police par défaut — à vérifier.

## Sortie attendue
Une bannière lisible sur toute console, sans changer la police ni aucun réglage de la console de l'utilisateur.

## Référence indépendante
Capture d'écran de la console de la VM (`virsh screenshot`) sous Windows 7, Vista et XP, et sous Windows 11.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucun réglage de la console modifié (police, page de code persistée).

## Tâches
- [x] Bannière réécrite en caractères « # » seulement (décision utilisateur : une seule bannière, pas de détection de la police)
- [x] Vérifiée par capture d'écran de la console de Windows 7, police par défaut

## Journal
- 2026-10-22 : sortie de B-037 à sa clôture (défaut cosmétique, non bloquant pour la 3.0).
- 2026-10-22 : décision utilisateur — une bannière unique en « # », qui marche partout, plutôt qu'un choix selon la police. Réécrite (76a7b58a), affichée lisiblement dans la console de Windows 7 (capture d'écran, WAC lancé par une tâche interactive puis arrêté). L'article garde l'ancienne bannière (fichiers de l'utilisateur).

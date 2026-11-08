# B-077 — Dates supposées : heure locale ou UTC, vérifiées produit par produit, à la précision écrite

| Statut | Priorité | Effort |
|---|---|---|
| en cours (avant la revue B-074) | P1 | moyen |

## Pourquoi
Demande de l'utilisateur (2026-11-08) : « l'exactitude des dates avec la précision maximale est la priorité absolue ». La conversion générique des traces d'applications (B-076) écrit toutes les dates sous la même forme (`Time` local avec décalage, `TimeUtc`), décision de l'utilisateur du même jour. Une date écrite sans fuseau y est **supposée** à l'heure locale de la machine examinée (`TimeZoneAssumed: Local`), ou UTC pour un produit mesuré comme tel (`TraceProduct::writesUtc`). Une supposition fausse place chaque événement du produit à côté d'une heure (ou plus) dans la chronologie, sans que rien ne le montre : la sortie reste valide. Chaque supposition doit donc être vérifiée par un test, pas seulement raisonnée.

## Ordre
Dernière fiche de fond de la 5.0.0, après B-062 à B-073 et B-076, avant la revue B-074 et la documentation B-075.

## Périmètre
- Chaque produit de `application_traces.h` dont un journal a une date sans fuseau : heure locale ou UTC.
- Chaque date de format connu d'un produit qui n'est pas lu (jour ou mois en premier, sans année, nom de mois) : lu, ou écart dit.
- La précision : écrire autant de chiffres que le journal en donne, ni plus (`.5` n'est pas `.500`), ni moins sans le dire (au-delà de 100 ns, la limite d'un FILETIME : `TimeAsWritten` garde le texte, la coupe est dite).
- Les autres artefacts de WAC qui supposent un fuseau, relevés et listés (revue, pas de réécriture ici).

## Méthode : comparer à l'heure d'exécution
1. **Automatique, à chaque cycle** (`check-json.py`) : pour chaque journal converti, l'instant de son dernier enregistrement (`TimeUtc`) confronté au moment où le fichier a été écrit pour la dernière fois (`SourceModifiedUtc` du manifeste, lu dans `$STANDARD_INFORMATION`). Heure locale bien supposée : écart de quelques minutes au plus. Écart égal au décalage de la machine (une heure à Paris en hiver, deux en été) : le produit écrit en UTC, `writesUtc` à poser. Autre écart : non concluant, dit.
2. **Provoqué** : pour les produits installables dans les VM (OpenSSH, outils gratuits), une action datée (une connexion à 14:03:21 relevée par l'hôte), puis la ligne du journal confrontée à cet instant, à la précision écrite.
3. **Deux fuseaux** : un cycle sur une VM réglée sur un autre fuseau (UTC−5 par exemple) : une supposition juste donne le même `TimeUtc` ; une fausse se décale.
4. **Changement d'heure** : une ligne témoin écrite dans l'heure répétée d'octobre et dans l'heure manquante de mars, convertie selon les règles de la date (`suspectLocalToUtc`) ; l'ambiguïté de l'heure répétée dite.

## Sortie attendue
Pour chaque produit : heure locale ou UTC, mesurée, avec le cycle et l'écart relevé ; `writesUtc` posé où il faut ; un tableau dans le dossier de validation FR et EN (produit, forme de date, fuseau, mesure, précision).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque produit dont la VM porte un journal : supposition confirmée par la mesure 1, ou corrigée.
- Mesures 2, 3 et 4 faites, chacune vue échouer sur une supposition volontairement fausse (mutation de `writesUtc`, du fuseau).
- Aucune date écrite avec plus de chiffres que la source n'en donne ; une coupe au-delà de 100 ns dite.
- Les produits non mesurables (absents des VM) listés comme tels dans la documentation, leur supposition marquée non vérifiée.

## Tâches
- [x] Contrôle automatique « dernier enregistrement contre dernière écriture » dans `check-json.py`, sur tous les journaux convertis
- [x] Précision exacte : chiffres écrits = chiffres de la source ; coupe au-delà de 100 ns dite
- [ ] Mesure provoquée (OpenSSH, outils installables)
- [ ] Cycle sur une VM à un autre fuseau
- [ ] Témoins du changement d'heure
- [ ] `writesUtc` posé d'après les mesures ; tableau de validation FR et EN
- [ ] Relevé des autres artefacts qui supposent un fuseau
- [ ] **Changement de fuseau dans l'histoire de la machine** : le fuseau en vigueur à chaque date, d'après les changements que Windows journalise (journal Système), appliqué aux lignes écrites avant ; témoin : une VM dont le fuseau change entre deux lignes

## Journal
- 2026-11-08 : créée à la demande de l'utilisateur ; l'exactitude des dates, à la précision maximale, est la priorité absolue.
- 2026-11-08 : mesure 1 en place (087d1652). Cycles ciblés, **Windows 11 61 ✅, 0 ❌ ; Server 2025 61 ✅, 0 ❌**. Témoin TeamViewer daté de l'heure d'exécution : 22:14:16.968 heure de Paris lu 21:14:16.968Z, l'UTC que Windows calcule, à la milliseconde (de même sur Server 2025). Heure locale confirmée (dernier enregistrement à quelques minutes de la dernière écriture) : Windows 11 — jonction au domaine (`NetSetup.log`, mois en premier), TeamViewer, journaux d'installation de Windows ; Server 2025 — TeamViewer, journaux d'installation. **Non concluant** : `NetSetup.log` de Server 2025, dernière ligne 480 min avant la dernière écriture du fichier — ni zéro, ni le décalage de la VM (60 min) : fichier touché après sa dernière ligne, ou lignes écrites avant le réglage du fuseau à l'installation (le fuseau par défaut d'une installation est celui du Pacifique). À examiner. Précision exacte faite dans le même commit.
- 2026-11-08 : **le cas non concluant expliqué, à la milliseconde.** `NetSetup.LOG` de Server 2025 : créé 08:04:23.98Z, dernière écriture 08:04:24.0149725Z (manifeste) ; dernière ligne `10/31/2026 01:04:24:014`. Écart : 7 h exactement, l'heure avancée du Pacifique (UTC−7) du 31 octobre, fuseau par défaut d'une installation de Windows — la VM a été passée à l'heure de Paris ensuite. Le journal écrit donc bien l'heure **locale**, mais celle du fuseau **en vigueur au moment de l'écriture** ; WAC applique le fuseau actuel de la machine (UTC+1), d'où 00:04:24.014Z au lieu de 08:04:24.014Z, 8 h d'erreur. Limite réelle, pas du harnais : tout changement de fuseau dans l'histoire d'une machine (installation, déménagement, portable en voyage) décale ainsi les lignes écrites avant lui, ici comme dans tout artefact daté en heure locale. Tâche ajoutée : le fuseau en vigueur à chaque date, d'après les changements que Windows journalise.

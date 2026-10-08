# B-046 — Journaux ESE ni prélevés ni rejoués : activité récente de la WebCache manquée

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | fort |

## Pourquoi
Cycle VM du 2026-10-08, après un redémarrage de win11-test : le témoin HTA (mshta.exe, mis en cache par WinINet) n'apparaît plus dans web_client.json — ni avec le binaire courant ni avec le précédent. Le jeton de la visite n'est pas dans `WebCacheV01.dat` prélevé : l'entrée est encore dans les journaux de transactions ESE de la base (`V01.log`, `V01*.log`, `V01res*.jrs`), que WAC ne prélève pas et ne rejoue pas. Avant le redémarrage, un point de contrôle avait écrit les entrées des cycles précédents dans le .dat, ce qui masquait le manque. Toute navigation récente (Edge en mode IE, mshta, téléchargements WinINet, Cookies) peut donc échapper à la collecte — l'activité la plus intéressante d'un incident. Même question pour les autres bases ESE lues : SRUM (`SRUDB.dat`, journaux `SRU*.log`), index de recherche (`Windows.edb`).

## Source
Les journaux ESE à côté de chaque base (`*.log`, `*.jrs`, `*.chk`) ; le format des journaux ESE (enregistrements de modification de page) ; `ese_database.cpp`.

## Sortie attendue
Au moins : les journaux prélevés avec la base (pièces). Au mieux : rejoués dans la copie de travail avant la lecture, comme les journaux de ruche, sans toucher la consigne.

## Référence indépendante
`esentutl /r` (récupération) sur une copie dans la VM, puis lecture de la base récupérée ; `dissect.esedb`.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les journaux de la WebCache, de SRUM et de la base BITS rejoués dans la copie de travail à la conversion, par esent.dll, la consigne jamais lue ni la base d'origine ouverte ; une conversion rejouée donne au moins ce que donnait la lecture telle que copiée.

## Tâches
- [x] Décider : rejeu complet avant la 2.0.0 (décision utilisateur 2026-10-08)
- [x] Rejeu par esent.dll (ese_recovery.cpp), branché sur WebCache, SRUM et BITS

## Journal
- 2026-10-08 : créée pendant B-045 ; manque démontré (jeton absent du .dat prélevé, ancien binaire en échec aussi).
- 2026-10-08 : décision utilisateur — rejeu complet avant la 2.0.0. Méthode retenue : le moteur de Windows lui-même (esent.dll, chargé dynamiquement à la conversion seulement, comme WinHTTP pour --update-trust) rejoue les journaux sur la copie de travail — JetInit3 avec une table de correspondance (JET_RSTMAP) du chemin d'origine de la base vers sa copie, événements d'information et compteurs coupés. Réimplémenter le rejeu physique ESE serait un moteur entier, au risque d'une base valide et fausse. À vérifier : aucune trace sur la machine examinée en --full (mesure Sysmon de B-027), et résultat identique à esentutl /r.
- 2026-10-08 : CORRECTION DU DIAGNOSTIC. Le ❌ du témoin HTA ne venait pas des journaux ESE : mshta.exe, tué après 8 s fixes, n'avait pas téléchargé le HTA (aucune copie en cache) ; témoin corrigé (ec18a43). La recherche du jeton dans les octets ne prouvait rien : ESE compresse le texte de ses colonnes. Le rejeu, implémenté (esent.dll chargé de System32, JetInit3 avec table de correspondance de la base d'origine vers la copie, événements et compteurs coupés), fonctionne : la WebCache rejouée passe à l'état propre ; sur les collectes de la VM, mêmes enregistrements qu'avant, à l'octet (175 entrées WebCache), SRUM déjà propre à la copie (détaché entre ses écritures). Décision utilisateur : garder le rejeu, à la conversion seulement — puis suppression du mode --full (B-047) : WAC ne convertit plus jamais sur la machine examinée, esent.dll n'y est donc jamais chargé.

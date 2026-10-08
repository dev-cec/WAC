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
- Le témoin HTA retrouvé même quand l'entrée n'est que dans les journaux.

## Tâches
- [x] Décider : rejeu complet avant la 2.0.0 (décision utilisateur 2026-10-08)
- [ ] Étude du format des journaux ESE

## Journal
- 2026-10-08 : créée pendant B-045 ; manque démontré (jeton absent du .dat prélevé, ancien binaire en échec aussi).
- 2026-10-08 : décision utilisateur — rejeu complet avant la 2.0.0. Méthode retenue : le moteur de Windows lui-même (esent.dll, chargé dynamiquement à la conversion seulement, comme WinHTTP pour --update-trust) rejoue les journaux sur la copie de travail — JetInit3 avec une table de correspondance (JET_RSTMAP) du chemin d'origine de la base vers sa copie, événements d'information et compteurs coupés. Réimplémenter le rejeu physique ESE serait un moteur entier, au risque d'une base valide et fausse. À vérifier : aucune trace sur la machine examinée en --full (mesure Sysmon de B-027), et résultat identique à esentutl /r.

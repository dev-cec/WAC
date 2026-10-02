# B-037 — Collecte compatible avec toutes les versions de Windows depuis XP SP1

| Statut | Priorité | Effort |
|---|---|---|
| à faire (en dernier) | P3 | fort |

## Pourquoi
Les machines examinées ne sont pas toutes récentes : postes industriels, caisses, serveurs oubliés tournent encore sous Windows XP, Server 2003, Vista ou 7. WAC est aujourd'hui développé et éprouvé sur Windows 10 et 11. Demande utilisateur du 2026-10-02 : la collecte doit fonctionner depuis Windows XP SP1. Pas prioritaire, à faire après les autres fiches.

## Source
Tout ce que la collecte touche sur la machine examinée :
- **le binaire lui-même** : fonctions de l'API Windows absentes de XP (bcrypt, `GetTickCount64`, `CreateFile2`, fonctions de chaînes récentes, chemins longs…) — un import manquant empêche WAC de démarrer ; runtime MinGW statique et sous-système (version minimale du PE) ;
- **les emplacements** : `Documents and Settings\<compte>`, `Local Settings\Temporary Internet Files`, `Application Data`, ruches et profils de XP ;
- **les formats anciens** : journaux d'événements `.evt` (XP, 2003) au lieu de `.evtx`, Prefetch version 17, `index.dat` d'IE 5 à 8 (déjà lus, B-016), raccourcis et jump lists absents avant 7, SRUM et Amcache absents, ShimCache au format XP/2003, NTFS 3.0/3.1 ;
- **la lecture brute** : volumes, `\\.\X:` et droits sous XP.

## Sortie attendue
Le même WAC.exe démarre et collecte de XP SP1 à Windows 11, et chaque artefact absent d'une version le dit (`CollectionStatus`) au lieu d'échouer.

## Référence indépendante
Une VM par version (XP SP1, XP SP3, Server 2003, Vista, 7, 8.1) passée par le harnais, avec les outils de référence déjà utilisés (EZ, plaso/libyal) sur les mêmes pièces.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- WAC.exe se charge sur XP SP1 : aucune importation absente (vérifiée sur le PE et par un lancement réel).
- Chaque artefact propre à une version récente est déclaré absent sur les anciennes, jamais en échec.
- Les formats anciens rencontrés (au moins `.evt`) sont convertis ou déclarés non pris en charge, avec leur raison.

## Tâches
- [ ] Inventaire des importations de WAC.exe et de leur disponibilité par version
- [ ] VM XP SP1 (et autres versions) dans le harnais
- [ ] Emplacements XP (Documents and Settings…)
- [ ] Journaux `.evt`
- [ ] Prefetch v17, ShimCache XP/2003

## Journal
- 2026-10-02 : créée à la demande de l'utilisateur — compatibilité depuis Windows XP SP1, à faire en dernier.

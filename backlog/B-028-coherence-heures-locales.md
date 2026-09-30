# B-028 — Cohérence des heures locales à travers les artefacts

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P1 | moyen |

## Pourquoi
« L'incohérence de date est le pire ennemi de l'investigation » (utilisateur, 2026-09-30). Un même instant doit se lire à la même heure dans chaque artefact. Certains artefacts stockent une heure locale calculée par Windows avec le décalage du moment où il l'ÉCRIT, et non de la date qu'elle représente. Une date d'hiver écrite en été est alors décalée d'une heure si on la convertit avec le décalage de sa date. B-013 l'a montré sur les copies vers FAT (corrigé, 7ce205d).

## Source
Recensement des heures locales lues par WAC :
- `idList` : dates FAT des éléments de shell. L'Explorateur les écrit quand il crée l'élément. Elles se trouvent dans les raccourcis, les jump lists, les shellbags et les documents récents ;
- `idList` : date OLE (élément de shell d'archive) ;
- `setupapi_log` : lignes écrites au moment de l'événement, la date est donc l'instant d'écriture (juste) ;
- `fat_volumes` : fait dans B-013.

## Sortie attendue
Chaque date locale convertie avec le décalage en vigueur au moment où elle a été écrite, quand ce moment est connu ou borné. Quand ce décalage diffère de celui de la date, le JSON le signale (`…OffsetApplied`, `…AsStored`, origine du moment).

## Référence indépendante
L'en-tête d'un raccourci porte les dates de sa cible en UTC, et son élément de shell les mêmes en heure locale. Chaque raccourci de la VM confronte donc les deux. Témoin : raccourci créé en été vers un fichier daté d'hiver.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Sur tous les raccourcis de la VM, la date de modification de la cible lue dans l'élément de shell égale à 2 s près celle de l'en-tête, en UTC.
- Aucune heure locale émise qui ne soit dérivée de l'UTC.

## Tâches
- [x] Mesure sur la VM : les dates des éléments de shell sont en UTC (dossier créé à 18:48:05 UTC stocké 18:48:06 ; cible d'hiver 08:00 UTC stockée 08:00). WAC les lisait comme locales : raccourcis, jump lists, shellbags et documents récents décalés d'1 à 2 h. Corrigé.
- [x] Contrôle croisé dans check-json : élément de shell contre l'en-tête UTC du raccourci, et bloc 0xbeef0004 des shellbags contre la création de l'enregistrement MFT (17 dates, aucun écart)
- [x] Témoin à cheval sur le changement d'heure : raccourci créé en été vers un fichier daté d'hiver
- [ ] Élément de contenu d'archive (ArchiveFileContent) : date DOS d'une entrée ZIP, lue comme locale, à confronter sur un vrai ZIP ouvert dans l'Explorateur
- [ ] Date OLE (VT_DATE) des magasins de propriétés : lue comme locale par convention OLE, à confronter

## Journal
- 2026-09-30 : fiche créée à la demande de l'utilisateur, après la correction des dates FAT copiées.
- 2026-09-30 : l'hypothèse du départ (heure locale écrite avec le décalage du moment) était fausse pour les éléments de shell : ils stockent l'UTC. Le code d'origine le lisait juste ; un « correctif » ultérieur, fondé sur la spécification FAT sans mesure, l'avait faussé.

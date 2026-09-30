# B-027 — Empreinte comparée : WAC, KAPE et outils EZ sous bac à sable

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | fort |

## Pourquoi
L'innocuité de WAC est aujourd'hui mesurée seule (dates et USN de fichiers témoins). La question d'un examinateur est comparative : qu'est-ce que chaque outil laisse réellement sur la machine examinée ? Prefetch, Amcache, ShimCache, BAM, UserAssist, journaux d'événements (4688, 4663, 7045…), fichiers temporaires, clés de registre créées, pilotes chargés, journal USN, $LogFile. Dernière tâche du backlog, après les artefacts (demande utilisateur 2026-09-30).

## Source
Un clone de la VM de test par outil, restauré depuis le même instantané (état identique), sans réseau :
- WAC (collecte seule, puis collecte et conversion) ;
- KAPE (cibles `!SANS_Triage`, puis avec modules EZ) ;
- outils EZ seuls sur la machine vivante (MFTECmd, EvtxECmd, RECmd, PECmd, AmcacheParser, AppCompatCacheParser).
Chaque exécution depuis un support externe, comme sur le terrain.

## Sortie attendue
Rapport `doc/footprint/` (FR + EN) : par outil, chaque trace laissée, sa nature (fichier, clé, événement, entrée d'artefact) et sa gravité pour l'analyse. Tableau comparatif. Script de différence rejouable dans `vmtest/`.

## Référence indépendante
La différence entre l'instantané avant et l'état après, lue HORS de la VM (image disque montée en lecture seule sur l'hôte) : $MFT et journal USN comparés, ruches comparées clé par clé, journaux d'événements comparés. Option : Sysmon (configuration complète : processus, fichiers, registre, pilotes) et politique d'audit étendue (création de processus avec ligne de commande, accès aux objets, registre) activés dans l'instantané de départ — ils nomment l'auteur de chaque trace.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les trois outils mesurés depuis le même état, par la même différence hors VM.
- Chaque trace de WAC expliquée : inévitable (le lancement d'un exécutable), réductible (corrigée ou mise au backlog) ou déjà documentée dans le dossier d'innocuité.
- Le dossier d'innocuité (FR + EN) mis à jour avec la comparaison.

## Tâches
- [ ] Instantané de référence de la VM (avec et sans Sysmon et audit)
- [ ] Obtenir KAPE (inscription chez Kroll : à faire par l'utilisateur) et les outils EZ (.NET)
- [ ] Script de différence hors VM : image montée en lecture seule, $MFT/USN, ruches, journaux
- [ ] Une exécution par outil, chacune depuis l'instantané
- [ ] Rapport comparatif FR + EN

## Journal
- 2026-09-30 : demande utilisateur — dernière tâche, comparaison WAC / KAPE / EZ sous bac à sable ; Sysmon et audit en option.
- Lien : B-015 compare le contenu prélevé ; B-027 compare les traces laissées.

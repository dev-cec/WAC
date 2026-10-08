# B-027 — Empreinte comparée : WAC, KAPE et outils EZ sous bac à sable

| Statut | Priorité | Effort |
|---|---|---|
| fait (b8c6f8b) | P2 | fort |

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
**Le journal des modifications (USN) borné**, source principale pour les fichiers (décision utilisateur 2026-10-07) : numéro USN courant relevé juste avant l'outil, puis lecture des enregistrements depuis ce numéro jusqu'à la fin de l'outil. Il liste chaque fichier créé, modifié, renommé ou supprimé, avec sa date et sa raison — y compris ceux créés puis supprimés pendant l'exécution, qu'une différence de $MFT avant/après manquerait. La lecture peut se faire dans la VM : ce qu'elle écrit porte des USN postérieurs à la borne de fin. WAC décode déjà ce journal (`usn_journal.json`).
Ce que l'USN ne dit pas, et qui le complète :
- **l'auteur** : Windows écrit en permanence (indexation, Defender, SRUM). **Sysmon** (processus, fichiers, registre, pilotes) dans l'instantané de départ attribue chaque écriture à un processus ;
- **le contenu** d'une ruche ou d'un journal d'événements : l'USN dit que `NTUSER.DAT`, `Amcache.hve` ou `Security.evtx` ont changé, pas quelle clé (BAM, ShimCache, UserAssist) ni quel événement (4688, 7045). Différence ciblée sur les seules ruches et journaux que l'USN désigne, clé par clé et événement par événement.
Ce choix remplace la différence complète hors VM (image montée, $MFT comparée en entier), plus lourde.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les trois outils mesurés depuis le même état, par la même différence hors VM.
- Chaque trace de WAC expliquée : inévitable (le lancement d'un exécutable), réductible (corrigée ou mise au backlog) ou déjà documentée dans le dossier d'innocuité.
- Le dossier d'innocuité (FR + EN) mis à jour avec la comparaison.

## Tâches
- [x] Instantané de référence : clone win11-footprint sans réseau, Sysmon, outils sur une clé K: (vmtest/footprint/prepare-footprint.sh)
- [x] Obtenir KAPE : fourni par l'utilisateur, `vmtest/kape.zip` (exclu du dépôt)
- [x] Outils EZ et KAPE sur la clé ; C:\Tools retiré du clone, runtime .NET 9 laissé (prérequis)
- [x] Mesure : USN borné, parents résolus, Sysmon, journaux de la fenêtre, ShimCache après redémarrage (guest/measure-run.ps1, run-footprint.sh)
- [x] Analyse : soustraction du témoin, attribution (footprint-diff.py)
- [x] Une exécution par outil, chacune depuis l'instantané
- [x] Rapport : chapitre « traces laissées » du document de comparaison (FR + EN), avec temps d'exécution et différences de prélèvement (nombre, volume, précision) — demande utilisateur 2026-10-08 ; dossier d'innocuité

## Journal
- 2026-09-30 : demande utilisateur — dernière tâche, comparaison WAC / KAPE / EZ sous bac à sable ; Sysmon et audit en option.
- Lien : B-015 compare le contenu prélevé ; B-027 compare les traces laissées.
- 2026-10-07 : méthode révisée sur proposition de l'utilisateur — USN borné comme source des fichiers, Sysmon pour l'auteur, différence ciblée des ruches et journaux ; plus de montage d'image ni de différence complète de la $MFT.
- 2026-10-08 : en cours — clone dédié de la VM, Sysmon, outils sur clé USB.
- 2026-10-08 : clone win11-footprint (disque de win11-test copié, sans interface réseau, clé USB qcow2 WACFOOT0001 en K:). Sysmon (Sysmon.zip SHA-256 00ecf1b4…aa54, signature Microsoft vérifiée), configuration vmtest/footprint/sysmon-config.xml. Images figées en lecture seule ; chaque exécution sur des surcouches neuves. Six exécutions : témoin (ver), WAC collecte, WAC --full, KAPE !SANS_Triage, KAPE + !EZParser, outils EZ en direct ; lancement identique (tâche planifiée de wac, droits élevés). Incident : un premier essai de la préparation a supprimé C:\Tools du clone avant la copie sur la clé (bloc PowerShell sans arrêt sur erreur) — clone seul touché, outils repris des archives de l'hôte ; script corrigé (arrêt à la première erreur). fsutil localisé : USN suivant lu par sa position.
- 2026-10-08 : premiers résultats et corrections. (1) WAC lançait `cmd.exe /c cls` (system("cls")) : processus créé, Prefetch de CMD.EXE — corrigé par l'API console, plus aucune fonction de lancement importée, contrôle ajouté à build-windows.sh (db04e46). (2) WAC attend une touche à la fin : dans la tâche planifiée, la fenêtre de mesure s'étirait (1 165 s pour 620 s de travail) et captait les tâches d'inactivité de Windows (ProvTool LogonIdleTask, 486 fichiers) — commandes WAC lancées avec `< nul`. (3) Analyse : la racine de l'arbre des processus est le cmd.exe lancé par le Planificateur (une commande du harnais qui citait le fichier de console avait été prise pour l'outil). Témoin (`ver`) : cmd et conhost, BAM de cmd/conhost, tâche planifiée, Prefetch de fsutil. Collecte WAC (avant correctif) : aucun fichier écrit sur C: par ses processus, registre : BAM seul. Série relancée à 08:02 avec le WAC corrigé (déposé sur K: à chaque exécution).
- 2026-10-08 : fait (b8c6f8b). Série complète (témoin, WAC collecte 592 s, WAC --full 544 s, KAPE !SANS_Triage 127 s, KAPE + !EZParser 235 s, outils EZ en direct 132 s). WAC : aucun fichier, aucune valeur de registre, aucun événement ; Windows ajoute Amcache (pendant) et ShimCache (à l'arrêt, « SIGN.MEDIA=… WAC\\WAC.exe ») ; ni Prefetch ni BAM pour les 22 programmes lancés de la clé. KAPE : 4 valeurs ZoneMap dans NTUSER ; avec modules, 136 écritures ZoneMap par 14 processus et 28 fichiers sur C: (BreadcrumbStore .NET, sentinelles System.CommandLine). Prélèvement : 1 151 pièces communes WAC/KAPE (1 011 au même SHA-1, les autres réécrites par Windows), 1 140 propres à KAPE (profil utilisateur surtout : B-016/031/032), 10 679 propres à WAC. Corrigé en chemin : system("cls") (db04e46). Ouvert en chemin : B-045 (144 scripts en échec 0x80004005). Document de comparaison (temps, prélèvement, traces) et dossier d'innocuité mis à jour, FR + EN. Le clone win11-footprint et ses images figées restent pour rejouer la mesure.

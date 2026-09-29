# B-002 — Lot 1 : petits artefacts fichiers (7)

| Statut | Priorité | Effort |
|---|---|---|
| fait (2657784) | P1 | faible |

## Pourquoi
Sources attendues de toute collecte de réponse à incident (niveau KAPE !SANS_Triage), absentes de WAC.

## Source
PSReadLine de chaque profil ; `\Windows\INF\setupapi.dev*.log` ; `$I` de `\$Recycle.Bin` de chaque volume NTFS fixe ; `drivers\etc\hosts` ; `WER\Report*\*\Report.wer` (machine et profils) ; `Windows Defender\Support\MPLog-*.log` ; dossiers de démarrage (tous utilisateurs et profils).

## Sortie attendue
`powershell_history.json`, `setupapi.json`, `recycle_bin.json`, `hosts.json`, `error_reports.json`, `defender_log.json`, `startup_folders.json` ; clés `artefacts:` du même nom.

## Référence indépendante
`file_artefacts_test` (33 contrôles sur formats décrits) ; témoins déposés par `vmtest/place-file-artefacts.ps1` et retrouvés par `check_small_file_artefacts` ; comptes de sections setupapi et de journaux MPLog relevés par Windows.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les 4 témoins retrouvés à l'identique (commandes, chemin d'origine, entrée hosts, SHA-256 du script).
- setupapi.json : au moins autant de sections que Windows en compte, 90 % datées.
- Rien d'écrit sur la machine examinée par WAC (contrôle d'innocuité vert).

## Tâches
- [x] Décodeurs, collecteurs, prélèvement brut
- [x] Interrupteurs wac.yml, textes FR/EN
- [x] file_artefacts_test 33/0
- [x] Manuels, guide des tests, validation, README
- [x] Témoins VM et contrôle check-json
- [x] Cycle VM vert (3e cycle, 29/09)
- [x] PDF des tests et de la validation régénérés
- [x] Commit 2657784, fiche déplacée dans archives/

## Journal
- 2026-09-29 : écrit et compilé ; cycle VM à passer.
- 2026-09-29 : 1er cycle VM — 5 artefacts sur 7 conformes aux témoins. Corbeille : témoin mal posé (en SYSTEM, ou en tâche hors session, « envoyer à la corbeille » supprime définitivement) → recyclage par une tâche dans la session interactive de wac, vérifié à la main dans la VM ($IPMRFOP.txt). error_reports.json : `Values` en objet reprenait les clés brutes du rapport (`DynamicSig[1].Name`), refusées par le contrôle des noms de clés → liste de paires Name/Value.
- 2026-09-29 : 2e cycle VM — error_reports conforme ; corbeille : $I bien posés mais extraction en échec (E_FAIL) : ExtractFilesRaw n'écrit que dans un dossier existant, le bloc de la corbeille ne le créait pas → dossiers créés avant l'extraction. 3e cycle lancé.
- 2026-09-29 : 3e cycle VM entièrement vert — les 7 artefacts conformes à leurs témoins (fichier recyclé retrouvé avec son instant de suppression), innocuité verte. Reste : PDF, commit, archivage.
- 2026-09-29 : commité (2657784), fiche archivée.

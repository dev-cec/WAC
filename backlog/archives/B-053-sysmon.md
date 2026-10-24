# B-053 — Sysmon : journaux, configuration et archives, s'il est présent

| Statut | Priorité | Effort |
|---|---|---|
| fait (5fb2a2b7) | P1 | moyen |

## Pourquoi
Demande utilisateur du 2026-10-17 : s'assurer que les journaux Sysmon, s'ils sont présents, sont bien prélevés. Sysmon (Sysinternals) n'est pas installé par défaut, mais là où il l'est, son journal est souvent la meilleure source de détection : création de processus avec ligne de commande et empreintes, connexions réseau, chargement de pilotes, accès à LSASS, création de fichiers, modifications du registre.

## Constat (2026-10-17)
- Déjà couvert : WAC prend tous les `.evtx` de `System32\winevt\Logs` et les convertit tous dans `events.json`, sans filtre de canal. Le journal `Microsoft-Windows-Sysmon%4Operational.evtx`, à son emplacement par défaut, est donc prélevé et converti — à **démontrer** par un témoin.
- Non couvert :
  - **un journal déplacé** : le chemin d'un canal se change (valeur `File` de `SYSTEM\…\Services\EventLog\<canal>` ou de la configuration du canal, `wevtutil sl /lfn`) ; WAC ne lit que `winevt\Logs` ;
  - **la configuration de Sysmon** : ses règles, binaires, dans `SYSTEM\…\Services\SysmonDrv\Parameters` (`Rules`, `HashingAlgorithm`, `Options`) — ce que Sysmon surveillait, donc ce que son silence prouve ou non ;
  - **le dossier d'archives** (`ArchiveDirectory`, `C:\Sysmon` par défaut) : les copies des fichiers supprimés que Sysmon garde quand une règle `FileDelete` est active — le contenu même d'outils effacés par un intrus.

## Sortie attendue
- Les journaux de tous les canaux, où que leur configuration les place (emplacement lu dans le registre de la machine examinée), dont celui de Sysmon.
- Une clé `sysmon` : version du pilote et du service, configuration (règles décodées si le format est établi, sinon brutes avec leur empreinte), dossier d'archives prélevé avec les empreintes de chaque fichier.

## Référence indépendante
Sysmon installé dans les VM de test (Windows 7 et suivants ; Vista selon la version de Sysmon qui la prend encore) avec une configuration témoin : ses événements confrontés à `Get-WinEvent`, sa configuration à `sysmon -c`, une suppression archivée retrouvée avec la bonne empreinte.

## Tâches
- [x] Témoin : Sysmon et une configuration connue sous Windows 11 (`vmtest/guest/sysmon-witness.ps1`, installé par le harnais, retiré avant l'étape 8)
- [x] Démontrer le journal Sysmon dans `events.json` (lu dans le journal déplacé)
- [x] Journaux déplacés : emplacement des canaux lu dans le registre examiné (`event_log_files`, collecte et conversion)
- [x] Configuration de Sysmon ; dossier d'archives (clé `sysmon`, `sysmon.json`)
- [x] Documentation FR et EN (manuel : `sysmon.json`, journaux déplacés ; validation ; table des artefacts)

## Journal
- 2026-10-17 : créée à la demande de l'utilisateur, pour la 3.0. Constat : le journal Sysmon à son emplacement par défaut est déjà pris avec les autres ; restent le journal déplacé, la configuration et les archives.
- 2026-10-24 : commencée. Constat : event_log_configuration.json relève déjà la valeur `File` de chaque canal (WINEVT\Channels, Services\EventLog) — donc l'emplacement d'un journal déplacé —, mais la collecte ne prend que `winevt\Logs` et la conversion n'y lit que lui. Module `event_log_files` écrit (liste des fichiers de journaux que le registre examiné place ailleurs, développés par normalizeFilePath), à brancher sur la collecte et la conversion après les commits de B-036. Sysmon 15 téléchargé dans `vmtest/tools/sysmon` (Sysinternals, Sysmon.zip SHA-256 00ecf1b4…, non versionné) : il vise Windows 10 et suivants — témoin sous Windows 11. Témoin prévu : installation par le harnais avec une configuration connue (ProcessCreate d'un exécutable témoin, FileDelete archivé dans un dossier d'archives témoin), journal Sysmon déplacé sur le volume de données (`wevtutil sl /lf`), puis désinstallation à la fin du cycle.
- 2026-10-24 : relevé en VM (Sysmon 15.22, Windows 11) : la configuration est dans `Services\SysmonDrv\Parameters` (`Rules` binaire, `HashingAlgorithm`, `CheckRevocation`, `DnsLookup`, `ArchiveDirectory` = `\WacSysmonArchive\`, relatif à la racine du volume système, `ConfigFile`, `ConfigHash` = `SHA256=…` du XML) ; le service `Sysmon64` relie son pilote par `Parameters\DriverName` ; une archive est nommée `<SHA-256>.<extension>` ; `wevtutil sl /lfn:` écrit la valeur `File` du canal ; `-u force` laisse `C:\Windows\Sysmon64.exe` (supprimé par le témoin). Version non relue à part : l'événement 4 du journal la porte. Écrit : `sysmon.h/.cpp` (installation reconnue au lien service → pilote portant `Rules`, donc même renommée ; `Parameters` tels que stockés, `RulesSha256`, archives et XML de configuration prélevés bruts), journaux déplacés pris un à un (`extractFiles`) et convertis avec leur canal. Premier cycle : témoin non installé (sous `Stop`, PowerShell 5.1 fait une erreur de la sortie d'erreur redirigée d'un exécutable natif) → appels natifs sous `Continue`.
- 2026-10-24 : second cycle restreint : configuration et archives absentes de la collecte — `conf.CurrentControlSet` n'était ouvert, pendant `--collect`, qu'après les extractions (`collectForConversion`) → ouvert avant elles ; journal déplacé absent de la première collecte, présent dans la seconde : la valeur `File` venait d'être écrite et la ruche SOFTWARE pas encore vidée sur le disque (WAC ne force jamais l'écriture) → `sysmon` parmi les témoins du registre vivant, qu'on attend. Retrait du témoin : `-Folder` manquait à l'appel, et le Prefetch du témoin restait → corrigés. Cycle complet Windows 11 : 543 ✅, 2 ❌ (témoin du cliché, B-056) ; Sysmon : service et pilote, SHA-256 des règles, ConfigHash et SHA-256 du XML identiques à Windows, archives par taille et SHA-256, ProcessCreate du témoin lu dans le journal déplacé, aux deux collectes ; VM rendue sans trace (service, pilote, binaire, archives, journaux, Prefetch).

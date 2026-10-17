# B-053 — Sysmon : journaux, configuration et archives, s'il est présent

| Statut | Priorité | Effort |
|---|---|---|
| à faire (version 3.0) | P1 | moyen |

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
- [ ] Témoin : Sysmon et une configuration connue dans les VM (installé par le harnais, retiré ensuite)
- [ ] Démontrer le journal Sysmon dans `events.json`
- [ ] Journaux déplacés : emplacement des canaux lu dans le registre examiné
- [ ] Configuration de Sysmon ; dossier d'archives
- [ ] Documentation FR et EN

## Journal
- 2026-10-17 : créée à la demande de l'utilisateur, pour la 3.0. Constat : le journal Sysmon à son emplacement par défaut est déjà pris avec les autres ; restent le journal déplacé, la configuration et les archives.

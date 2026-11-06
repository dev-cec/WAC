# B-072 — `system_traces` : ce que Windows garde en plus

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | moyen |

## Pourquoi
Traces de Windows lui-même, surtout sur les **clients** : exécution (`pca`, `SchedLgU.txt`, `EventTranscript.db`), persistance (shims personnalisés), activité (notifications, Sticky Notes, captures), historique d'installation (Panther, `Windows.old`).

## Source
21 sources, une option chacune : `crash_dumps`, `custom_shims`, `encapsulation_logging`, `event_transcript`, `microsoft_sccm`, `minidumps`, `notifications`, `office_cache`, `pca`, `pcw_diagnostics`, `power_diagnostics`, `powershell_transcripts`, `scheduled_task_log`, `search_gather_logs`, `sleep_study`, `snip_sketch`, `startup_info`, `sticky_notes`, `syscache`, `windows_old`, `windows_upgrade`.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. `minidumps` et `crash_dumps` peuvent contenir des secrets en mémoire, activés par défaut : à confirmer. `office_cache` contient de vrais documents. `MEMORY.DMP`, `hiberfil` et `pagefile` restent exclus.

## Référence indépendante
Pièces réelles confrontées à `Get-FileHash` : `pca` sur Windows 11, `SchedLgU.txt`, notifications, `setupact.log`. Témoins pour le reste : `Windows.old`, `.sdb` dans `Custom64`, transcription PowerShell réelle (`Start-Transcript`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque source présente sur la version mesurée, ou son absence dite.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table écrite
- [ ] Témoins en VM
- [ ] Mesurer le volume de `windows_old` et d'`office_cache`

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.

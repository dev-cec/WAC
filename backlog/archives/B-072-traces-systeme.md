# B-072 — `system_traces` : ce que Windows garde en plus

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P1 | moyen |

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
- [x] Témoins en VM
- [x] Mesurer le volume de `windows_old` et d'`office_cache`

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-08 : décision de l'utilisateur : `crash_dumps`, `minidumps` et `office_cache` coupés par défaut (mémoire, documents de l'utilisateur), réactivables dans `wac.yml`.
- 2026-11-12 : témoins : un transcript écrit par `Start-Transcript` lui-même, retrouvé dans `system_traces.json` ligne à ligne ; le vidage de plantage, coupé par défaut, jamais pris. Cycle ciblé sur `win11-test` : 75 ✅, 0 ❌. `windows_old` : aucune VM n'a de `Windows.old`, volume non mesurable ici ; `office_cache` coupé par défaut.
- 2026-11-13 : **fait.** Témoins : vidage de plantage coupé par défaut, ni collecté ni converti ; transcription écrite par `Start-Transcript`. Volume de `windows_old` et d'`office_cache` non mesuré, décision de l'utilisateur (2026-11-13) : absents des VM ; limite écrite dans les manuels. Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

# B-063 — `remote_administration` : outils d'administration à distance

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P1 | moyen |

## Pourquoi
Voie d'entrée et de maintien courante dans les rançongiciels, y compris sur des postes de travail : qui s'est connecté, d'où, quand.

## Source
15 produits, une option chacun : Ammyy, AnyDesk, Atera, Kaseya, LogMeIn, Radmin, Remote Utilities, RustDesk, ScreenConnect, Splashtop, Supremo, TeamViewer, UltraViewer, VNC, mRemoteNG. Sous `ProgramData`, `Program Files*` et chaque profil.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. `confCons.xml` de mRemoteNG et `service.conf` d'AnyDesk peuvent contenir des secrets chiffrés ou hachés : pris comme chez KAPE.

## Référence indépendante
Fichier témoin de valeur connue à un chemin par produit. Si l'utilisateur l'autorise, un produit réellement installé en VM (AnyDesk portable) : le fichier écrit par le produit, confronté à `Get-FileHash`.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table écrite
- [x] Témoins en VM
- [x] Dire la limite pour RustDesk : chemin de mémoire, à vérifier dans sa documentation

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Chemin de RustDesk écrit de mémoire : pas une cible de KAPE, non vérifié à ce jour.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoins faits. TeamViewer (ligne datée, suite, leurre, changement de fuseau, heures d'été) depuis le 2026-11-08 ; AnyDesk, RustDesk et mRemoteNG installés et mesurés le 2026-11-11 (B-077), leurs journaux restés dans `win11-test` confrontés à chaque cycle. Le chemin de RustDesk n'est plus de mémoire : son journal réel a été écrit à `%APPDATA%\RustDesk\log` et pris par WAC. Cycle ciblé sur `win11-test` : 75 ✅, 0 ❌.
- 2026-11-13 : **fait.** Témoins : TeamViewer (ligne datée à la milliseconde, suite, leurre, changement de fuseau, heures d'été) ; AnyDesk, RustDesk, mRemoteNG et UltraViewer installés et mesurés (B-077). Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

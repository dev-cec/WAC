# B-063 — `remote_administration` : outils d'administration à distance

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | moyen |

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
- [ ] Témoins en VM
- [ ] Dire la limite pour RustDesk : chemin de mémoire, à vérifier dans sa documentation

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Chemin de RustDesk écrit de mémoire : pas une cible de KAPE, non vérifié à ce jour.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.

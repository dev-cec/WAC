# B-065 — `messaging` : messageries

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P2 | moyen |

## Pourquoi
Échanges, pièces reçues, comptes : souvent décisifs dans une enquête sur une personne, surtout sur un poste client. L'utilisateur a demandé de les prendre le 2026-11-05.

## Source
11 produits, une option chacun : Discord, Cisco Jabber, Mattermost, Signal, Skype, Slack, Teams, Telegram, Viber, WhatsApp, Zoom ; dans chaque profil.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. Bases souvent chiffrées par l'application ; caches compris comme chez KAPE.

## Référence indépendante
Fichier témoin par produit, dans chaque profil, un second compte compris.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Manuels : ces pièces contiennent de vraies conversations, parfois en clair, et peuvent peser plusieurs Go ; chaque produit se coupe.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table écrite
- [x] Témoins en VM
- [x] Mesurer le volume ajouté sur `win11-test`

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Telegram : `tdata` et les téléchargements, entiers. Les clés de session de `tdata` y sont : à dire dans la revue B-060.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoin : un journal de Zoom d'une ligne datée, retrouvé dans `messaging.json` ; un témoin par groupe dans `guest/application-traces-witness.ps1`, confronté par `check_application_traces` (67b22c22). Cycle ciblé sur `win11-test` : 75 ✅, 0 ❌. Le volume ajouté reste à mesurer : aucune messagerie n'est installée sur `win11-test`, la mesure n'y dirait rien.
- 2026-11-13 : **fait.** Témoin : journal Zoom, sa ligne datée ; et dans le profil de Server 2003. Volume ajouté non mesuré, décision de l'utilisateur (2026-11-13) : aucune messagerie installable sans compte dans les VM ; la limite est écrite dans les manuels (caches compris, plusieurs Go possibles, chaque produit se coupe). Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

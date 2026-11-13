# B-066 — `cloud_storage` : métadonnées du stockage en ligne

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P2 | faible |

## Pourquoi
Ce qui a été synchronisé, et vers où : indice d'exfiltration. OneDrive a déjà son artefact.

## Source
5 produits, une option chacun : Box, Dropbox, Google Drive, pCloud, SugarSync ; dans chaque profil.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. Bases et journaux seulement, pas les fichiers de l'utilisateur : le `content_cache` de Google Drive, aux noms sans extension, reste hors du filtre.

## Référence indépendante
Témoin par produit ; leurre sans extension dans `DriveFS\<compte>\content_cache`, qui ne doit pas être pris.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table écrite
- [x] Témoins et leurre en VM

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). KAPE classe `Microsoft\Protect` sous Dropbox : déjà pris par `dpapi_master_keys`.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoin (base pCloud listée, non convertie, depuis le 2026-11-08) et leurre : un fichier de l'utilisateur sans extension dans `DriveFS\…\content_cache` de Google Drive, jamais pris. Cycle ciblé sur `win11-test` : 61 ✅, 0 ❌.
- 2026-11-13 : **fait.** Témoins : base pCloud listée non convertie ; leurre dans le cache de contenu de Google Drive, jamais pris. Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

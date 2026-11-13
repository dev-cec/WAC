# B-073 — `application_registry` : PuTTY, WinSCP, WinRAR et 7-Zip dans le registre

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P2 | faible |

## Pourquoi
Les sessions et clés d'hôte de PuTTY et WinSCP nomment les machines atteintes depuis celle-ci ; l'historique de WinRAR et de 7-Zip, les archives préparées avant une sortie de données. Hors de la portée de KAPE, qui copie la ruche sans la lire.

## Source
`NTUSER.DAT\Software` de chaque profil : `SimonTatham\PuTTY`, `Martin Prikryl\WinSCP 2`, `WinRAR`, `7-Zip`. Une option par produit.

## Sortie attendue
`application_registry.json` : Sid, Product, Key, KeyLastWrite, Values. Une valeur dont le nom contient « password » n'est pas émise, `HasPassword` le dit. Ruche déjà copiée, aucun prélèvement de plus.

## Référence indépendante
Clés témoins posées dans la ruche de l'utilisateur, confrontées à `reg query` et à `regipy`.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Valeur de mot de passe témoin absente du JSON, `HasPassword` présent.
- Test vu échouer par mutation de `isPasswordValue`.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Lecteur écrit, non compilé
- [x] Règle du mot de passe au test natif
- [x] Témoins en VM
- [x] Contrôle dans `check-json.py`

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoins : une session PuTTY et une session WinSCP (avec un mot de passe) écrites dans la ruche de `wac` ; contrôle : les deux retrouvées, au SID de `wac`, le mot de passe absent du JSON et signalé (`HasPassword`). Premier cycle : 0 entrée — **défaut** : `application_registry` (et `cloud_identity`) manquaient à `needsUserHives`, les ruches n'étaient pas copiées quand aucun autre lecteur n'était demandé ; un cycle complet le masquait. Corrigé (92e04fdc), `config_test` active chaque lecteur seul (vu échouer avant). Cycle ciblé : 75 ✅, 0 ❌.
- 2026-11-13 : **fait.** Témoins : sessions PuTTY et WinSCP dans la ruche de wac, `SID` et `SIDName`, mot de passe WinSCP absent, `HasPassword` présent ; `isPasswordValue` vu échouer par mutation. Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

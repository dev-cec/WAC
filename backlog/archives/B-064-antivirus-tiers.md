# B-064 — `antivirus` : journaux des antivirus autres que Defender

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P1 | moyen |

## Pourquoi
Ce que le produit a vu et retiré, avant qu'un intrus ne le coupe. Defender a déjà ses artefacts ; les parcs d'entreprise, postes et serveurs, ont souvent un autre produit.

## Source
21 produits, une option chacun : Avast, AVG, Avira, Bitdefender, Cybereason, Emsisoft, ESET, F-Secure, HitmanPro, Malwarebytes, McAfee, RogueKiller, SecureAge, SentinelOne, Sophos, SUPERAntiSpyware, Symantec, TotalAV, Trend Micro, VIPRE, Webroot.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. Une quarantaine (Symantec) reste chiffrée comme le produit la garde.

## Référence indépendante
Fichier témoin à un chemin par produit, composants `*` compris (`Sophos *`, `Symantec Endpoint Protection\*\Data`).

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

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Chemins issus des cibles de KAPE.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoin : un rapport Emsisoft (`scan_*.txt`) d'une ligne datée, retrouvé dans `antivirus.json`, l'heure telle qu'écrite, supposée locale ; un témoin par groupe dans `guest/application-traces-witness.ps1`, confronté par `check_application_traces` (67b22c22). Cycle ciblé sur `win11-test` : 75 ✅, 0 ❌. Aucun antivirus tiers installé : le format réel de chaque produit n'est pas mesuré, la conversion générique le lit ligne à ligne.
- 2026-11-13 : **fait.** Témoin : rapport Emsisoft, sa ligne datée telle qu'écrite, heure locale ; et sous All Users sur Server 2003. Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

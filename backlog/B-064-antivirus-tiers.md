# B-064 — `antivirus` : journaux des antivirus autres que Defender

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | moyen |

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
- [ ] Témoins en VM

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Chemins issus des cibles de KAPE.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.

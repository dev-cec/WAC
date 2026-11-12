# B-067 — `file_transfer` : outils de transfert de fichiers

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P2 | faible |

## Pourquoi
Ce qui est parti, vers quel serveur.

## Source
4 produits, une option chacun : FileZilla, FreeFileSync, TeraCopy, WinSCP.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. Les sessions de FileZilla (`sitemanager.xml`) et `WinSCP.ini` peuvent porter des mots de passe peu protégés : pris comme chez KAPE, à dire dans la revue B-060.

## Référence indépendante
Fichier témoin par produit. KAPE cherche `WinSCP.ini` sur tout le volume : ici à ses deux emplacements, écart à dire.

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
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). La configuration de WinSCP dans le registre relève de B-073.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoins faits depuis le 2026-11-08 : `WinSCP.ini` et `sitemanager.xml` de FileZilla en structure, l'hôte gardé, le mot de passe absent et signalé ; confrontés à chaque cycle complet.

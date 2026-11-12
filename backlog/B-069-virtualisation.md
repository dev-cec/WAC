# B-069 — `virtualisation` : VirtualBox, VMware Workstation, WSL

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P2 | faible |

## Pourquoi
Une machine dans la machine, pour agir hors de la vue de l'hôte. Surtout sur les postes.

## Source
3 produits, une option chacun : VirtualBox, VMware Workstation, WSL (dossiers personnels de WSL 1, `.bash_history`).

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. Ni disque ni mémoire. Les dossiers de WSL 2 sont dans un disque virtuel, non pris : limite à dire. KAPE cherche `.vbox` et `VBox.log` sur tout le volume ; ici dans `VirtualBox VMs` de chaque profil, écart à dire.

## Référence indépendante
Fichier témoin par produit ; `.bash_history` témoin sous un `rootfs` posé à la main.

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
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoin : une machine VirtualBox (`.vbox`), retrouvée dans `virtualisation.json` en XML, son nom gardé ; un témoin par groupe dans `guest/application-traces-witness.ps1`, confronté par `check_application_traces` (67b22c22). Cycle ciblé sur `win11-test` : 75 ✅, 0 ❌.

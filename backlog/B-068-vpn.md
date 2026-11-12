# B-068 — `vpn` : clients VPN

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P2 | faible |

## Pourquoi
Les tunnels que la machine ouvre ou a ouverts, dont ceux qu'un intrus installe.

## Source
4 produits, une option chacun : OpenVPN, Proton VPN, Tailscale, WireGuard.

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants.

## Référence indépendante
Fichier témoin par produit.

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
- [ ] Vérifier les chemins de Tailscale et de WireGuard dans leur documentation

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Tailscale et WireGuard ne sont pas des cibles de KAPE : chemins écrits de mémoire, non vérifiés à ce jour.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoins : OpenVPN et Tailscale installés et mesurés le 2026-11-11 (B-077), leurs journaux confrontés à chaque cycle ; le chemin de Tailscale vérifié par son journal réel (`C:\ProgramData\Tailscale`). WireGuard ni installé ni mesuré : son chemin reste celui de sa documentation.

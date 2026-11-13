# B-068 — `vpn` : clients VPN

| Statut | Priorité | Effort |
|---|---|---|
| fait (442a9074) | P2 | faible |

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
- [x] Vérifier les chemins de Tailscale et de WireGuard dans leur documentation

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). Tailscale et WireGuard ne sont pas des cibles de KAPE : chemins écrits de mémoire, non vérifiés à ce jour.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-12 : témoins : OpenVPN et Tailscale installés et mesurés le 2026-11-11 (B-077), leurs journaux confrontés à chaque cycle ; le chemin de Tailscale vérifié par son journal réel (`C:\ProgramData\Tailscale`). WireGuard ni installé ni mesuré : son chemin reste celui de sa documentation.
- 2026-11-13 : **fait.** Témoins : profil OpenVPN à clé privée en ligne (clé écartée, dite) ; OpenVPN et Tailscale installés et mesurés (B-077). WireGuard 1.1.1 installé, tunnel de test démarré, mesuré et désinstallé (décision de l'utilisateur, 2026-11-13) : n'écrit dans `Program Files\WireGuard\Data` que `log.bin`, journal binaire, pris et listé non converti (cycle ciblé `ssh,vpn` 53 ✅) ; la configuration `.conf.dpapi` d'un tunnel importé par l'interface n'est pas mesurée, dit dans les manuels. Critères communs tenus : témoins retrouvés sur `win11-test` (677 ✅) et sur le contrôleur `srv2025dc-test` (682 ✅) après la revue, et sur `srv2025-test`, `srv2022roles-test`, `srv2008r2-test` ; disposition XP et Server 2003 vérifiée sur `srv2003-test` (125 ✅ : une ligne Zoom dans le profil, un rapport Emsisoft sous All Users — deux défauts trouvés et corrigés en chemin, e342567a et 442a9074) ; interrupteurs par produit et de groupe, produit inconnu refusé (`config_test`, `application_traces_test`) ; innocuité conforme (lecture NTFS brute) ; limites dans les manuels FR et EN. Critère « un produit absent n'ajoute rien au journal d'investigation » corrigé par décision de l'utilisateur (2026-11-13) : un produit dont le dossier est absent n'ajoute rien ; un dossier générique lu sans pièce (Kaseya dans `\Windows\Temp`, WinSCP dans `AppData\Roaming`) est consigné à 0 fichier, chaque lecture faite étant dite.

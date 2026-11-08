# B-070 — `ssh` : OpenSSH serveur et client

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | faible |

## Pourquoi
Qui peut entrer sans mot de passe (`authorized_keys`, une persistance), et où la machine est allée (`known_hosts`). OpenSSH est livré avec Windows 10, Windows 11 et Server 2019 et suivants.

## Source
2 options : `openssh_server` (`ProgramData\ssh` : `sshd_config`, `administrators_authorized_keys`, clés publiques, `logs` ; `authorized_keys` de chaque profil), `openssh_client` (`config`, `known_hosts`, clés publiques de chaque profil).

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. **Aucune clé privée**, à la différence de KAPE : `id_*` et `ssh_host_*_key` restent hors du filtre, décision du 2026-11-05 à confirmer par l'utilisateur.

## Référence indépendante
Mesure réelle : fonctionnalité OpenSSH installée sur `win11-test` et un serveur, clé témoin posée, connexion vers localhost pour remplir `known_hosts` et le journal ; `Get-FileHash`. Leurres `id_ed25519` et `ssh_host_ed25519_key` : absents du dépôt.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune clé privée dans le dépôt, vérifié sur le manifeste et par le test natif, vu échouer par mutation du filtre.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table et règle du test natif
- [ ] Mesure réelle en VM

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-08 : décision de l'utilisateur : clés privées exclues (le test de la table le garantit).

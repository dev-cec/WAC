# B-071 — `server_applications` et `server_logs` : applications et journaux de serveur

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P1 | moyen |

## Pourquoi
Propres aux rôles. Ce sont les deux seuls groupes surtout serveur ; ils restent inoffensifs sur un client, où SQL Server Express ou un poste joint au domaine (`NetSetup.log`, `netlogon.log`) en portent aussi.

## Source
`server_applications` : SQL Server (ERRORLOG, SQL Agent, `.xel`, `.trc`), Exchange, FileZilla Server, Confluence, ManageEngine. `server_logs` : autorité de certification (`CertLog`), `dcpromo`, `netlogon`, `NetSetup`, NPS (`LogFiles\IN*.log`), accès distant (`Windows\Tracing`).

## Sortie attendue
Copie brute dans le dépôt des pièces, scellée au manifeste (condensats), sans conversion JSON. **Écart à la définition de « fini », point 5**, à valider par l'utilisateur : même traitement que `etw_logs`, `onedrive` et `defender_endpoint`, formats propres à chaque éditeur et changeants. L'autorité de certification reste en copie brute, sans JSON : décision du 2026-11-05, à confirmer.

## Référence indépendante
Mesure réelle : rôle AD CS sur le contrôleur de test, base `CertLog` lue par `dissect.esedb`, nombre de lignes de `Certificates` confronté à `certutil -view`. `netlogon` et `NetSetup` réels sur le contrôleur. SQL Server, Exchange et les autres : fichiers témoins.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Table écrite
- [ ] Rôle AD CS en VM
- [ ] Témoins en VM

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062). `CertLog` et `netlogon.log` ne sont pas dans les cibles de KAPE retenues.
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.
- 2026-11-08 : décision de l'utilisateur : la base de l'autorité de certification reste copiée brute pour la 5.0.0, sans JSON propre.

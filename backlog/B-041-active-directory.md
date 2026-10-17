# B-041 — Artefacts de compromission d'Active Directory (version 4.0)

| Statut | Priorité | Effort |
|---|---|---|
| à faire (version 4.0, prérequis : B-039, B-038) | P2 | fort |

## Pourquoi
Sur un contrôleur de domaine, la compromission se joue dans l'annuaire : comptes ajoutés aux groupes privilégiés, réplication détournée pour lire les secrets (DCSync), tickets forgés, délégations abusives, stratégies de groupe modifiées pour se propager. Ces traces sont propres aux serveurs et n'existent sur aucun poste. Demande utilisateur du 2026-10-07 : pour les serveurs, la version 3.0 doit les relever.

## Source
À étudier, sur un contrôleur de domaine de test :
- la base de l'annuaire `NTDS.dit` (ESE) et ses journaux : comptes, groupes et appartenances, `adminCount`, historique des mots de passe, `pwdLastSet`, métadonnées de réplication (date et origine de chaque modification d'attribut), objets supprimés ;
- `SYSVOL` : stratégies de groupe (`GPT.INI`, `Registry.pol`, scripts de démarrage et d'ouverture de session, tâches planifiées des préférences) ;
- les journaux d'événements propres au contrôleur : Kerberos (4768, 4769, 4771), réplication et accès aux objets (4662, DCSync), modifications de comptes et de groupes (4720, 4728, 4732, 4756, 4738, 4742), Directory Service, DFS Replication ;
- la ruche SYSTEM et `NTDS` (clé de chiffrement des condensats, avec la clé de démarrage) : le jugement des mots de passe revient à WAE, comme pour la SAM (B-034).

## Sortie attendue
Un ou plusieurs artefacts à leur clé de `wac.yml` (par exemple `active_directory`), présents seulement là où ils existent (table de B-039) : annuaire converti (comptes, groupes, métadonnées de réplication), stratégies de groupe, événements de contrôleur regroupés avec leurs champs utiles.

## Référence indépendante
Contrôleur de domaine de test dans le harnais : opérations témoins de valeur connue (compte ajouté à un groupe privilégié, GPO modifiée, réplication demandée) ; confrontation à des outils publics (dissect.esedb sur `NTDS.dit`, `Get-ADReplicationAttributeMetadata`, `Get-ADUser`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Témoins retrouvés, avec leur date et l'origine de la modification.
- Rien de lu par l'annuaire en marche ni par ses services : lecture brute, comme pour les ruches.

## Tâches
- [ ] Étude des sources sur un contrôleur de test
- [ ] Contrôleur de domaine dans le harnais

## Journal
- 2026-10-07 : créée à la demande de l'utilisateur — version 3.0, pour les serveurs.
- 2026-10-17 : décision utilisateur — version 4.0, avec les serveurs.

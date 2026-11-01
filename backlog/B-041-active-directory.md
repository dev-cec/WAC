# B-041 — Artefacts de compromission d'Active Directory (version 4.0)

| Statut | Priorité | Effort |
|---|---|---|
| en cours (version 4.0) | P2 | fort |

## Pourquoi
Sur un contrôleur de domaine, la compromission se joue dans l'annuaire : comptes ajoutés aux groupes privilégiés, réplication détournée pour lire les secrets (DCSync), tickets forgés, délégations abusives, stratégies de groupe modifiées pour se propager. Ces traces sont propres aux serveurs et n'existent sur aucun poste. Demande utilisateur du 2026-10-07 : pour les serveurs, la version 3.0 doit les relever.

## Source
À étudier, sur un contrôleur de domaine de test :
- la base de l'annuaire `NTDS.dit` (ESE) et ses journaux : comptes, groupes et appartenances, `adminCount`, `pwdLastSet`, métadonnées de réplication (date et origine de chaque modification d'attribut), objets supprimés ;
- `SYSVOL` : stratégies de groupe (`GPT.INI`, `Registry.pol`, scripts de démarrage et d'ouverture de session, tâches planifiées des préférences) ;
- les journaux d'événements propres au contrôleur : Kerberos (4768, 4769, 4771), réplication et accès aux objets (4662, DCSync), modifications de comptes et de groupes (4720, 4728, 4732, 4756, 4738, 4742), Directory Service, DFS Replication ;

## Sortie attendue
Un ou plusieurs artefacts à leur clé de `wac.yml` (par exemple `active_directory`), présents seulement là où ils existent (table de B-039) : annuaire converti (comptes, groupes, métadonnées de réplication), stratégies de groupe, événements de contrôleur regroupés avec leurs champs utiles. Les attributs de secrets de l'annuaire ne sont ni lus ni émis.

## Référence indépendante
Contrôleur de domaine de test dans le harnais : opérations témoins de valeur connue (compte ajouté à un groupe privilégié, GPO modifiée, réplication demandée) ; confrontation à des outils publics (dissect.esedb sur `NTDS.dit`, `Get-ADReplicationAttributeMetadata`, `Get-ADUser`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Témoins retrouvés, avec leur date et l'origine de la modification.
- Rien de lu par l'annuaire en marche ni par ses services : lecture brute, comme pour les ruches.

## Plan par lots (2026-11-01)
- **Lot 1 — l'annuaire.** Repérage par le registre (`Services\NTDS\Parameters`), lecture brute de `ntds.dit` et de ses journaux, rejoués sur la copie de travail ; comptes, groupes et appartenances (`link_table`), `adminCount`, délégations, SPN, `sIDHistory`, objets supprimés ; métadonnées de réplication (`replPropertyMetaData` : attribut, version, date, DSA d'origine). Référence : `Get-ADUser`, `Get-ADReplicationAttributeMetadata`, dissect.esedb.
- **Lot 2 — les stratégies de groupe.** `SYSVOL\domain` (le dossier réel : `sysvol\<domaine>` est une jonction) : `GPT.INI`, `Registry.pol`, scripts, tâches des préférences. Référence : `Get-GPO`, `Get-GPRegistryValue`.
- Les événements du contrôleur (Kerberos, 4662, Directory Service, DFS Replication) sont déjà pris par `events`, quel que soit leur canal : à vérifier par un témoin, pas de code attendu.

## Tâches
- [ ] Étude des sources sur un contrôleur de test
- [ ] Contrôleur de domaine dans le harnais (`install-domain-controller.sh`, écrit)
- [ ] Lot 1 : annuaire
- [ ] Lot 2 : stratégies de groupe

## Journal
- 2026-10-07 : créée à la demande de l'utilisateur — version 3.0, pour les serveurs.
- 2026-10-17 : décision utilisateur — version 4.0, avec les serveurs.
- 2026-11-01 : reprise, B-035 et B-038 quasi closes ; contrôleur de domaine de test en création (`DOM=srv2022dc-test ./create-vm.sh srv2022`, puis promotion). Reprend le point `NTDS.dit` de B-038.
- 2026-11-01 : contrôleur `srv2022dc-test` promu (forêt wac.test). Étude sur un `ntds.dit` réel : 3 518 lignes, 1 326 colonnes ; les objets récents ne sont que dans les journaux, le rejeu est indispensable ; les groupes intégrés ont un nom traduit (« Admins du domaine ») : les témoins les visent par SID.

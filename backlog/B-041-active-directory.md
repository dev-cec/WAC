# B-041 — Artefacts de compromission d'Active Directory (version 4.0)

| Statut | Priorité | Effort |
|---|---|---|
| en cours (version 4.0) | P2 | fort |

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

## Plan par lots (2026-11-01)
- **Lot 1 — l'annuaire.** Repérage par le registre (`Services\NTDS\Parameters`), lecture brute de `ntds.dit` et de ses journaux, rejoués sur la copie de travail ; comptes, groupes et appartenances (`link_table`), `adminCount`, délégations, SPN, `sIDHistory`, objets supprimés ; métadonnées de réplication (`replPropertyMetaData` : attribut, version, date, DSA d'origine). Référence : `Get-ADUser`, `Get-ADReplicationAttributeMetadata`, dissect.esedb.
- **Lot 2 — les condensats.** Clé PEK déchiffrée avec la clé de démarrage, condensats NT et historique en JSON, comme la SAM ; le jugement revient à WAE. Référence : le condensat NT calculé sur l'hôte depuis un mot de passe témoin connu.
- **Lot 3 — les stratégies de groupe.** `SYSVOL\domain` (le dossier réel : `sysvol\<domaine>` est une jonction) : `GPT.INI`, `Registry.pol`, scripts, tâches des préférences. Référence : `Get-GPO`, `Get-GPRegistryValue`.
- Les événements du contrôleur (Kerberos, 4662, Directory Service, DFS Replication) sont déjà pris par `events`, quel que soit leur canal : à vérifier par un témoin, pas de code attendu.

## Tâches
- [ ] Étude des sources sur un contrôleur de test
- [ ] Contrôleur de domaine dans le harnais (`install-domain-controller.sh`, écrit)
- [ ] Lot 1 : annuaire
- [ ] Lot 2 : condensats
- [ ] Lot 3 : stratégies de groupe

## Journal
- 2026-10-07 : créée à la demande de l'utilisateur — version 3.0, pour les serveurs.
- 2026-10-17 : décision utilisateur — version 4.0, avec les serveurs.
- 2026-11-01 : reprise, B-035 et B-038 quasi closes ; contrôleur de domaine de test en création (`DOM=srv2022dc-test ./create-vm.sh srv2022`, puis promotion). Reprend le point `NTDS.dit` de B-038.

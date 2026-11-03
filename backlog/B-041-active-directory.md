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
- [x] Étude des sources sur un contrôleur de test
- [x] Contrôleur de domaine dans le harnais (`install-domain-controller.sh`)
- [ ] Lot 1 : annuaire
  - [x] Artefact `active_directory` écrit : `active_directory_objects`, `_links`, `_replication`, `_security_descriptors` (.json) ; clé de `wac.yml`, catalogue, textes FR et EN
  - [x] Témoins (`guest/active-directory-witness.ps1`) et contrôle (`check_active_directory`)
  - [x] Cycle court `--only=active_directory` vert sur `srv2022dc-test`
  - [x] Test unitaire vu échouer par mutation
  - [x] Rejeu avec les journaux dans un autre dossier que la base
  - [x] Commit du lot (6be64175)
  - [ ] Cycle complet sur le contrôleur (en cours), puis non-régression Windows 11 (lecteur ESE et ACL touchés)
  - [x] Documentation FR et EN, PDF régénérés, 0 débordement (les mesures du cycle complet restent à y reporter)
- [ ] Lot 2 : stratégies de groupe (commité ; cycle complet et non-régression à passer)

## Journal
- 2026-10-07 : créée à la demande de l'utilisateur — version 3.0, pour les serveurs.
- 2026-10-17 : décision utilisateur — version 4.0, avec les serveurs.
- 2026-11-01 : reprise, B-035 et B-038 quasi closes ; contrôleur de domaine de test en création (`DOM=srv2022dc-test ./create-vm.sh srv2022`, puis promotion). Reprend le point `NTDS.dit` de B-038.
- 2026-11-01 : contrôleur `srv2022dc-test` promu (forêt wac.test). Étude sur un `ntds.dit` réel : 3 518 lignes, 1 326 colonnes ; les objets récents ne sont que dans les journaux, le rejeu est indispensable ; les groupes intégrés ont un nom traduit (« Admins du domaine ») : les témoins les visent par SID.
- 2026-11-01 : fiche recentrée à la demande de l'utilisateur : sans les secrets de l'annuaire (aab16023).
- 2026-11-03 : lot 1 écrit, **non commité**. Seule une liste d'attributs est décodée : aucun attribut de secret, et un attribut nouveau du schéma reste non lu tant qu'il n'y est pas nommé. Noms des attributs et des classes lus dans le schéma de la base elle-même ; lecture en flux (`EseDatabase::forEachRecord`) pour une base de plusieurs Gio ; ACE d'objet décodées dans `aclToJson` (le GUID du droit, indispensable pour voir un droit de réplication) ; rejeu possible avec des journaux hors du dossier de la base, chemin non encore mesuré.
- 2026-11-03 : cycle court vert sur `srv2022dc-test` (Server 2022, forêt wac.test), sans ❌ : les 3 700 objets listés par `Get-ADObject` sur les cinq contextes de nommage, supprimés compris, tous présents et 3 700 écrits ; nom, classe, SID, compte, `userAccountControl`, `adminCount`, SPN et création identiques ; 78 changements de `Get-ADReplicationAttributeMetadata` identiques (date, version, contrôleur, USN) ; témoins retrouvés : membre d'Admins du domaine (visé par SID), appartenance retirée avec sa date, objet supprimé avec son nom et son parent, délégations contrainte et basée sur la ressource, droit `DS-Replication-Get-Changes-All` sur la racine. Le rejeu des journaux s'applique : les objets récents sont là. Mesuré au passage : sans corbeille de l'annuaire, un objet supprimé n'a pas de `msDS-LastKnownRDN` (son dernier nom reste dans `name`).
- 2026-11-03 : limites à ce stade : mesuré sur Server 2022 seul ; aucun `sIDHistory` réel dans le harnais (décodé comme `objectSid`, non confronté) ; `msDS-IntId` non lu, un attribut d'extension du schéma peut n'apparaître que par son `AttributeId` dans la réplication. Mutation en cours ; restent les étapes non cochées ci-dessus, puis le lot 2.
- 2026-11-03 : mutation : RID non retourné, compte annoncé non borné, ACE d'objet non reconnue : `active_directory_test` passe de 0 à 5 échecs. Incident : un appel interrompu avait déjà muté les sources, et la relance a sauvegardé ces sources mutées comme référence ; les trois mutations ont été défaites une à une, sans mutant dans `bin/` (`build-windows.sh` s'arrêtait avant la copie, sur le compte attendu d'`artefact_catalogue_test`, corrigé).
- 2026-11-03 : journaux déplacés dans la VM (`ntdsutil`, `C:\NtdsLogs`, NTDS arrêté, harnais seulement) : `edb.chk` reste à côté de la base, et le rejeu ne le trouvait pas ; il le cherche maintenant aussi là. Mesuré : `edb*.log` rejoués, copie propre, 32 ✅ sans ❌. Journaux remis en place ; NTDS, ADWS, KDC et DNS en marche, l'annuaire répond, sans redémarrage de la VM.
- 2026-11-03 : lot 1 commité (6be64175), harnais commité. Manuels FR et EN écrits, non commités, PDF à régénérer. Cycle complet lancé sur `srv2022dc-test` (08:37) ; pendant ce temps, documentation et PDF, sans toucher à `build-windows/`, `bin/` ni au harnais.
- 2026-11-03 : manuels, guide des tests, dossier de validation, tables du catalogue et d'ATT&CK à jour (attack-coverage inchangé en nombre : 475 techniques couvertes sur 479). Cycle complet relancé (le premier lancement n'avait pas démarré : script introuvable dans le shell d'arrière-plan). Étude du lot 2 en cours, sans compiler tant que le cycle tourne.
- 2026-11-03 : lot 2 écrit, ni compilé ni testé (le cycle complet du contrôleur tourne) : artefact `group_policies`, `group_policies.json`, depuis la copie de `SYSVOL\domain` (`GPT.INI`, `Registry.pol`, `scripts.ini`, `ScheduledTasks.xml` des préférences, `GptTmpl.inf`, liste des fichiers). Un `cpassword` de préférence est signalé par son fichier et son élément, sa valeur n'est pas écrite. Branchement, témoins et contrôle : après le cycle.
- 2026-11-03 : cycle complet du lot 1 sur `srv2022dc-test` (32 min) : 536 ✅, 14 ❌ pour 7 écarts distincts vus aux deux conversions, aucun sur le décodage de l'annuaire. Harnais : référence de l'annuaire prise avant les témoins qui le changent (SPN, `net accounts`, `wacpw`), reportée après ; deux bases témoins relevées puis déplacées. Sans objet sur un contrôleur, contrôles sautés et dits : hachés et questions de `wacpw`, groupes locaux (la SAM n'y est que celle du mode restauration). **Limite de WAC, ouverte :** sur un contrôleur, les SID du domaine ne sont pas nommés par la table de noms (`SidName`, propriétaires…) ; le nom est dans `active_directory_objects.json`.
- 2026-11-03 : lot 2 branché : clé `group_policies`, test `group_policies_test`, politique témoin (valeur de registre, script de démarrage, tâche immédiate, mot de passe de préférence fictif, lien désactivé) et `check_group_policies`. Non commité, cycle à passer.
- 2026-11-03 : cycle court des lots 1 et 2 sur le contrôleur : 41 ✅, 1 ❌ du harnais (clé de référence vide, corrigée) : les 3 705 objets identiques, les 3 stratégies de `Get-GPO` avec leur version et leur nom, valeur de registre, script, tâche immédiate et lien témoins retrouvés, mot de passe de préférence signalé et sa valeur absente de la sortie. Lot 2 et harnais commités. Mutation du lot 2 en cours, restauration par git ; documentation en cours d'écriture.
- 2026-11-03 : mutation du lot 2, premier passage non concluant : les trois mutations appliquées ensemble, la borne retirée fait planter le test (défaut de page, code 5) et masque les deux autres. Sources et `bin/` restaurés par git, 14 contrôles sans échec. Relance une mutation à la fois.
- 2026-11-03 : mutation du lot 2, une à la fois : borne de `parseRegistryPol` retirée, le test plante sur la lecture hors tampon (code 5, aucun bilan) ; `cpassword` non filtré, 1 contrôle en échec ; `clsid` non filtré, 1 contrôle en échec. Restauré par git : 14 contrôles, 0 échec, `bin/` identique. Documentation du lot 2 écrite, tables d'artefacts et de couverture régénérées, 6 PDF sans débordement. Cycle complet du contrôleur lancé ensuite.

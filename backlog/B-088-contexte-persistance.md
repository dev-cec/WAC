# B-088 — Contexte de liaison : persistance

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
Run, `persistence`, services, tâches planifiées, dossiers de démarrage, WMI, profils PowerShell, `shadow_copy_registry`.

## Contexte à écrire
`Kind` `Persistence` (`Installation` pour un service) ; `Subject` l'exécutable lancé, **séparé de ses arguments** et variables résolues ; `How.CommandLine` la commande entière ; `Subject.Name` la tâche ou le service ; `Actor.Sid` (clé d'un utilisateur, `RunAsSID`).

## Référence indépendante
Cycle `win11-test` : témoins de persistance du harnais : chemin de l'exécutable égal à celui posé, arguments à part ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit : Run (programme sans ses arguments,
  variables d'un utilisateur sur son profil — `userCommandProgram` —, ruche
  d'origine — `hiveEvidence` : SOFTWARE, DEFAULT, NTUSER.DAT), `persistence`
  (premier programme du mécanisme, les autres valeurs en `Related`,
  empreintes), services (la DLL d'un service hébergé par svchost est le code
  exécuté, svchost et la commande de reprise en `Related` ; `ImagePath`
  relatif lu depuis le dossier de Windows), tâches (nommées par leur chemin ;
  programme de la première action Exec ; gestionnaires COM en `Related` ;
  compte d'exécution), dossiers de démarrage (fichier et empreintes, cible
  d'un raccourci), profils PowerShell, abonnements WMI (programme d'un
  consommateur en ligne de commande, `CreatorSID`, dépôt). Tests ; mutation
  (programme de la tâche pris hors de l'action Exec) vue échouer ; 361/361,
  `bin/` = compilation. Contrôle du harnais : IFEO, SilentProcessExit, Run de
  DEFAULT (dont `%SystemRoot%`), script de démarrage et son SHA-256 ; aucun
  service ni tâche non résolu ; rejoué sur la collecte sans Context : ❌ (vu).
  Reste : cycle VM.
- 2026-11-15 : cycle `win11-test` : **311 ✅, 0 ❌** ; les 5 témoins de
  persistance sujets de leur enregistrement, aucun service ni tâche non
  résolu. Définition de « fini » remplie (manuels : section « Le contexte de
  liaison », commune aux familles) : **à valider**.

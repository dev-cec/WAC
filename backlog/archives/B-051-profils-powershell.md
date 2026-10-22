# B-051 — Profils PowerShell (persistance)

| Statut | Priorité | Effort |
|---|---|---|
| fait (5dd91db1) | P2 | moyen |

## Pourquoi
Un script de profil PowerShell s'exécute à chaque lancement de PowerShell, pour tous les utilisateurs (`%windir%\System32\WindowsPowerShell\v1.0\profile.ps1`, `Microsoft.PowerShell_profile.ps1`) ou pour un seul (`Documents\WindowsPowerShell\…`, et `Documents\PowerShell\…` pour PowerShell 7) : un intrus y place une persistance qui ne passe ni par le registre, ni par une tâche, ni par un service. WAC n'en prélève aucun, sur aucune version. Remarque de l'utilisateur du 2026-10-17 : PowerShell s'installe sous Vista (et XP), absent par défaut — s'il est présent, ses traces doivent être prélevées.

## Source
Les profils de la machine et de chaque utilisateur, des hôtes console, ISE et VS Code (`Microsoft.PowerShellISE_profile.ps1`, `Microsoft.VSCode_profile.ps1`), de PowerShell 1 à 7 ; sous XP, `My Documents\WindowsPowerShell`.

## Sortie attendue
Une clé `powershell_profiles` ; chaque profil prélevé tel quel, et dans le JSON son chemin, sa portée (machine, utilisateur), son hôte, sa date de modification, son SHA-256 et son contenu.

## Référence indépendante
Témoins posés par le harnais (un profil machine, un profil utilisateur), confrontés à leur contenu et à leur empreinte.

## Tâches
- [x] Décision de l'utilisateur : oui, pour la 3.0 (2026-10-17)
- [x] Prélèvement et conversion : $PSHOME (System32, SysWOW64, Program Files\PowerShell\<version>), documents de chaque profil et dossier Personal redirigé (User Shell Folders) — 5dd91db1, avec deux factorisations préalables (decodeTextFile 8ab3fb83, redirectedShellFolder)
- [x] Témoins du harnais (profil machine, profil « wac ») et contrôle check-json — d440e15e
- [x] Documentation FR et EN, table des artefacts

## Journal
- 2026-10-17 : fiche proposée après la remarque de l'utilisateur sur PowerShell installable sous Vista. Constaté en chemin : les journaux PowerShell (`Windows PowerShell.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`) sont déjà pris avec les autres journaux ; l'historique PSReadLine n'était cherché qu'à partir de Windows 10 alors qu'il existe sous 7, 8 et 8.1 avec PowerShell 3 ou plus — corrigé (table des artefacts).
- 2026-10-17 : décision utilisateur — à faire pour la 3.0.
- 2026-10-22 : fait. Cycles complets : Windows 11 531 ✅ 0 ❌, Vista 367 ✅ 0 ❌, Windows 7 388 ✅ 2 ❌, XP SP1 83 ✅ 0 ❌ ; les deux profils témoins retrouvés avec portée, SHA-256 et texte sous 11, Vista et 7. Les 2 ❌ de Windows 7 sont étrangers à la fiche : la valeur Run témoin du cliché instantané n'était pas encore écrite dans la ruche (ni dans son journal) quand le harnais a pris le cliché, malgré 15 s d'attente — relu hors ligne dans le cliché collecté ; le harnais forcera l'écriture (RegFlushKey) avant le cliché.

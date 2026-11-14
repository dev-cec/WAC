# B-088 — Contexte de liaison : persistance

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

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
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

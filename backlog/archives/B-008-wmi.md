# B-008 — Abonnements WMI (dépôt CIM)

| Statut | Priorité | Effort |
|---|---|---|
| fait (5e637df) | P1 | fort |

## Pourquoi
Persistance WMI : filtre + consommateur + liaison, invisible au registre, prisée des intrusions.

## Source
`\Windows\System32\wbem\Repository\OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`.

## Sortie attendue
`wmi_persistence.json` : filtres, consommateurs (CommandLine, ActiveScript), liaisons.

## Référence indépendante
Abonnement de test créé par le harnais ; `Get-WmiObject -Namespace root\subscription` en référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- L'abonnement de test retrouvé ; aucun appel WMI par WAC.

## Tâches
- [x] Lecteur du dépôt CIM (cim_repository) : correspondance, index B-tree, pages de données, définitions de classes avec héritage et valeurs par défaut, instances
- [x] Instances de toute classe dérivée de __EventFilter, __EventConsumer, __FilterToConsumerBinding, __TimerInstruction, dans chaque espace de noms

## Journal
- 2026-09-29 : décision utilisateur — lecteur complet du dépôt CIM (pages, correspondance, index, classes), pas une recherche de motifs.
- 2026-09-30 : les deux dates d'en-tête d'une instance ne sont pas des dates de création (trois objets créés à des minutes d'écart portent la même) : non émises. WMI écrit son dépôt quelques minutes après une création : les témoins sont créés une fois et gardés.

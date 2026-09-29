# B-008 — Abonnements WMI (dépôt CIM)

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | fort |

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
- [ ] Lecteur du dépôt CIM (pages, mapping)
- [ ] Extraction des instances __EventFilter / __EventConsumer / __FilterToConsumerBinding

## Journal
- 2026-09-29 : décision utilisateur — lecteur complet du dépôt CIM (pages, correspondance, index, classes), pas une recherche de motifs.

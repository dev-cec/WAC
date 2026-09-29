# B-006 — Defender : historique des détections et quarantaine

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
Une détection effacée de l'observateur d'événements reste dans DetectionHistory ; la quarantaine garde le fichier malveillant (chiffré, clé RC4 publique).

## Source
`Windows Defender\Scans\History\Service\DetectionHistory\*` ; `Quarantine\Entries|ResourceData`.

## Sortie attendue
`defender_detections.json` ; fichiers de quarantaine déchiffrés en pièces (à décider : risque de manipuler le malveillant en clair).

## Référence indépendante
Détection EICAR provoquée dans la VM ; `Get-MpThreatDetection` en référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- La détection EICAR retrouvée avec chemin, menace et date.

## Tâches
- [ ] Format DetectionHistory
- [ ] Quarantaine : décision sur le déchiffrement
- [ ] Témoin EICAR

## Journal
- (vide)

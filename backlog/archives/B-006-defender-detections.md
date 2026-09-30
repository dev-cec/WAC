# B-006 — Defender : historique des détections et quarantaine

| Statut | Priorité | Effort |
|---|---|---|
| fait (2c59d97) | P2 | moyen |

## Pourquoi
Une détection effacée de l'observateur d'événements reste dans DetectionHistory ; la quarantaine garde le fichier malveillant (chiffré, clé RC4 publique).

## Source
`Windows Defender\Scans\History\Service\DetectionHistory\*` ; `Quarantine\Entries|ResourceData`.

## Sortie attendue
`defender_detections.json` et `defender_quarantine.json` ; quarantaine copiée chiffrée, contenu déchiffré en mémoire pour son empreinte seulement.

## Référence indépendante
Détection EICAR provoquée dans la VM ; `Get-MpThreatDetection` en référence.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- La détection EICAR retrouvée avec chemin, menace et date.

## Tâches
- [x] Format DetectionHistory : champs typés alignés sur 8 ; seuls les champs dont la position est confirmée par MSFT_MpThreatDetection (deux détections différentes) sont nommés, les autres rendus tels que lus
- [x] Quarantaine : copie chiffrée (décision utilisateur) ; balises 0x600F création et 0x6011 modification établies sur un fichier aux dates connues
- [x] Témoin EICAR daté (zone exclue puis analyse ciblée), confronté à MSFT_MpThreatDetection et au SHA-1 de la chaîne EICAR

## Journal
- 2026-09-30 : décision utilisateur — quarantaine copiée chiffrée ; rien de malveillant en clair sur le support ni sur le poste d'analyse.
- 2026-09-30 : 0x6010 égale l'instant de mise en quarantaine à la microseconde : non nommé. Deux champs varient ensemble avec DetectionSourceTypeID, deux dates égalent RemediationTime : non nommés.

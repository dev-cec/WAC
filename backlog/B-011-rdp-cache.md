# B-011 — Cache bitmap RDP et connexions RDP sortantes

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P3 | moyen |

## Pourquoi
Montre ce qu'un attaquant a vu sur une machine distante ; `Terminal Server Client` liste les serveurs contactés.

## Source
`AppData\Local\Microsoft\Terminal Server Client\Cache\*` ; NTUSER `Software\Microsoft\Terminal Server Client`.

## Sortie attendue
`rdp.json` (serveurs, dates, fichiers de cache et nombre de tuiles) ; tuiles en pièces.

## Référence indépendante
Connexion RDP de test depuis la VM.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Serveur contacté retrouvé ; tuiles extraites lisibles.

## Tâches
- [ ] Clés Terminal Server Client
- [ ] Format bcache*.bmc / cache*.bin

## Journal
- (vide)

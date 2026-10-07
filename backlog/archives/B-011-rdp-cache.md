# B-011 — Connexions RDP sortantes (cache bitmap) et entrantes

| Statut | Priorité | Effort |
|---|---|---|
| fait (83ef8aa) | P3 | moyen |

## Pourquoi
Sortantes : montre ce qu'un attaquant a vu sur une machine distante ; `Terminal Server Client` liste les serveurs contactés. Entrantes : qui s'est connecté à la machine, d'où et quand — peu fréquent sur un poste client, essentiel sur un serveur (demande utilisateur du 2026-10-07).

## Source
- Sortantes : `AppData\Local\Microsoft\Terminal Server Client\Cache\*` ; NTUSER `Software\Microsoft\Terminal Server Client` (Default\MRUn, Servers\<hôte>) ; fichiers `.rdp` des Documents.
- Entrantes : journaux d'événements collectés — TerminalServices-LocalSessionManager/Operational (21, 22, 23, 24, 25), TerminalServices-RemoteConnectionManager/Operational (1149), Security (4624/4625 de type 10, 4778, 4779).

## Sortie attendue
- `rdp_client.json` (clé `rdp_client`) : connexions récentes, serveurs, fichiers `.rdp`, caches et leurs tuiles exportées en images (`rdp_cache\`).
- `rdp_server.json` (clé `rdp_server`) : chaque trace de session entrante, avec utilisateur, adresse source, session, instant.

## Référence indépendante
Session RDP réelle en bouclage dans la VM (« wac » vers 127.0.0.2 avec un compte de test), sortante et entrante à la fois. Cache : bmc-tools (ANSSI), tuile par tuile. Entrantes : `Get-WinEvent` sur les mêmes journaux.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Serveur contacté retrouvé ; tuiles extraites lisibles.

## Tâches
- [x] Clés Terminal Server Client, fichiers .rdp
- [x] Format Cache*.bin (tuiles exportées) ; bcache*.bmc collecté, non décodé faute d'échantillon
- [x] Témoin VM et confrontation bmc-tools
- [x] Connexions entrantes (`rdp_server`)

## Journal
- 2026-10-07 : essai en VM. Une session en bouclage (« wac » → 127.0.0.2, compte de test) fonctionne, à condition de lancer `mstsc /v:` et non un fichier `.rdp` (Windows affiche désormais un avertissement à l'ouverture d'un fichier .rdp) et de fermer le client proprement : `Cache0000.bin` (version 6, 4 tuiles 64 x 64 et 64 x 32) n'est écrit qu'à la déconnexion par le client ; `bcache24.bmc` reste vide (pipeline graphique RDP 8). La clé `Servers\<hôte>` n'est écrite qu'après une ouverture de session réussie.
- 2026-10-07 : demande utilisateur — ne pas oublier les connexions entrantes, utiles surtout sur les serveurs.
- 2026-10-07 : fait. `rdp_client` (serveurs, MRU, fichiers .rdp, cache Cache*.bin décodé, tuiles exportées en BMP avec le SHA-256 de leurs pixels) et `rdp_server` (traces entrantes des journaux, User/Domain/SourceAddress/SessionId normalisés). Témoin : vraie session « wac » → 127.0.0.2, tout défait ensuite ; cache d'une session à la fois. bmc-tools (ANSSI) sur la copie de travail du cache : mêmes pixels, tuile par tuile (4 à 18 tuiles selon la session) ; 3 traces entrantes retrouvées, même utilisateur et même source. Test unitaire : 153 contrôles, un en-tête de tuile faux est pris.
- 2026-10-07 : **Close**. Cycle complet vert (448 ✅) une fois corrigés deux contrôles du harnais rendus fragiles par la durée des témoins (BAM, SRUM, commit de correction du harnais). Commits : 83ef8aa (artefacts, témoin, contrôles, documentation).

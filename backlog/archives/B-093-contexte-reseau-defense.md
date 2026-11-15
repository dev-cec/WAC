# B-093 — Contexte de liaison : réseau et défense

| Statut | Priorité | Effort |
|---|---|---|
| fait (7ece1838) | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
`network`, `network_configuration`, `known_networks`, `network_shares`, `hosts`, pare-feu, `internet_settings`, Defender (détections, quarantaine, journal), Sysmon, antivirus.

## Contexte à écrire
`Kind` `Network`, `Detection` ou `Configuration` ; `Subject` l'adresse, la règle, le fichier détecté (`Resources[].Path`, empreintes) ; `Actor.Process` le processus d'une connexion (chemin, plus seulement le nom) ; `Actor.Sid` de `DomainUser`.

## Référence indépendante
Cycle `win11-test` : EICAR du harnais : détection, quarantaine et MFT nomment le même `Subject` ; connexion témoin : processus résolu ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Ce qui est écrit
| JSON | `Kind` | Sujet | Autres |
|---|---|---|---|
| `network.json` (connexions) | `Network` | l'adresse distante (pas `0.0.0.0` ni `::`) | `How.RemoteAddress`, `RemotePort` ; `Actor.Process` : le chemin de son image (`processes.json` du même relevé) et le PID |
| `firewall_log.json` | `Network` | le côté distant : destination d'un `SEND`, source d'un `RECEIVE` | port, PID ; le journal |
| `hosts.json` (entrées) | `Configuration` | l'adresse | `Related` `HostName` : chaque nom ; le fichier `hosts` |
| `firewall.json` (règles) | `Configuration` | le programme (`App`, `%SystemRoot%` résolu), le nom de la règle | `Related` `Service` |
| `internet_settings.json` | `Configuration` | le premier serveur mandataire | `How.Url`/`Host` : le script de configuration ; acteur |
| `known_networks.json` | `Network` | `Name` : le nom du réseau | SOFTWARE |
| `network_shares.json` | `Configuration` | le dossier partagé, le nom du partage | SYSTEM |
| `network_configuration.json` (adaptateurs) | `Configuration` | l'adresse (fixe, sinon le bail DHCP) | SYSTEM |
| `defender_detections.json` | `Detection` | le premier fichier des ressources, le nom de la menace | `Related` `Resource`, `QuarantineEntry` ; acteur : `DomainUser` et son SID s'il est un compte local ; le processus par son chemin |
| `defender_quarantine.json` | `Detection` | le fichier retiré, SHA-1 et SHA-256 du contenu conservé (entier, déchiffré) | `Related` `QuarantineEntry` |
| `defender_configuration.json` (exclusions) | `Configuration` | le chemin ou le processus exclu, l'adresse, sinon le texte (extension) | SOFTWARE |
| `sysmon.json` | `Configuration` | le programme du service | `Related` `Driver`, `Archived` (avec SHA-256) |
| `defender_log.json` | aucun | — (texte libre) | le journal |

`localAccountSid` (`account_names`) : le SID d'un compte local d'après
« MACHINE\nom », sur le nom NetBIOS de la machine examinée
(`examinedComputerName`, lu dans sa ruche SYSTEM). Un autre domaine ne donne
rien : un compte de domaine homonyme est un autre compte. Les noms
traduits des comptes intégrés (« AUTORITE NT\SERVICE LOCAL ») ne sont pas
résolus : ils restent en `Actor.User`.

## Tâches
- [x] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [x] Tests unitaires, mutation vue échouer
- [x] Témoins et contrôles du harnais ; cycle vert
- [x] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).
- 2026-11-15 : `Context` écrit (tableau ci-dessus), tests dans
  `file_artefacts_test` ; contrôle `check_context_network` préparé : le
  fichier EICAR par la détection, la quarantaine (SHA-256 de la chaîne EICAR
  recalculé dans le contrôle) et la suppression du journal ; les témoins
  `hosts`, règle de pare-feu et proxy ; chaque connexion par le chemin de
  son processus, les témoins d'exclusion et de partage. Mutation vue échouer
  (côté distant inversé dans le journal du pare-feu), restauration.
- 2026-11-15 : cycle `win11-test` (`7ece1838`) : 316 ✅, 1 ❌ du contrôle lui-même — l'exclusion du processus `wac-excluded.exe`, un nom seul, était attendue en chemin ; WAC l'écrit à juste titre en `Name`. Contrôle corrigé, rejoué sur la même collecte : vert (EICAR par la détection, la quarantaine avec son SHA-256 et la suppression du journal ; hosts, règle, proxy, exclusions, partage ; 41 connexions par le chemin de leur processus).
- 2026-11-15 : validée par l'utilisateur ; fiche close et archivée (7ece1838).

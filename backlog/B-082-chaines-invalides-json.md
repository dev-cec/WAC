# B-082 — Chaînes invalides dans le JSON : canal d'événement lu au-delà de sa fin, `VT_BLOB` de l'index écrit en texte

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | petit |

## Pourquoi
Trouvé par WAE (E-010) le 2026-11-14, à l'import de la collecte
`win11-test` (Windows 11 26300) : `events.json` et `search_index.json`
contiennent des demi-paires de substitution isolées (`\udefd`, `\udbe0`),
qui ne sont pas de l'Unicode. WAE refuse le fichier à partir de là (5 485
événements lus sur 59 645) ; le vérificateur Python les accepte. Aucun
contrôle de `check-json.py` ne l'a vu : un JSON valide d'apparence, faux.

1. **`events.json`, `EvtSystemChannel`** d'un événement
   `Microsoft-Windows-AppXDeployment-Server` :
   `"Microsoft-Windows-AppXDep" + ~25 caractères sans rapport` (CJK, privés,
   demi-paires). Le nom est coupé, puis WAC écrit ce qui suit en mémoire :
   **lecture au-delà de la fin d'une chaîne** (règle commune n° 3 : toute
   lecture bornée par la taille réelle). Le même relevé montrait
   `EvtSourceLog='Microsoft-Windows-AppXDeploymentServer%…`. À chercher
   dans `events.cpp` (`sys->textOf(L"Channel")`, ligne ~201) et dans la
   lecture du nom de canal (`channel`) : chaîne de longueur fixe non
   terminée, ou nom de fichier `%4` mal décodé.
2. **`search_index.json`, `InvertedOnlyMD5` et `InvertedOnlyPids`** :
   type `VT_BLOB` (65, `search_property_types.cpp`), des octets ;
   `addSearchBlob` (`search_index.cpp`) essaie d'abord `utf16Strings` et
   les écrit comme texte s'ils « ressemblent » à de l'UTF-16. Un `VT_BLOB`
   s'écrit en hexadécimal, jamais en texte (sauf type texte déclaré).

## À faire
- Vérifier les CRC des blocs EVTX (en-tête, enregistrements) et marquer
  les enregistrements d'un bloc qui ne les vérifie pas ; confirmer que 1
  en vient ; sinon trouver la cause et la corriger, test unitaire sur un enregistrement
  dont le canal est le plus long relevé (`Microsoft-Windows-AppXDeploymentServer/Operational`).
- 2 : la table de Windows déclare aussi `VT_BLOB` (65) pour des listes de
  textes (`System.Author`, `System.Kind`, `System.Keywords`) : le texte
  reste deviné, mais `utf16Strings` refuse une demi-paire isolée, et
  `InvertedOnlyMD5`/`InvertedOnlyPids` (octets par nature) sont toujours en
  hexadécimal ; test dans `file_artefacts_test`.
- **Pas** de changement de `jsonEscape` : une demi-paire isolée y est
  échappée exprès (`\udXXX`) — un nom NTFS peut en porter une (mesuré :
  bases de User Access Logging, Server 2016), et la convertir en U+FFFD
  rendrait deux noms identiques. C'est une sortie légitime de WAC, que WAE
  doit lire (WAE E-022). Le défaut est d'en produire là où la source n'en
  a pas.

## Référence indépendante
WAE (lecture stricte, RapidJSON avec validation d'encodage) importe les deux
fichiers en entier ; `check-json.py` ne trouve aucune demi-paire isolée ;
le canal égale celui que donne `Get-WinEvent` pour le même `EventRecordID`.

## Journal
- 2026-11-14 : fiche créée (WAE E-010) ; les deux fichiers de la collecte
  `win11-test` du jour.
- 2026-11-14 : lecture du décodeur (`evtx.cpp`) : toutes les lectures
  (`name`, `value` T_STRING, CDATA) sont bornées par la taille du bloc ; la
  longueur de la chaîne est juste (≈ 50 caractères, celle du vrai nom),
  seuls les 25 derniers sont étrangers. Hypothèse : les octets sont **dans
  le bloc** — enregistrement réécrit pendant la copie à chaud du journal
  (journal ouvert, `dirty`), non une lecture hors tampon. WAC ne vérifie
  **aucune somme de contrôle EVTX** : le format en porte deux par bloc
  (CRC32 de l'en-tête, octets 0–0x78 et 0x80–0x200, stocké à 0x7C ; CRC32
  des enregistrements, de 0x200 à la fin des données, stocké à 0x34).
  À faire en plus : vérifier ces CRC, et dire par enregistrement que son
  bloc ne les vérifie pas (sans le taire ni le jeter) ; contrôle à confirmer
  sur le journal du prochain cycle (les `.evtx` de ce cycle ne sont pas sur
  l'hôte).
- 2026-11-14 : `jsonEscape` échappe exprès les demi-paires isolées (noms
  NTFS) : la tâche « ne jamais en écrire » retirée. Correctif de 2 écrit
  (`search_index.cpp` : `utf16Strings` refuse une demi-paire isolée,
  `InvertedOnly*` en hexadécimal) et son test (`file_artefacts_test`) ; à
  compiler et voir échouer par mutation après le cycle en cours.
- 2026-11-14 : cycle de la VM qui a vécu : `events.json` **sans** demi-paire
  (l'événement AppX corrompu ne se reproduit pas : en faveur d'un
  enregistrement réécrit pendant la copie à chaud) ; `search_index.json` :
  78, celles d'`InvertedOnly*`. Correctif de 2 compilé ; mutations vues
  échouer (demi-paire acceptée ; `InvertedOnly*` deviné en texte),
  restaurées, recompilées. Reste : CRC des blocs EVTX (1), cycle VM.

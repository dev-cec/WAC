# B-082 — Chaînes invalides dans le JSON : canal d'événement lu au-delà de sa fin, `VT_BLOB` de l'index écrit en texte

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | petit |

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
- Trouver la cause de 1, la corriger, test unitaire sur un enregistrement
  dont le canal est le plus long relevé (`Microsoft-Windows-AppXDeploymentServer/Operational`).
- 2 : `VT_BLOB` (et tout type non texte) en hexadécimal ; test unitaire.
- `Json` : ne jamais écrire une demi-paire isolée (une chaîne UTF-16
  invalide dite comme telle, ou ses unités en hexadécimal) — défense de
  dernier rang, avec test.
- `check-json.py` : refuser toute demi-paire isolée dans tout JSON du cycle
  (`json.loads` les accepte : contrôle explicite).

## Référence indépendante
WAE (lecture stricte, RapidJSON avec validation d'encodage) importe les deux
fichiers en entier ; `check-json.py` ne trouve aucune demi-paire isolée ;
le canal égale celui que donne `Get-WinEvent` pour le même `EventRecordID`.

## Journal
- 2026-11-14 : fiche créée (WAE E-010) ; les deux fichiers de la collecte
  `win11-test` du jour.

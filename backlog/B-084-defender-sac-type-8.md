# B-084 — Defender : un type inconnu du sac `ThreatTracking` coupait la suite en silence

| Statut | Priorité | Effort |
|---|---|---|
| à valider | P1 | petit |

## Pourquoi
Cycle `win11-test` (Windows 11 26300) du 2026-11-14, deux fois de suite :
❌ « ThreatTrackingSha1 of the detection differs from the quarantined
content ». Le fichier `DetectionHistory` de la détection, lu dans la VM,
porte 12 propriétés (`ThreatTrackingSha256`, `SigSeq`, `Id`, `StartTime`,
`ThreatName`, **`FileIdentity`**, `Sha1`, `SigSha`, `Size`, `MD5`,
`ScanFlags`, `IsEsuSig`) ; WAC n'en écrivait que 5. `parseBag`
(`defender_history.cpp`) ne connaissait que les types 3 à 6 et, sur un
autre, **s'arrêtait sans rien dire** : le SHA-1, le MD5 et la taille du
fichier détecté perdus — un JSON valide, incomplet, que rien ne signalait.

`ThreatTrackingFileIdentity`, nouveau sur ce Defender, est de **type 8** :
une longueur sur 4 octets puis les octets (96 relevés ; le SHA-256 du
fichier à la fin, le reste non documenté).

## À faire
- Type 8 lu : écrit en hexadécimal, tel que lu.
- Un type inconnu (ou une longueur qui sort du sac) : la propriété écrite
  avec `UndecodedType`, et la lecture s'arrête là — dit, pas tu.
- Test unitaire (`file_artefacts_test`) : type 8 puis SHA-1 lus ; type
  inconnu dit ; mutation vue échouer.

## Référence indépendante
Le fichier `DetectionHistory` relu dans la VM (noms des propriétés, en
UTF-16) ; `check-json.py` : `ThreatTrackingSha1` égal au SHA-1 du contenu
mis en quarantaine (EICAR).

## Journal
- 2026-11-14 : fiche créée ; cause trouvée en lisant le fichier de la
  détection dans la VM (12 propriétés, 5 écrites) ; correctif et test
  écrits.
- 2026-11-14 : compilé sans avertissement, `file_artefacts_test` 332/332 ;
  mutation (type 8 non lu) vue échouer, restaurée, recompilée,
  `bin/WAC.exe` = compilation. Reste : cycle VM (contrôle de la
  quarantaine vert).

# B-032 — Couverture de fichiers : ce que KapeTriage copie et WAC non

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | moyen |

## Pourquoi
B-015 a confronté la collecte de WAC (configuration du kit, sans binaires) à celle de KAPE, cible KapeTriage, sur la VM (`vmtest/kape-compare.sh --no-binary`). 1 130 fichiers communs, SHA-1 identiques sauf ceux écrits entre les deux collectes. Chaque écart de couverture doit être ajouté ou écarté avec sa raison.

## Source
`vmtest/results/kape/*/compare.txt`.

## Sortie attendue
KAPE seul, à ajouter :
1. **Raccourcis hors de Recent** : menu Démarrer (utilisateur et commun), Bureau (utilisateur et Public), Quick Launch et barre des tâches épinglée — 17 fichiers. Même décodeur que recentdocs.json.
2. **Ruche du profil Default** (`C:\Users\Default\NTUSER.DAT` et journaux) : modèle de tout nouveau profil ; une persistance posée là se propage.
3. **Métadonnées NTFS** : `$Secure:$SDS` (descripteurs de sécurité : propriétaires et ACL de chaque fichier de la $MFT), `$UsnJrnl:$Max`, `$Boot`, `$TxfLog`.
4. **Traces WPP de Defender** (`Support\*.bin`) : copie brute seulement, faute de format documenté.
Déjà au backlog : ActivitiesCache (B-010) ; navigateurs Edge et IE, WebCache, INetCookies (B-016).
5. **Clés maîtresses DPAPI** (`AppData\Roaming\Microsoft\Protect\<SID>\*`, `Preferred`, et celles du système sous `Windows\System32\Microsoft\Protect`) : copiées telles quelles (chiffrées par le mot de passe de l'utilisateur ou la clé DPAPI_SYSTEM). Elles permettent, à l'analyse et avec le mot de passe ou la clé, de déchiffrer les secrets de l'utilisateur : mots de passe enregistrés, identifiants, cookies. Décision utilisateur du 2026-10-01 : utiles à l'enquête, donc prises. Leur JSON : SID, GUID de la clé, dates, clé préférée et sa date d'expiration — jamais la clé.
Écartés : `desktop.ini`, sans valeur d'enquête.

WAC seul, pour mémoire (couverture que KapeTriage n'a pas) : historique PowerShell (PSReadLine), dépôt WMI, file BITS, rapports WER, historique de détection et quarantaine de Defender, journaux setupapi, fichiers hosts et réseau, dossiers de démarrage, ruches des profils de service et systemprofile, second volume et clés USB (FAT/exFAT), état vivant (processus, sessions, réseau, horloge), binaires des fournisseurs de messages.

## Référence indépendante
KAPE sur la même VM, même instant (`vmtest/kape-compare.sh`).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les points 1 à 5 ajoutés, avec leur JSON en --convert (sauf le 4, copie brute justifiée), ou écartés avec leur raison.
- kape-compare.sh ne montre plus de fichier « KAPE seul » non classé.

## Tâches
- [ ] 1 Raccourcis hors de Recent
- [ ] 2 Ruche Default
- [ ] 3 $Secure:$SDS (et sa lecture dans mft.json : propriétaire de chaque fichier), $UsnJrnl:$Max, $Boot, $TxfLog
- [ ] 4 Traces WPP de Defender
- [ ] 5 Clés maîtresses DPAPI (utilisateurs et système)

## Journal
- 2026-10-01 : ouverte depuis B-015.
- 2026-10-01 : décision utilisateur — les clés maîtresses DPAPI sont prises (elles servent l'enquête), au lieu d'être écartées.

# B-030 — Regrouper toutes les fonctions de conversion dans tools

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | moyen |

## Pourquoi
Des fonctions de conversion générales vivent dans des modules qui n'ont rien à voir avec elles : `toHexadecimal` dans `sha.h`, qu'evtx.cpp et reg_amcache.cpp doivent inclure pour afficher des octets ; `unixToFiletime` était enfermée dans system.cpp ; `realToText`, `windowsHex` (evtx.cpp), `realText`, `oleDateText` (ese_database.cpp) et d'autres restent locales. Résultat : on ne les trouve pas, on les recopie (un `bytesToHex` a failli doubler `toHexadecimal`). Demande utilisateur du 2026-09-30.

## Source
Tout `sources/` : fonctions de conversion d'octets, de nombres, de dates (FILETIME, Unix, OLE, textes), de GUID, d'encodages.

## Sortie attendue
Un seul endroit (`tools.h`/`tools.cpp`, ou un `conversions.h/.cpp` inclus par tools.h) qui porte toutes les conversions générales ; les modules n'incluent plus un en-tête métier (sha.h…) pour une conversion. Une fonction paramétrée plutôt qu'une par type (voir la règle « regrouper les conversions »).

## Référence indépendante
Les tests existants (system_conversions_test, evtx_test, ese_test, link_tracking_test…) et un cycle VM complet : sorties JSON identiques avant et après (comparaison octet à octet des JSON d'une même collecte convertie deux fois).

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Inventaire des conversions dupliquées ou déplacées, dans le journal.
- Aucun changement de sortie : JSON identiques avant/après sur la même collecte.
- Commit `refactor :` seul, sans changement de comportement mêlé.

## Tâches
- [x] Inventaire (grep des conversions locales et des en-têtes inclus pour une seule fonction) — voir le journal du 2026-10-07
- [x] Lecture little-endian : 13 copies → readLittleEndian<T> (pointeur ou vecteur borné), writeLittleEndian<T>
- [ ] Déplacement dans tools, suppression des doublons
- [ ] Conversion d'une collecte avant/après, JSON comparés

## Journal
- 2026-09-30 : créée à la demande de l'utilisateur, à faire en fin de refactoring.
- 2026-10-01 : `readLittleEndian<T>` ajouté à tools.h (B-032) ; les copies locales `rd16/rd32/rd64` (mft.cpp, fat_volume.cpp, ese_database.cpp, bits_jobs.cpp, defender_history.cpp, cim_repository.cpp, hive_recover.cpp, pe_resource.cpp) sont à y ramener.
- 2026-10-01 : `conversions.h` créé, en-tête autonome inclus par tools.h et sha.h : `toHexadecimal` (sorti de sha.h/sha.cpp) et `readLittleEndian` y sont. Plus besoin d'inclure sha.h pour afficher des octets ; les `#include "sha.h"` des modules qui ne l'utilisaient que pour cela restent à retirer, et les `rd16/rd32/rd64` locaux à ramener. 66 JSON identiques avant/après sur une même collecte.
- 2026-10-07 : `splitNtfsReference` (B-022) ajouté à `conversions.h` : le découpage d'une référence de fichier NTFS, écrit dix-sept fois à la main (mft, usn_journal, raw_hive, idList, prefetchs), y est ramené ; celui de prefetchs était faux. Copies locales `rd64` encore présentes dans bits_jobs, fat_volume, cim_repository, defender_history, ese_database, hive_recover, recycle_bin, mft, usn_journal, raw_hive.
- 2026-10-07 : inventaire. Familles en double : lecture little-endian (13 fichiers) ; entier 64 bits → FILETIME (consigne, bits_jobs, defender_history, mft, web_client, + network depuis LARGE_INTEGER) ; GUID depuis des octets (bits_jobs, defender_history, wevt ; tools a guid_to_wstring) ; hexadécimal (evtx windowsHex, defender_history hexOf, ntfs_volumes upperHex, wevt hexadecimal ; tools a to_hex et toHexadecimal) ; réel → texte (cim_repository realText, ese_database realText — même nom —, evtx realToText) ; dates d'époques (ese oleDateText, web_client chromiumTime/firefoxTime ; tools a unixToFiletime, oleDateToSystemTime). Binaire d'avant B-030 gardé pour la comparaison finale des JSON.

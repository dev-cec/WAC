# B-001 — Clés JSON cohérentes en anglais

| Statut | Priorité | Effort |
|---|---|---|
| à commiter | P1 | faible |

## Pourquoi
Des clés hétérogènes (`Childs`, `Sha1` et `SHA1`) gênent WAE et un lecteur humain ; la règle de nommage exige un seul nom par concept.

## Source
Sorties JSON existantes.

## Sortie attendue
`Childs`→`Children`, `Dir`/`Dirs`→`Directory`/`Directories`, `FilesStrings`→`FileNames`, `Md5`/`Sha1`/`Sha256`/`AuthenticodeSha256`→`MD5`/`SHA1`/`SHA256`/`AuthenticodeSHA256`, `LNKFlags`→`LinkFlags`.

## Référence indépendante
Relevé de toutes les clés des sorties réelles (354 clés) ; WAE n'utilise aucune clé renommée.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Aucune clé hors anglais ni abréviation hors domaine dans les sorties du cycle VM.
- check-json.py lit les nouveaux noms (Prefetch : `FileNames`).

## Tâches
- [x] Renommer dans le code et check-json.py
- [x] Cycle VM vert (29/09)
- [ ] Commit seul, sans le lot B-002

## Journal
- 2026-09-29 : renommage fait, cycle VM vert ; commit en attente.

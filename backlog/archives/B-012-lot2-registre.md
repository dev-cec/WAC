# B-012 — Lot 2 : registre utilisateur et système

| Statut | Priorité | Effort |
|---|---|---|
| fait (2fc0ba7) | P2 | faible |

## Pourquoi
Office TrustRecords (documents dont les macros ont été activées), magasins de certificats (racines ajoutées), proxy, règles et journal du pare-feu, TypedPaths, WordWheelQuery, RecentApps, thumbcache.

## Source
Ruches déjà copiées ; `pfirewall.log` ; `thumbcache_*.db`.

## Sortie attendue
Un fichier JSON par artefact, clé `artefacts:` par artefact.

## Référence indépendante
Valeurs de test posées par le harnais.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Chaque valeur posée retrouvée.

## Tâches
- [x] TrustRecords → office_trust_records.json
- [x] Certificats racines → root_certificates.json (SHA-1 contrôlé contre le nom de la clé)
- [x] Proxy → internet_settings.json ; pare-feu → firewall.json (règles et profils ; le journal pfirewall.log, désactivé par défaut, reste à faire)
- [x] TypedPaths, WordWheelQuery → typed_paths.json, word_wheel_query.json ; RecentApps écarté (supprimé par Windows 10 1809)
- [ ] thumbcache : déplacé dans B-026 (format binaire à part)

## Journal
- 2026-09-29 : six artefacts dans registry_lot2.{h,cpp} (une structure commune, un fichier JSON et une clé chacun). SummarizeCertificate ajouté à authenticode (sujet, émetteur, validité). forEachProfileHive mis en commun (Run et persistance y passent). Clés JSON sans abréviation (Dir→Direction, LPort→LocalPort, App→Application, AutoConfigURL→AutoConfigUrl), champs bruts gardés. file_artefacts_test 43/0 (un attendu du test faux corrigé : six champs, pas cinq). Cycle VM lancé.
- 2026-09-29 : cycle VM vert du premier coup ; commité (2fc0ba7), fiche archivée. Restent ailleurs : thumbcache (B-026), journal pfirewall.log (à ouvrir si utile).

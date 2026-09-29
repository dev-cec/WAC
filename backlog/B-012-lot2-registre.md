# B-012 — Lot 2 : registre utilisateur et système

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P2 | faible |

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
- [ ] TrustRecords
- [ ] Certificats racines ajoutés
- [ ] Proxy et pare-feu
- [ ] TypedPaths, WordWheelQuery, RecentApps
- [ ] thumbcache

## Journal
- (vide)

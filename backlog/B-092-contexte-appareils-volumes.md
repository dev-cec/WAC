# B-092 — Contexte de liaison : appareils et volumes

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
USBSTOR, `devices`, `setupapi`, `mount_points`, `mounted_device`, `ntfs_volumes`, `fat_volumes`, `shadow_copies`.

## Contexte à écrire
`Kind` `Installation` (appareil) ou `Access` (volume) ; `Subject.Device` (identifiant d'instance) et `Subject.Serial` ; `Related` le volume (GUID, lettre, numéro de série) : la chaîne appareil ↔ volume ↔ lettre ↔ numéro de série que lisent les raccourcis (B-090).

## Référence indépendante
Cycle `win11-test` : clé USB virtuelle du harnais : même numéro de série de l'appareil aux raccourcis qui en ouvrent un fichier ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

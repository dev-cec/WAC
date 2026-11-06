# B-073 — `application_registry` : PuTTY, WinSCP, WinRAR et 7-Zip dans le registre

| Statut | Priorité | Effort |
|---|---|---|
| à faire (5.0.0, code mis de côté) | P2 | faible |

## Pourquoi
Les sessions et clés d'hôte de PuTTY et WinSCP nomment les machines atteintes depuis celle-ci ; l'historique de WinRAR et de 7-Zip, les archives préparées avant une sortie de données. Hors de la portée de KAPE, qui copie la ruche sans la lire.

## Source
`NTUSER.DAT\Software` de chaque profil : `SimonTatham\PuTTY`, `Martin Prikryl\WinSCP 2`, `WinRAR`, `7-Zip`. Une option par produit.

## Sortie attendue
`application_registry.json` : Sid, Product, Key, KeyLastWrite, Values. Une valeur dont le nom contient « password » n'est pas émise, `HasPassword` le dit. Ruche déjà copiée, aucun prélèvement de plus.

## Référence indépendante
Clés témoins posées dans la ruche de l'utilisateur, confrontées à `reg query` et à `regipy`.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Valeur de mot de passe témoin absente du JSON, `HasPassword` présent.
- Test vu échouer par mutation de `isPasswordValue`.
- Valable sur **les clients comme sur les serveurs** : mesuré au moins sur Windows 11 (`win11-test`) et sur un serveur ; disposition XP et Server 2003 (`Documents and Settings`, `All Users`) vérifiée sur `srv2003`, qui a cette disposition.
- Option par produit lue, un produit à `false` non pris, son voisin pris, une clé inconnue refusée ; un groupe à `false` coupe tous ses produits.
- Un produit absent de la machine n'ajoute rien, ni au dépôt ni au journal d'investigation.
- Innocuité : lecture NTFS brute, rien d'écrit sur la machine examinée.
- Limite écrite dans les manuels FR et EN : ce que le témoin prouve et ne prouve pas.

## Tâches
- [x] Lecteur écrit, non compilé
- [x] Règle du mot de passe au test natif
- [ ] Témoins en VM
- [ ] Contrôle dans `check-json.py`

## Journal
- 2026-11-05 : fiche ouverte à la demande de l'utilisateur, le code étant déjà écrit (voir B-062).
- 2026-11-05 : décision de l'utilisateur : la 4.0.0 se clôt avec les serveurs, cet artefact passe en **5.0.0**. Code écrit mais jamais compilé, retiré de `sources/` et gardé dans le `git stash` « 5.0.0 : traces d'applications », sur `1a05c822`.

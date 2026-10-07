# B-017 — Courriels et pièces jointes

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P2 | fort |

## Pourquoi
Messages et pièces jointes, y compris les copies ouvertes depuis le client (cache OLK, Content.Outlook).

## Source
PST/OST, profils Thunderbird, dossiers temporaires d'Outlook.

## Sortie attendue
Décidé le 2026-10-07 (portée de la 2.0.0) :
- Thunderbird : boîtes mbox des profils, décodées.
- Outlook : PST et OST décodés par WAC (format NDB/LTP : en-têtes, B-arbres, tables de propriétés), sans bibliothèque tierce.
- Copies ouvertes depuis le client : `Content.Outlook` (INetCache), cache OLK.
- JSON par message : expéditeur, destinataires, objet, dates, dossier, identifiant ; pièces jointes extraites en pièces, avec leurs empreintes et le message d'origine.

## Référence indépendante
- PST : corpus public téléchargé, non versionné, épinglé par SHA-256 (comme les index.dat de plaso) ; lecteur indépendant : pypff (libpff), sur les mêmes fichiers. Pas d'OST réel disponible.
- Thunderbird : installé dans la VM de test, un message témoin (pièce jointe comprise) écrit par Thunderbird lui-même ; lecteur indépendant : le module mailbox de Python sur la copie de travail.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Pièce jointe de test retrouvée avec son message.

## Tâches
- [ ] Format PST/OST
- [ ] Caches

## Journal
- (vide)
- 2026-10-07 : portée décidée par l'utilisateur — Outlook (PST/OST décodés) et Thunderbird, plus les copies ouvertes.
- 2026-10-07 : en cours. Décisions de l'utilisateur : PST d'un corpus public (référence pypff), Thunderbird installé dans la VM (référence mailbox de Python).

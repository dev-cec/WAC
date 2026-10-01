# B-034 — La base SAM convertie en entier

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Un mot de passe vide ou faible utilisé par un attaquant fait passer sa connexion pour légitime. L'utilisateur veut pouvoir le vérifier après coup (décision du 2026-10-01). Ce repérage est fait par **WAE** ; WAC, lui, convertit la SAM en JSON, en entier. Aujourd'hui, `users.json` n'en donne qu'une partie : nom, RID, drapeaux, dates, compteurs.

## Source
Ruche SAM, déjà copiée brute dans chaque collecte, avec SYSTEM.

## Sortie attendue
Le contenu de la SAM en JSON, compte par compte, avec tout ce que WAE doit lire pour son analyse. Les groupes locaux et leurs membres aussi, qui disent quel compte est administrateur.

## Référence indépendante
Comptes témoins de la VM, créés par le harnais : un sans mot de passe, un à mot de passe connu. WAE doit les reconnaître à partir du JSON de WAC.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les comptes témoins reconnus par WAE.
- Les documents (manuel, dossier d'innocuité) disent ce que WAC prélève de la SAM.

## Tâches
- [ ] Inventaire de ce que users.json ne donne pas encore
- [ ] Alias (groupes locaux) et leurs membres ; droits des comptes de SECURITY\Policy\Accounts (SeDebugPrivilege, SeRemoteInteractiveLogonRight…), venus de B-031
- [ ] Conversion
- [ ] Témoins dans la VM

## Journal
- 2026-10-01 : ouverte sur décision de l'utilisateur ; l'analyse des mots de passe revient à WAE.

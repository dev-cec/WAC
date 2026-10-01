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

### Décisions (2026-10-01)
- **Condensats** : déchiffrés. WAC dérive la clé de démarrage de SYSTEM, la clé de hachage de la SAM, puis déchiffre les condensats NT et LM (schéma AES de Win10+, schéma RC4 ancien, puis la couche DES par RID) et les écrit en hexadécimal. WAE les compare aux condensats connus (mot de passe vide, dictionnaire). L'historique des condensats aussi.
- **Questions de sécurité** : la valeur `ResetData` (JSON en clair sous le compte) est convertie telle quelle, questions ET réponses : une réponse triviale est une faiblesse au même titre qu'un mot de passe faible, et WAE la juge.
- **Mécanique isolée** dans `sam_secrets.h/.cpp` : clé de démarrage, clé de hachage, déchiffrement par compte. `users.cpp` l'appelle. BCrypt (CNG) pour AES-CBC, DES-ECB et MD5 ; RC4 réécrit (clé paramétrée).
- **Contrôle indépendant** : un compte témoin de la VM à mot de passe connu. Le condensat NT relevé par WAC doit égaler MD4(mot de passe en UTF-16LE), recalculé dans le harnais (MD4 réécrit en Python, OpenSSL 3 l'ayant retiré ; vérifié sur le vecteur RFC et sur le mot de passe vide = `31d6cfe0d16ae931b73c59d7e0c089c0`). Ce seul compte exerce toute la chaîne — clé de démarrage, clé de hachage, AES, DES — contre un calcul indépendant. Pas d'outil tiers requis.

## Référence indépendante
Comptes témoins de la VM, créés par le harnais : un sans mot de passe, un à mot de passe connu. WAE doit les reconnaître à partir du JSON de WAC.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les comptes témoins reconnus par WAE.
- Les documents (manuel, dossier d'innocuité) disent ce que WAC prélève de la SAM.

## Tâches
- [x] Inventaire de ce que users.json donne déjà : nom, nom complet, commentaire, SID, RID, désactivé, drapeaux, profil, compteurs, dates. Manquent : condensats, historique, questions de sécurité, groupes locaux, droits.
- [x] 1 Clé de démarrage (SYSTEM) + clé de hachage (SAM) + condensats NT/LM déchiffrés dans users.json ; témoin
- [x] 2 Historique des condensats
- [ ] 3 Questions de sécurité (ResetData)
- [ ] 4 Alias (groupes locaux) et leurs membres
- [ ] 5 Droits des comptes de SECURITY\Policy\Accounts (venus de B-031)

## Journal
- 2026-10-01 : ouverte sur décision de l'utilisateur ; l'analyse des mots de passe revient à WAE.
- 2026-10-01 : tâches 1 et 2 faites. `sam_secrets.h/.cpp` : clé de démarrage (classes de Control\Lsa, permutées), clé de hachage (SAM Domains\Account F, RC4 rev.1 / AES-CBC rev.2), condensats NT/LM par compte (schéma du blob + couche DES par RID), historique. BCrypt pour AES-CBC et DES-ECB, MD5 par QuickDigest5, RC4 réécrit à clé paramétrée. `users.json` porte NtHash, LmHash, NtHashHistory, LmHashHistory. Témoin VM : compte à mot de passe connu, changé une fois (stratégie d'historique relevée à 5) ; le harnais recalcule MD4(mot de passe UTF-16LE) — condensat courant et ancien dans l'historique, chaîne vérifiée de bout en bout. MD4 réécrit en Python (OpenSSL 3 l'a retiré). Première jointure de -lbcrypt. L'historique SAM place le condensat courant en tête : restitué tel quel.

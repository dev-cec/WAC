# B-034 — La base SAM convertie en entier

| Statut | Priorité | Effort |
|---|---|---|
| fait (6fd3d3d à 5a03dd4) | P1 | moyen |

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
- [x] 3 Questions de sécurité (ResetData)
- [x] 4 Alias (groupes locaux) et leurs membres
- [x] 5 Droits des comptes de SECURITY\Policy\Accounts (venus de B-031)

## Journal
- 2026-10-01 : ouverte sur décision de l'utilisateur ; l'analyse des mots de passe revient à WAE.
- 2026-10-01 : tâches 1 et 2 faites. `sam_secrets.h/.cpp` : clé de démarrage (classes de Control\Lsa, permutées), clé de hachage (SAM Domains\Account F, RC4 rev.1 / AES-CBC rev.2), condensats NT/LM par compte (schéma du blob + couche DES par RID), historique. BCrypt pour AES-CBC et DES-ECB, MD5 par QuickDigest5, RC4 réécrit à clé paramétrée. `users.json` porte NtHash, LmHash, NtHashHistory, LmHashHistory. Témoin VM : compte à mot de passe connu, changé une fois (stratégie d'historique relevée à 5) ; le harnais recalcule MD4(mot de passe UTF-16LE) — condensat courant et ancien dans l'historique, chaîne vérifiée de bout en bout. MD4 réécrit en Python (OpenSSL 3 l'a retiré). Première jointure de -lbcrypt. L'historique SAM place le condensat courant en tête : restitué tel quel.
- 2026-10-01 (relecture) : code revu. WAC est 64 bits, les offsets de la valeur V ne débordent pas ; chaque lecture est bornée par `start + len > v.size()` (ruche forgée). À surveiller : le schéma **RC4** (images Windows 7/8) suit la spécification mais n'est pas exercé par la VM Win11 (en AES) ; il reflète à l'identique le chemin AES, validé de bout en bout. À exercer sur une image ancienne quand l'occasion se présente.
- 2026-10-01 : tâches 3, 4 et 5 faites, chacune recoupée en VM.
  - **Groupes locaux** (local_groups.json, clé registry) : alias de SAM Builtin (S-1-5-32) et Account, valeur C décodée (en-tête de 13 DWORD, données à 0x34 : nom, description, membres en SID empaquetés). Recoupé avec Get-LocalGroupMember sur 21 groupes ; compte témoin ajouté aux Administrateurs. SID du groupe émis ; membres résolus hors ligne (getNameFromSid). Fichier exclu de check_account_names (nommé depuis la SAM, comme users.json).
  - **Droits des comptes** (AccountRights dans security.json) : Policy\Accounts\<SID>, Privilgs (LUID bien connus 2..36 → noms) et ActSysAc (bitmask des droits de connexion). Recoupé avec secedit /export (33 droits) ; les SID de service virtuels que secedit ne retraduit pas sont tolérés en extra.
  - **Questions de sécurité** (SecurityQuestions dans users.json) : valeur ResetData parsée en JSON (Json::parse, entrée hostile), questions et réponses en clair. Témoin écrit directement dans la SAM (SYSTEM peut) faute de cmdlet, relu identique.
  - Dossier d'innocuité mis à jour : la ruche SAM voit ses condensats déchiffrés et les questions lues en clair, collecte voulue, sur la copie, machine non touchée.
- 2026-10-01 : close. B-034 terminée.

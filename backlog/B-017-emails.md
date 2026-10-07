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
- [x] Corpus de test et lecteur de référence (pypff dans vmtest/tools/pff-venv, non versionné)
- [x] Couche NDB du PST/OST (pst_file) : en-tête, B-arbres des nœuds et des blocs, permutation, arbres de blocs et de sous-nœuds ; pages de 4 Kio et blocs zlib (Adler-32 vérifié) de l'OST d'Outlook 2013+
- [x] Couche LTP : tas (HN), B-arbre sur tas (BTH), contexte de propriétés (PC), table (TC)
- [x] Messagerie (pst_messages) : dossiers, messages, destinataires, pièces jointes, objets intégrés (méthode 5) — pst_test : 1 800 contrôles, les 256 messages lus par pypff identiques champ par champ (objet, expéditeur, dates, pièces jointes nom/taille/SHA-256, corps), et les 4 que pypff ne lit pas lus par WAC
- [ ] Mutation vue échouer ; commit du lecteur
- [ ] Artefact emails : export des pièces jointes et des corps, JSON
- [ ] Thunderbird : mbox des profils, MIME (en-têtes encodés, multipart, base64, quoted-printable), pièces jointes ; Thunderbird installé dans la VM, message témoin, confronté au module mailbox de Python
- [ ] Copies ouvertes : Content.Outlook (INetCache), cache OLK, prélevées
- [ ] Clé emails, prélèvement (Outlook Files, AppData\Local\Microsoft\Outlook, profils Thunderbird), conversion, documentation FR + EN, cycle complet

## Journal
- (vide)
- 2026-10-07 : portée décidée par l'utilisateur — Outlook (PST/OST décodés) et Thunderbird, plus les copies ouvertes.
- 2026-10-07 : en cours. Décisions de l'utilisateur : PST d'un corpus public (référence pypff), Thunderbird installé dans la VM (référence mailbox de Python).
- 2026-10-07 : corpus de test, non versionné, épinglé par SHA-256 :
  - java-libpst (Apache 2.0) : dist-list.pst c86841da…28ac, passworded.pst e1085e21…f217 (Unicode, version 23), example-2013.ost b18ff390…853d (version 36, pages de 4 Kio, compressé) ; 8 éléments, l'OST d'Outlook 2013 couvert ;
  - EDRM Enron v2 publié par intellekthq sur Hugging Face (CC-BY 3.0 US, retouché : données sensibles supprimées, espace libre écrasé) : zl_south-s_000.pst 852f2090…04ab, 246 messages, 65 pièces jointes, 4 éléments que pypff ne lit pas (structures abîmées : la robustesse de WAC y sera éprouvée).
- 2026-10-07 : déjà dans WAC : DEFLATE (inflate.cpp), base64 (authenticode.h, à ramener dans conversions.h quand il servira hors d'Authenticode).
- 2026-10-07 : format relevé sur le corpus. PST : version 23 (Unicode), chiffrement 1 (permutation : table mpbbI de [MS-PST] §5.1). OST d'Outlook 2013 : version 36, pages de B-arbre de 4 096 octets (remorque de 24 octets à 4 072), blocs alignés sur 512 avec une remorque de 24 octets portant la taille décompressée ; 62 blocs sur 310 compressés, en flux zlib (0x78 0x9C, DEFLATE, Adler-32). Chiffrement 2 (« cyclique ») : aucun échantillon — non décodé, et dit. Format ANSI (versions 14/15, Outlook 97-2002) : hors corpus, non décodé.
- 2026-10-07 : lecteur écrit (pst_file, pst_messages, pst_test, pst_fixtures.sh). Deux écarts du premier passage expliqués : (1) les pièces jointes d'un rendez-vous sont des objets intégrés (PtypObject, méthode 5) — la valeur nomme un sous-nœud, dont pypff rend les octets ; WAC aussi, et décode en plus ses propriétés comme un message ; (2) pypff ne donne pas d'attribut subject à un élément de disponibilité (IPM.Microsoft.ScheduleData.FreeBusy) bien que le fichier porte « LocalFreebusy » : la référence lit alors la propriété 0x0037 dans le jeu d'enregistrements de pypff. Non commité.

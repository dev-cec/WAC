# B-023 — Messages lisibles d'environ un tiers des événements seulement

| Statut | Priorité | Effort |
|---|---|---|
| fait (2991808, d1c0ca5, 4eb43bd, 0380615, 788490d, 453225e) | P3 | moyen |

## Pourquoi
Deux tiers des événements n'ont pas de message lisible : fournisseurs sans ressources exploitables, ou lacune du décodage.

## Source
`event_messages.cpp`.

## Sortie attendue
Taux mesuré par fournisseur.

## Référence indépendante
Le message que Windows rend lui-même (EvtFormatMessage, par `Get-WinEvent`) pour chaque sorte d'événement de la VM — fournisseur, identifiant, version, qualificatifs —, sur le même enregistrement. Relevé à chaque cycle (`vmtest/guest/event-messages-reference.ps1`, lecture seule) et comparé par `check-json.py`.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Écart expliqué fournisseur par fournisseur.

## Tâches
- [x] Mesure par fournisseur, contre Windows
- [x] Corrections, une par cause mesurée
- [x] Contrôle permanent dans le cycle (seuil 90 %)

## Journal
- 2026-10-06 : mesure de départ, contre Windows : 28 % des événements avec un message, 261 sortes sur 911 au message identique. Causes trouvées une à une, chacune mesurée sur les fournisseurs réels de la VM :
  - pas des descripteurs du WEVT_TEMPLATE déduit de la taille du bloc EVNT (52 octets au lieu de 48 : des données suivent les descripteurs) — la cause principale ;
  - sources classiques (ReportEvent) ignorées ; puis leur EventSourceName (COM+), leur providerGuid, et le repli quand le manifeste ne décrit pas l'événement (CAPI2 4097) ;
  - entrées de table UTF-8 lues octet par octet ; satellite en-US préféré au fr-FR (la langue de l'interface est dans SYSTEM\Control\MUI, pas dans SOFTWARE) ;
  - espaces des données rognés par le lecteur XML (aussi dans EvtEventData) ; plusieurs %%nnnn dans une valeur ;
  - valeurs non typées : tables de valeurs et de drapeaux (VMAP, BMAP : lien à l'octet 8 du descripteur d'élément, un offset par table, en-tête de 20 octets — mesuré, libfwevt l'ignore), hexadécimal, texte des codes Win32/HRESULT/NTSTATUS (tables de kernelbase et ntdll), ErrorCode en hexadécimal, binaire et adresse réseau ;
  - données décalées par un tableau ou une feuille vide de UserData : alignement des données sur les éléments par leur nom ;
  - manifeste déplacé dans SystemResources\<nom>.mun (Shell-Core) ;
  - en collecte séparée (--collect), CurrentControlSet jamais ouvert, sources classiques et tables du système non prélevées.
- 2026-10-06 : résultat : 99,6 % des événements avec un message ; 887 sortes sur 898 identiques à Windows (98,8 %), collecte directe comme séparée. Écarts restants expliqués (dossier de validation) : Windows n'applique pas une table sur une donnée hexadécimale comme le dit le manifeste (4 sortes, WAC suit le manifeste) ; satellites fr-FR plus anciens que leur binaire, dont Windows ne prend pas le texte (4 sortes, origine du texte de Windows non trouvée) ; FILETIME nul (1) ; deux sortes sans message (ProcessingErrorData, Perflib 0).
- 2026-10-06 : **Close**. Cycle complet vert (437 ✅, 0 ❌), innocuité comprise. Commits : 9740e4a (renommage), 2991808, d1c0ca5, 4eb43bd, 0380615, 788490d (code et tests), 453225e (harnais), 3703f80 (documentation).

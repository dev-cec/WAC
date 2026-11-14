# B-093 — Contexte de liaison : réseau et défense

| Statut | Priorité | Effort |
|---|---|---|
| à faire | P1 | moyen |

## Pourquoi
Famille de l'étude B-078 (schéma validé par l'utilisateur le 2026-11-14) :
WAC écrit dans chaque enregistrement le bloc `Context` qui permet à WAE
d'ouvrir le dossier de n'importe quel objet (E-014). Après le socle B-079.

## JSON concernés
`network`, `network_configuration`, `known_networks`, `network_shares`, `hosts`, pare-feu, `internet_settings`, Defender (détections, quarantaine, journal), Sysmon, antivirus.

## Contexte à écrire
`Kind` `Network`, `Detection` ou `Configuration` ; `Subject` l'adresse, la règle, le fichier détecté (`Resources[].Path`, empreintes) ; `Actor.Process` le processus d'une connexion (chemin, plus seulement le nom) ; `Actor.Sid` de `DomainUser`.

## Référence indépendante
Cycle `win11-test` : EICAR du harnais : détection, quarantaine et MFT nomment le même `Subject` ; connexion témoin : processus résolu ; un contrôle de `check-json.py` par sorte
d'objet, sur la valeur posée par le harnais, jamais sur la seule forme.

## Tâches
- [ ] `Context` de chaque JSON de la famille, selon les tableaux de B-078
- [ ] Tests unitaires, mutation vue échouer
- [ ] Témoins et contrôles du harnais ; cycle vert
- [ ] Manuels FR et EN

## Journal
- 2026-11-14 : fiche créée (découpage de B-078 validé par l'utilisateur).

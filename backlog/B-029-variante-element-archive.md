# B-029 — Variante d'élément d'archive mal décodée

| Statut | Priorité | Effort |
|---|---|---|
| en cours | P3 | faible |

## Pourquoi
Dans la collecte réelle du 15/09 (ravenwood), certains éléments de shell classés ARCHIVE_FILE_CONTENT (types 0x3b, 0x00) sortent avec un nom illisible (« \x10\x01 01/01/1980  00:00:00 »). La date sous forme de texte est lue à la place du nom : c'est une variante dont les décalages diffèrent. Vu dans B-028.

## Source
Shellbags d'une machine réelle. Les ruches brutes de ravenwood n'ont pas été gardées : il faut une nouvelle collecte réelle qui conserve sa consigne.

## Sortie attendue
Nom et date de l'élément justes, ou l'élément signalé non décodé.

## Référence indépendante
ShellBagsExplorer / SBECmd (outils Zimmerman) sur la même ruche.

## Critères d'acceptation
En plus de la définition de « fini » commune (backlog/README.md) :
- Les éléments de la variante lus comme SBECmd les lit.

## Tâches
- [ ] Obtenir les octets d'un élément de la variante (collecte réelle avec sa consigne)
- [ ] Décodage et test

## Journal
- 2026-09-30 : sorti de B-028, qui traitait les fuseaux ; ce défaut est de décodage.
- 2026-10-07 : en cours — recherche d'un échantillon de la variante et lecture du décodeur.

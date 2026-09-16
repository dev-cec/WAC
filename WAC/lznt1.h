#pragma once

/*  lznt1.h — DÉCOMPRESSION NTFS (LZNT1).
 *
 *  POURQUOI CE MODULE EXISTE. Windows 11 active la compression NTFS sur
 *  `\Windows\System32\winevt\Logs` : les journaux d'événements y sont stockés
 *  compressés (mesuré : `System.evtx`, 1 118 208 octets pour 589 824 sur le
 *  disque, soit 1,9 pour 1). Un lecteur brut qui ignore la compression ne rend
 *  RIEN pour ces fichiers — sur une VM Windows 11, 400 des 404 journaux
 *  échouaient, et la lecture hors ligne des événements était donc inopérante
 *  sur le système d'exploitation le plus courant.
 *
 *  Ce n'est pas propre aux journaux : la compression est un attribut de
 *  répertoire que l'utilisateur ou une stratégie peut poser n'importe où, et
 *  tout artefact peut donc se trouver compressé.
 *
 *  LE FORMAT, en deux niveaux.
 *
 *  1. L'UNITÉ DE COMPRESSION, côté NTFS. L'attribut `$DATA` déclare une taille
 *     d'unité (2^n grappes, 16 en pratique). Le fichier est découpé en unités
 *     de cette taille, et chacune est indépendante :
 *       - unité dont TOUTES les grappes sont allouées : stockée telle quelle,
 *         la compression n'ayant rien gagné ;
 *       - unité entièrement creuse : des zéros ;
 *       - unité partiellement allouée : les grappes présentes contiennent la
 *         forme compressée, à détendre jusqu'à la taille de l'unité.
 *     C'est raw_hive qui traite ce niveau, seul à connaître les séquences.
 *
 *  2. LE FLUX LZNT1, traité ici. Une unité compressée est une suite de morceaux
 *     de 4096 octets détendus. Chaque morceau commence par un en-tête de
 *     2 octets : bits 0-11 la taille des données qui suivent moins un, bits
 *     12-14 une signature, bit 15 l'indicateur « compressé ». Un en-tête nul
 *     termine le flux.
 *
 *     Dans un morceau compressé, un octet de drapeaux commande les huit
 *     éléments suivants : bit à 0, un octet littéral ; bit à 1, une référence
 *     arrière de 2 octets. LA SUBTILITÉ, et le seul endroit où une
 *     implémentation se trompe : le découpage de ces 16 bits entre distance et
 *     longueur N'EST PAS FIXE — il dépend de la quantité déjà produite dans le
 *     morceau. La distance commence sur 4 bits et en gagne un chaque fois que
 *     la sortie franchit une puissance de deux, la longueur en perdant un
 *     d'autant. Un découpage figé donne un flux qui se décode sans erreur et
 *     produit des données fausses.
 *
 *  Les données viennent de la machine examinée : toutes les bornes sont
 *  vérifiées, et une sortie tronquée est signalée par un rendu partiel plutôt
 *  que par une lecture hors zone.
 *
 *  C++ portable, aucune dépendance : vérifiable hors Windows (cf. lznt1_test).
 */

#include <cstdint>
#include <cstddef>

/*! Détend un flux LZNT1.
*
*  @param compresse données compressées (une unité de compression entière)
*  @param tailleCompressee taille de ces données
*  @param sortie tampon de destination
*  @param tailleSortie capacité du tampon
*  @return nombre d'octets écrits ; 0 si l'entrée est inexploitable.
*          Un rendu inférieur à la capacité n'est pas une erreur : la dernière
*          unité d'un fichier est le plus souvent partielle.
*/
size_t Lznt1Detendre(const uint8_t* compresse, size_t tailleCompressee,
                     uint8_t* sortie, size_t tailleSortie);

#pragma once

/*  xpress.h — DÉCOMPRESSION XPRESS HUFFMAN (WOF / « Compact OS »).
 *
 *  POURQUOI CE MODULE EXISTE. Windows 10 et 11 stockent leurs binaires système
 *  compressés par WOF. Vu de l'API, un tel fichier est parfaitement ordinaire :
 *  attributs normaux, un seul flux, taille pleine — le filtre du système
 *  reconstitue tout à la volée. Vu du disque, c'est autre chose, et
 *  l'énumération des attributs $MFT le montre sans ambiguïté :
 *
 *      0x80 (sans nom)         1 372 160 octets   CREUX      <- $DATA vide
 *      0x80 WofCompressedData    667 578 octets              <- les vraies données
 *      0xC0 point de reparse          0x80000017  algorithme 2
 *
 *  Une lecture brute qui ignore cela rend un fichier de la bonne taille,
 *  entièrement à zéro. Sur une VM Windows 11, les 121 binaires de fournisseurs
 *  d'événements étaient dans ce cas : aucun message d'événement ne pouvait être
 *  reconstitué sans ouvrir les fichiers par l'API — ce que ce module évite.
 *
 *  LES ALGORITHMES DE WOF sont au nombre de quatre, désignés par le point de
 *  reparse : XPRESS sur des morceaux de 4, 8 ou 16 Kio, et LZX sur 32 Kio.
 *  Les trois premiers emploient LE MÊME codage, XPRESS Huffman, traité ici ;
 *  seule la taille des morceaux change. LZX est un format distinct, bien plus
 *  complexe, qui n'est pas implémenté : un fichier ainsi compressé est signalé
 *  comme illisible plutôt que rendu faux.
 *
 *  LE CODAGE, et ses deux subtilités.
 *
 *  Chaque morceau commence par une table de Huffman de 256 octets : 512
 *  longueurs de code sur 4 bits, une par symbole. Suit un train de bits d'où
 *  l'on décode des symboles ; sous 256 c'est un octet littéral, au-delà c'est
 *  une référence arrière dont les bits de poids fort donnent le nombre de bits
 *  de la distance et les quatre de poids faible la longueur.
 *
 *    - LE TRAIN DE BITS SE LIT PAR MOTS DE 16 BITS EN PETIT BOUTIEN, mais les
 *      bits se consomment du plus significatif au moins significatif à
 *      l'intérieur du mot. Inverser l'un ou l'autre décode un flux qui
 *      ressemble à du bruit sans jamais lever d'erreur.
 *    - LES LONGUEURS ÉTENDUES SE LISENT EN OCTETS, sur le MÊME curseur que le
 *      train de bits. Les deux lectures s'entrelacent donc, et un curseur
 *      séparé désynchronise tout le reste du morceau.
 *
 *  Les données viennent de la machine examinée : toutes les bornes sont
 *  vérifiées, et un flux incohérent rend ce qui a été produit jusque-là plutôt
 *  que de faire lire hors zone.
 *
 *  C++ portable, aucune dépendance : confronté au compresseur de Windows
 *  lui-même (cf. xpress_test).
 */

#include <cstdint>
#include <cstddef>

/*! Détend un morceau compressé en XPRESS Huffman.
*
*  @param compresse données compressées (un morceau entier, table comprise)
*  @param tailleCompressee taille de ces données
*  @param sortie tampon de destination
*  @param tailleSortie taille attendue du morceau détendu, qui borne l'écriture
*  @return nombre d'octets écrits ; 0 si l'entrée est inexploitable.
*          Un rendu inférieur à la taille attendue signale un flux tronqué.
*/
size_t XpressHuffmanDetendre(const uint8_t* compresse, size_t tailleCompressee,
                             uint8_t* sortie, size_t tailleSortie);

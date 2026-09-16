#pragma once

/*  consigne.h — CONSIGNE ET RÉPERTOIRE DE TRAVAIL.
 *
 *  LE PRINCIPE, QUI EST UNE PROCÉDURE ET NON UNE COMMODITÉ. Une pièce numérique
 *  ne s'analyse jamais sur elle-même. On en fait une copie, on scelle la copie,
 *  et tout le travail se fait sur une SECONDE copie. Si l'analyse abîme quelque
 *  chose — un outil qui écrit, une ruche rejouée, une manipulation
 *  malencontreuse — la pièce scellée reste disponible et l'opération est
 *  refaisable. Sans cette séparation, la première erreur détruit la preuve.
 *
 *  D'où deux répertoires sur le support de collecte :
 *
 *      <sortie>\consigne\   copies brutes, telles que lues du volume.
 *                           JAMAIS réouvertes en écriture après extraction.
 *                           Contient le manifeste qui les identifie.
 *      <sortie>\travail\    copies de travail. C'est là que les ruches sont
 *                           rejouées, que les journaux d'annulation sont écrits,
 *                           et c'est ce que lisent tous les collecteurs.
 *
 *  La séparation vaut pour TOUS les fichiers extraits, y compris ceux que WAC ne
 *  modifie pas — Prefetch, jumplists, .lnk, journaux d'événements. Ne dédoubler
 *  que ce qu'on modifie reviendrait à faire dépendre la procédure de ce que
 *  l'outil croit faire, alors que c'est précisément ce qu'il faut pouvoir
 *  vérifier de l'extérieur.
 *
 *  LE MANIFESTE. `consigne\MANIFESTE.json` identifie chaque pièce et la
 *  collecte. Il est scellé par `consigne\MANIFESTE.sha256`, qui porte son
 *  empreinte : un manifeste ne peut pas se hacher lui-même, et sans ce second
 *  fichier, une retouche du manifeste serait indétectable.
 *
 *  Ce qu'il contient, et pourquoi chaque champ est là :
 *
 *    pour chaque pièce
 *      - le chemin SOURCE avec sa lettre de volume, et le chemin dans la
 *        consigne : ce qui relie la copie à son origine ;
 *      - MD5, SHA-1 et SHA-256 : MD5 seul ne suffit plus (collisions depuis
 *        2008), SHA-1 non plus (2017) ; les trois ensemble ferment le débat ;
 *      - la taille extraite ET la taille annoncée par l'attribut $DATA : leur
 *        divergence signale une extraction tronquée, qu'une empreinte seule ne
 *        révélerait pas ;
 *      - le numéro d'enregistrement $MFT : il identifie le fichier sur le
 *        volume indépendamment de son nom, donc y compris si le nom a été
 *        changé pour tromper ;
 *      - les quatre horodatages NTFS du fichier SOURCE : ce sont des données
 *        d'investigation, et leur présence atteste que la lecture brute ne les
 *        a pas modifiés, la copie portant les dates du moment ;
 *      - l'horodatage de l'extraction, en UTC et en heure locale du SUSPECT ;
 *      - la méthode de collecte, et l'issue — un échec est consigné aussi,
 *        car une pièce absente du manifeste se lirait comme jamais cherchée.
 *
 *    pour la collecte
 *      - l'outil, sa version, la ligne de commande ;
 *      - l'opérateur : nom, SID, élévation ;
 *      - la machine examinée : nom, lecteur système, version de l'OS, fuseau,
 *        et l'écart avec le fuseau de la machine de collecte ;
 *      - les volumes lus : lettre, numéro de série, système de fichiers ;
 *      - le début et la fin de l'extraction ;
 *      - les décomptes, et la mention expresse qu'aucune écriture n'a eu lieu
 *        sur le système examiné.
 */

#include <windows.h>
#include <string>
#include <vector>
#include "raw_hive.h"

/*! Racine de la consigne : `<sortie>\consigne`. */
std::wstring dossierConsigne();

/*! Racine du répertoire de travail : `<sortie>\travail`.
 *  C'est la valeur de `conf.mountpoint` : les collecteurs lisent ici. */
std::wstring dossierTravail();

/*! Enregistre un relevé d'extraction au manifeste de consigne.
 *
 *  À appeler au fil des extractions, avec le relevé rendu par les fonctions de
 *  `raw_hive`. Rien n'est écrit sur le disque avant `ConsigneEcrireManifeste`.
 *
 *  @param releve pièces extraites (ou dont l'extraction a échoué)
 *  @param methode méthode de collecte, telle qu'elle sera consignée
 *         (ex. L"Lecture brute NTFS via \\\\.\\C: ($MFT, attribut $DATA)")
 */
void ConsigneAjouter(const std::vector<RawHiveExtrait>& releve,
                     const std::wstring& methode);

/*! Recopie la consigne vers le répertoire de travail, en vérifiant la copie.
 *
 *  Chaque fichier est recopié puis SA COPIE est rehachée et comparée à
 *  l'empreinte du manifeste. Sans cette vérification, une copie silencieusement
 *  tronquée — support plein, erreur d'écriture — donnerait un répertoire de
 *  travail qui ne correspond pas à la consigne, et toute l'analyse porterait sur
 *  autre chose que la pièce.
 *
 *  @param copies (optionnel) reçoit le nombre de fichiers recopiés
 *  @param octets (optionnel) reçoit le volume recopié
 *  @return ERROR_SUCCESS, S_FALSE si au moins un fichier n'a pas pu être
 *          recopié ou vérifié, ou un code d'erreur si la consigne est absente
 */
HRESULT ConsigneVersTravail(size_t* copies = nullptr, unsigned long long* octets = nullptr);

/*! Écrit `consigne\MANIFESTE.json` puis son sceau `consigne\MANIFESTE.sha256`.
 *
 *  À appeler une fois toutes les extractions terminées. Le sceau est écrit
 *  APRÈS le manifeste et porte son empreinte SHA-256.
 *
 *  @return ERROR_SUCCESS, ou E_FAIL si l'un des deux fichiers n'a pas pu
 *          être écrit — auquel cas la consigne n'est pas identifiable et il faut
 *          le savoir.
 */
HRESULT ConsigneEcrireManifeste();

/*! Nombre de pièces au manifeste, et volume total.
 *  Sert au récapitulatif de fin de collecte et au journal d'investigation. */
void ConsigneBilan(size_t* pieces, size_t* echecs, unsigned long long* octets);

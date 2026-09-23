#pragma once

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include "tools.h"



/*!
* OLE PARSER
* Documentation : https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
* Documentation : https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
* Documentation : https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
*/

/*!contient des informations sur les fichiers contenus avec un ID de secteur (SID) pour le secteur de départ d'une chaîne, etc.
*/
struct Directory {
	short int nameLength = 0; //!< longueur du nom
	unsigned int firstSectorID = 0;//!< id du premier secteur
	unsigned int userFlags = 0;//!< attributs du directory
	int directorySize = 0; //!< taille du Directory
	int previousDirectoryId = 0; //!< Id du précédent Directory
	int nextDirectoryId = 0; //!< Id du prochain Directory
	int subDirectoryId = 0; //!< Id du dubDirectory
	FILETIME createdUtc = { 0 }; //!< date de création au format UTC
	FILETIME created = { 0 }; //!< date de création
	FILETIME modifiedUtc = { 0 }; //!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification
	std::wstring name = L"";//!< nom du Directory
	std::wstring type = L"";//!< Type de directory
	std::wstring classId = L"";//!< Identifiant de classe du Directory
	std::wstring nodeColor = L"";//!< Couleur du nœud du Directory

	/*! retourne le nom du type de directory à partir d'un entier
	*/
	std::wstring getType(BYTE value);

	/*! retourne la couleur du nœud du directory à partir d'un entier
	*/
	std::wstring getNodeColor(BYTE value);

	/*! Constructeur par défaut
	*/
	Directory() {};

	/*!Constructeur
	* @param data contient un pointeur sur les données à parser
	*/
	Directory(LPBYTE data);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();
};

/*! représente une structure destfile*/
struct DestFile {
	std::wstring guidDroidVolume=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidDroidFile=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidVolume=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidFile=L"";//!< GUID containing an NTFS object identifier
	std::wstring hostname=L"";//!< Contains an ASCII string unused characters are filled with 0 - byte values
	std::wstring pathObject=L"";//!< Contains a UTF-16 little-endian string without an end-of-string character
	FILETIME lastModificationTime = { 0 };//!< date de dernière modification
	FILETIME lastModificationTimeUtc = { 0 };//!< date de dernière modification au format UTC
	short int pathObjectSize = 0; //!< taille du path object
	unsigned int entryNumber = 0;//!< numéro de l'entrée
	int pinStatus = 0;//!< Where a value of -1 (0xffffffff) indicates unpinned and a value of 0 or greater pinned.
	int size = 0;//!< taille de l'entrée

	/*! Constructeur par défaut
	*/
	DestFile() {};

	/*!Constructeur
	* @param buffer contient un pointeur sur les données à parser
	*/
	DestFile(LPBYTE buffer);

	/*! retourne le statut de pinned à partir de la valeur entière
	*/
	std::wstring getPinnedStatus();

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();
};

/*! représente une structure destfile Directory contenant un ensemble de DestFiles*/
struct DestFileDirectory {
	int formatVersion = 0;//!< format de l'entrée
	int numberOfEntries = 0;//!< nombre d'entrée
	int numberPinnedEntries = 0;//!< nombre d'entrée pinned
	std::vector<DestFile> destfiles;//!< tableau contenant les objets destfiles

	/*! Constructeur par défaut
	*/
	DestFileDirectory() {};

	/*!Constructeur
	* @param buffer contient un pointeur sur les données à parser
	*/
	DestFileDirectory(LPBYTE buffer);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();
};

/*! En-tete d'un conteneur OLE / CFB (Compound File Binary).
*
* Ces champs sont des coordonnees de navigation dans le conteneur (tailles de
* secteurs, tables d'allocation), PAS des donnees d'investigation : les traces
* exploitables d'une jumplist automatique sont dans le stream DestList et les
* shell items, que oleParser atteint grace a cet en-tete.
*
* Les fichiers analyses proviennent d'une machine suspecte : ils ne sont pas de
* confiance. Toute valeur servant a calculer un offset est donc validee ici,
* avant usage.
*/
struct oleHeader {
	bool littleIndian = false; //!< format littleindian ou Bigindian
	unsigned long long _signature = 0xe11ab1a1e011cfd0; //!< signature attendue de l'objet OLE
	unsigned long long signature = 0; //!< signature de l'objet OLE
	unsigned short versionMajor = 0; //!< version majeure (3 = secteurs 512 o, 4 = 4096 o)
	unsigned short versionMinor = 0; //!< version mineure
	int sectorSize = 0; //!< taille des secteurs, en octets (validee)
	int shortSectorSize = 0; //!< taille des petits secteurs, en octets (validee)
	int totalSATSectors = 0; //!< nombre total de secteurs dans la SAT
	int directoryStreamFirstSectorId = 0;//!< id du premier secteur contenant la liste des directory
	unsigned int minimumStandardStreamSize = 0;//!< taille minimale d'un stream
	unsigned int totalSSATSectors = 0; //!< taille totale de la SAT
	int MSATTotalSectors = 0;//!< nombre total de secteurs dans la MSAT
	int SSATFirstSectorId = 0; //!< id du premier secteur la SSAT
	int MSATFirstSectorId = 0;//!< id du premier secteur la MSAT
	std::vector<int> SATSectors; //!< tableau contenant les secteurs de la SAT
	std::vector<int> ShortSATSectors;//!< tableau contenant les secteurs de la SSAT
	/*! Constructeur par défaut
	*/
	oleHeader() {}

	/*!Constructeur
	* @param buffer contient un pointeur sur les données à parser
	* @param _bufferSize contient la taille du buffer
	*/
	oleHeader(LPBYTE buffer, size_t _bufferSize);

};

/* structure représentant le parser de OLE
*/
struct oleParser {
	oleHeader header; //!< entête du fichier ole
	Directory rootEntry;//!< entrée principal de l'objet ole
	std::vector<Directory> directories;//!< liste des directory de l'objet ole
	std::vector<std::vector<BYTE>> shortSectors; //!< liste des short sectors de l'objet ole
	std::vector<int> sat; //!< liste des secteurs de la sat
	std::vector<int> ssat;//!< liste des secteurs de la ssat
	LPBYTE buffer = NULL; //!< buffer contenant les données de l'objet ole à parser
	size_t bufferSize = 0;//!< taille du buffer


	/*! Constructeur par défaut
	*/
	oleParser() {};

	/*!Constructeur
	* @param _buffer contient un pointeur sur les données à parser
	* @param _bufferSize contient la taille du buffer
	*/
	oleParser(LPBYTE _buffer, size_t _bufferSize);

	/*! permet de retrouver un Directory dans l'objet ole à partir de son nom
	* @param name du Directory
	*/
	Directory findDirectory(std::wstring name);

	/*! Suit une chaine de secteurs dans une table d'allocation (SAT ou SSAT).
	*
	* Les indices viennent du fichier analyse, donc d'une source non fiable : cette
	* fonction valide chaque indice contre la taille de la table et detecte les
	* chaines cycliques, qui boucleraient indefiniment. Elle remplace le meme
	* parcours ecrit trois fois, chaque copie ayant ses propres trous.
	* @param table la table d'allocation a parcourir (sat ou ssat)
	* @param premier indice du premier secteur de la chaine
	* @return les indices de la chaine, premier inclus
	* @throws std::length_error si un indice est hors bornes ou la chaine cyclique
	*/
	static std::vector<int> sectorChain(const std::vector<int>& table, int first);

	std::vector<int> GetIntFromSat(int sectorNumber);

	/*! permet de parser un secteur de la sat en tableau de bytes
	* @param sectorNumber correspond au numéro du secteur à parser
	*/
	std::vector<BYTE> GetBytesFromSat(int sectorNumber);

	/*! permet de parser un secteur de la ssat en tableau de bytes
	* @param sectorNumber correspond au numéro du secteur à parser
	*/
	std::vector<BYTE> GetBytesFromSSat(int sectorNumber);

	/*! permet de parser les données d'un Directory
	* @param d correspond au directory contenant les données à récupérer
	*/
	std::vector<BYTE> Getdata(Directory d) { // Pour récupérer les Bytes correspondant d'un directory
		if (d.directorySize >= 4096) {
			log(3, L"🔈GetBytesFromSat firstSectorID");
			return GetBytesFromSat(d.firstSectorID);
		}
		else if (d.directorySize > 0) {
			log(3, L"🔈GetBytesFromSSat firstSectorID");
			return GetBytesFromSSat(d.firstSectorID);
		}
		return {};
	}

};
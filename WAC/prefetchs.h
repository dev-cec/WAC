#pragma once

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include "tools.h"
#include "quickdigest5.h"



/*structure représentant les informations liée à la MFT
*/
struct MFTInformation {
	unsigned int entryIndex = 0; //!< numéro d'entrée dans la MFT
	unsigned int sequenceNumber = 0;//!< numéro de séquence dans la MFT

	/*! constructeur par défaut
	*/
	MFTInformation() {}

	/*!Constructeur
	* @param data contient un pointeur sur les données à parser
	*/
	MFTInformation(LPBYTE data);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

struct DirStrings {
	std::wstring dir = L"";//!< original string presents in prefetch
	std::wstring fullPath = L""; //!< full path on hard drive

	Json toJson();
};

struct Filename {
	std::wstring filename = L"";//!< original string presents in prefetch
	std::wstring fullPath = L""; //!< full path on hard drive
	std::wstring md5 = L""; //!< hash md5 of the file

	Json toJson();
};

struct VolumeInfo { 
	FILETIME creationTime = { 0 }; //!< date de création
	FILETIME creationTimeUtc = { 0 };//!< date de création au format UTC
	std::wstring serialNumber = L""; //!< numéro de série du volume
	std::wstring mountPoint = L""; //!< lettre du point de montage du volume
	std::wstring deviceName = L""; //!< nom du périphérique
	std::vector<DirStrings> dirStrings; //!< tableau de strings liées au volume
	std::vector<MFTInformation> fileReferences; //!< inutile pour l'investigation numérique

	/*!Constructeur
	* @param data contient un pointeur sur les données à parser
	*/
	VolumeInfo() {}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	*/
	VolumeInfo(LPBYTE data, int indice);

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! structure représentant un prefecth windows
* documentation : https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
*/
struct Prefetch {
public:
	std::wstring path = L""; //!< chemin du prefetch dans le mountpoint
	std::wstring pathOriginal = L""; //!< chemin du prefetch sur le disque
	//HEADER
	std::wstring filename = L"";//!< nom du fichier
	std::wstring fullPath = L"";//!< full path du process
	std::wstring md5 = L"";//!< hash md5 of process
	int signature = 0; //!< signature du prefetch
	int version = 0; //!< version du prefetch
	int size = 0; //!< taille du prefetch
	// FILE INFORMATION
	FILETIME created = { 0 }; //!< date de création du fichier
	FILETIME createdUtc = { 0 }; //!< date de création du fichier au format utc
	FILETIME modified = { 0 };//!< date de modification  du fichier
	FILETIME modifiedUtc = { 0 };//!< date de modification du fichier au format utc
	FILETIME accessed = { 0 };//!< date d'accès du fichier
	FILETIME accessedUtc = { 0 };//!< date d'accès du fichier au format utc
	std::vector<FILETIME> last_runs; //!< liste des dates des dernières executions
	std::vector<FILETIME> last_runsUtc; //!< liste des dates des dernières executions au format UTC
	int run_count = 0; //!< nombre d’exécutions
	std::wstring hash_string = L"";//!< hash du chemin contenant le prefetch

	//Filename strings
	std::vector<Filename> filenames; //!< liste de nom de fichiers

	//volume information
	std::vector<VolumeInfo> volumes; //!< tableau contenant des information de volumes

	/*! constructeur
	* @param file_path en entrée contient le chemin vers le fichier prefetch à parser
	*/
	Prefetch(const std::wstring file_path);

	/* lecture du fichier prefetch
	*/
	HRESULT read();

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des objets
*/
struct Prefetchs {
	std::vector<Prefetch> prefetchs; //!< tableau contenant tout les prefetch

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
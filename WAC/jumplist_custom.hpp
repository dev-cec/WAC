#pragma once

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include "tools.h"
#include "idList.h"
#include "recent_docs.hpp"

////////////////////////////////////////////////////
// Documentation : https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
// Documentation : https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
// Documentation : https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
///////////////////////////////////////////////////

/*! Représente un objet représentant un objet Custom Destination Category
*/
struct CustomDestinationCategory {
	unsigned short int nameSize = 0; //!< taille du nom de la catégorie
	std::wstring name = L""; //!< nom de la catégorie
	unsigned int nbentries = 0; //!< nombre d'entrées dans la catégorie
	std::vector<RecentDoc> recentDocs; //!< tableau des recentDoc

	/*! Constructeur par défaut
	*/
	CustomDestinationCategory() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param buffersize en entrée contient la taille du buffer
	* @param _path est le chemin contenant les custom Destinations
	* @param _sid est le SID de l'utilisateur propriétaire du LNK

	*/
	CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid) {
		int pos = 0;
		int y = 0;

		nbentries = *reinterpret_cast<unsigned int*>(buffer + 4);
		pos += 4;
		//decoupage du fichier pour identifier tous les fichiers LNK
		for (int x = 0; x < buffersize - pos - 23; x++) {
			int s = *reinterpret_cast<int*>(buffer + pos + x); // = 0x4C = 76 pour un LNK
			if (s == 76) {
				GUID guid = *reinterpret_cast<GUID*>(buffer + pos + x + 4);
				log(3, L"🔈guid_to_wstring guid");
				std::wstring wguid = guid_to_wstring(guid);

				if (wguid.compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
					log(3, L"🔈RecentDoc");
					recentDocs.push_back(RecentDoc(buffer + pos + x, buffersize - pos - x, _path, _sid));
				}
			}
		}
	};

	virtual std::wstring to_json(int i) {
		log(3, L"🔈CusteomDestination to_json");
		std::wstring result = tab(i + 1) + L"\"recentDocs\": [ \n";
		std::vector<RecentDoc>::iterator it;
		for (it = recentDocs.begin(); it != recentDocs.end(); it++) {
			RecentDoc temp = *it;
			result += temp.to_json(i + 2);
			if (it != recentDocs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(i + 1) + L"]\n";
		return result;
	};

	void clear() {
		log(3, L"🔈CustomDestinationCategory clear");
	}
};

/*! Représente un objet représentant un objet Custom Destination
*/
struct CustomDestination {
	std::wstring Sid = L""; //!< SID de l'utilisateur propriétaire du custom Destination
	std::wstring SidName = L""; //!< nom de l'utilisateur propriétaire du custom Destination
	std::wstring application = L"";//!< nom de l'application liée au Custom Destination
	std::wstring path = L"";//!< Chemin du custom Destination dans la snapshot
	std::wstring pathOriginal = L"";//!< Chemin du custom Destination sur le disque
	unsigned int typeInt = 0;//!< type de custom Destination en entier
	std::wstring type = L"";//!< nom du type de Custom Destination
	CustomDestinationCategory* categorie = NULL; //! Pointeur vers un une Custom Destination Catégorie sur un fichier lnk est présent
	FILETIME created = { 0 }; //!< date de création du fichier
	FILETIME createdUtc = { 0 }; //!< date de création du fichier au format utc
	FILETIME modified = { 0 };//!< date de modification  du fichier
	FILETIME modifiedUtc = { 0 };//!< date de modification du fichier au format utc
	FILETIME accessed = { 0 };//!< date d'accès du fichier
	FILETIME accessedUtc = { 0 };//!< date d'accès du fichier au format utc

	/*! constructeur par défaut
	*/
	CustomDestination() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _path est le chemin contenant les Automatic Destinations
	* @param _sid est le SID de l'utilisateur propriétaire du LNK

	*/
	CustomDestination(std::filesystem::path _path, std::wstring _sid) {
		Sid = _sid;
		log(3, L"🔈getNameFromSid Sid");
		SidName = getNameFromSid(Sid);
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = _path.wstring();
		log(3, L"🔈replaceAll pathOriginal");
		pathOriginal = replaceAll(path, conf.mountpoint, L"C:");
		log(3, L"🔈replaceAll pathOriginal");
		pathOriginal = replaceAll(pathOriginal, L"\\", L"\\\\");
		log(2, L"❇️CustomDestination Path : " + pathOriginal);
		std::ifstream file(path, std::ios::binary);
		if (file.good())
		{
			file.unsetf(std::ios::skipws);
			file.seekg(0, std::ios::end);
			const size_t size = file.tellg();
			file.seekg(0, std::ios::beg);
			LPBYTE buffer = new BYTE[size];
			file.read(reinterpret_cast<CHAR*>(buffer), size);
			file.close();

			//récupération des dates
			log(3, L"🔈CreateFile hFile");
			HANDLE hFile = CreateFile(path.c_str(),  // name of the write
				GENERIC_READ,          // open for reading
				0,                      // do not share
				NULL,                   // default security
				OPEN_EXISTING,          // open existing file only
				FILE_ATTRIBUTE_NORMAL,  // normal file
				NULL);                  // no attr. template
			if (hFile != INVALID_HANDLE_VALUE) {
				FILE_BASIC_INFO fileInfo = { 0 };

				GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
				memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
				memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
				memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
				FileTimeToLocalFileTime(&createdUtc, &created);
				FileTimeToLocalFileTime(&modifiedUtc, &modified);
				FileTimeToLocalFileTime(&accessedUtc, &accessed);
			}
			else {
				log(2, L"🔥CreateFile hFile ",GetLastError());
			}
			CloseHandle(hFile);

			//conversion de l'appid contenu dans le nom de fichier en nom d'application
			std::wstring baseName = _path.stem(); // nom de fichier sans extension
			log(3, L"🔈from_appId application");
			application = from_appId(baseName);
			typeInt = *reinterpret_cast<unsigned int*>(buffer);
			switch (typeInt) {
			case 0: {
				log(2, L"🔥"+ pathOriginal + L" : Custom category", ERROR_UNSUPPORTED_TYPE);
				type = L"Custom category";
				break;
			}
			case 1: {
				log(2, L"🔥" + pathOriginal + L" : Known category",ERROR_UNSUPPORTED_TYPE );
				type = L"Known category";
				break;
			}
			case 2: {
				type = L"User tasks";
				break;
			}
			default:break;
			}

			//Control de la taille du fichier pour recherche de fichier LNK
			if ((size > 24) && (typeInt == 2)) {
				log(3, L"🔈CustomDestinationCategory");
				categorie = new CustomDestinationCategory(buffer, size, path, _sid);
			}
			else {
				log(2, L"🔥" + pathOriginal + L" : no LNK to parse",ERROR_EMPTY );
			}
			delete[] buffer;
		}
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		log(3, L"🔈CustomDestination to_json");
		std::wstring result = tab(i) + L"{ \n";
			result += tab(i + 1) + L"\"SID\":\"" + Sid + L"\", \n";
			result += tab(i + 1) + L"\"SIDName\":\"" + SidName + L"\", \n";
			result += tab(i + 1) + L"\"Application\":\"" + application + L"\", \n";
			result += tab(i + 1) + L"\"Path\":\"" + pathOriginal + L"\", \n";
			result += tab(i + 1) + L"\"Type\":\"" + type + L"\", \n";
			log(3, L"🔈time_to_wstring created");
			result += tab(i + 1) + L"\"Created\":\"" + time_to_wstring(created) + L"\", \n";
			log(3, L"🔈time_to_wstring createdUtc");
			result += tab(i + 1) + L"\"CreatedUtc\":\"" + time_to_wstring(createdUtc) + L"\", \n";
			log(3, L"🔈time_to_wstring modified");
			result += tab(i + 1) + L"\"Modified\":\"" + time_to_wstring(modified) + L"\", \n";
			log(3, L"🔈time_to_wstring modifiedUtc");
			result += tab(i + 1) + L"\"ModifiedUtc\":\"" + time_to_wstring(modifiedUtc) + L"\", \n";
			log(3, L"🔈time_to_wstring accessed");
			result += tab(i + 1) + L"\"Accessed\":\"" + time_to_wstring(accessed) + L"\", \n";
			log(3, L"🔈time_to_wstring accessedUtc");
			result += tab(i + 1) + L"\"AccessedUtc\":\"" + time_to_wstring(accessedUtc) + L"\"";
		if (categorie != NULL) {
			result += L",\n";
			result += categorie->to_json(i);
		}
		else {
			result += L"\n";
		}
		result += tab(i) + L"}";
		return result;
	};

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈CustomDestination clear");
		categorie->clear();
		delete categorie;
	}
};

/*! Représente un objet représentant un objet Jumplist contenant les Custom Destinations
*/
struct JumplistCustoms {
	std::vector<CustomDestination> customDestinations; //!< tableau contenant les objets
	

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️JumplistCustoms : ");
		log(0, L"*******************************************************************************************************************");


		std::string rep = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			log(3, L"🔈replaceAll profile");
			std::wstring profilePath = replaceAll(get<1>(profile), L"C:", L"");
			log(3, L"🔈wstring_to_string path");
			std::string path = wstring_to_string(conf.mountpoint + profilePath) + rep;
			struct stat sb;
			if (stat(path.c_str(), &sb) == 0) { // directory Exists
				for (const auto& entry : std::filesystem::directory_iterator(path)) {
					if (entry.is_regular_file() && (entry.path().extension() == ".customDestinations-ms")) {
						log(1, L"➕CustomDestination");
						customDestinations.push_back(CustomDestination(entry.path(), get<0>(profile)));
					}
				}
			}
			else {
				continue;
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈CustomDestinations to_json");
		std::wofstream myfile;
		std::wstring result = L"[\n";

		std::vector<CustomDestination>::iterator it;
		for (it = customDestinations.begin(); it != customDestinations.end(); it++) {
			result += it->to_json(1);
			if (it != customDestinations.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]\n";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir +"/jumplistCustomDestinations.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	};

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈CustomDestinations clear");
		for (CustomDestination temp : customDestinations)
			temp.clear();
	}
};
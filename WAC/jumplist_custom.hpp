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
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid,   std::vector<std::tuple<std::wstring, HRESULT>>* _errors) {
		int pos = 0;
		nbentries = bytes_to_unsigned_int(buffer + 4);
		pos += 4;
		//decoupage du fichier pour identifier tous les fichiers LNK
		int y = 0;
		for (int x = 0; x < buffersize - pos - 23; x++) {
			int s = bytes_to_int(buffer + pos + x); // = 0x4C = 76 pour un LNK
			if (s == 76) {
				GUID guid = *reinterpret_cast<GUID*>(buffer + pos + x + 4);
				std::wstring wguid = guid_to_wstring(guid);

				if (guid_to_wstring(guid).compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
					RecentDoc i = RecentDoc(buffer + pos + x, _path, _sid,  _errors);
					recentDocs.push_back(i);
				}
			}
		}
	};

	virtual std::wstring to_json(int i) {
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
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	CustomDestination(std::filesystem::path _path, std::wstring _sid,   std::vector<std::tuple<std::wstring, HRESULT>>* _errors) {
		Sid = _sid;
		SidName = getNameFromSid(Sid);
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = ansi_to_utf8(_path.wstring());
		replaceAll(path, L"\\", L"\\\\");
		pathOriginal = replaceAll(path, conf.mountpoint, L"C:");
		std::ifstream file(_path.wstring(), std::ios::binary);
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
			HANDLE hFile = CreateFile(_path.wstring().c_str(),  // name of the write
				GENERIC_READ,          // open for reading
				0,                      // do not share
				NULL,                   // default security
				OPEN_EXISTING,          // open existing file only
				FILE_ATTRIBUTE_NORMAL,  // normal file
				NULL);                  // no attr. template
			if (hFile != INVALID_HANDLE_VALUE) {
				FILE_BASIC_INFO fileInfo;
				GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
				memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
				memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
				memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
				FileTimeToLocalFileTime(&createdUtc, &created);
				FileTimeToLocalFileTime(&modifiedUtc, &modified);
				FileTimeToLocalFileTime(&accessedUtc, &accessed);
			}
			CloseHandle(hFile);

			//conversion de l'appid contenu dans le nom de fichier en nom d'application
			std::wstring::size_type const p(_path.filename().wstring().find_last_of('.')); // position du point de l'extension
			std::wstring baseName = _path.filename().wstring().substr(0, p); // nom de fichier sans extension
			application = ansi_to_utf8(from_appId(baseName));

			typeInt = bytes_to_unsigned_int(buffer);
			switch (typeInt) {
			case 0: {
				_errors->push_back({ replaceAll(path,L"\\",L"\\\\") + L" : Custom category not supported",ERROR_UNSUPPORTED_TYPE});
				type = L"Custom category";
				break;
			}
			case 1: {
				_errors->push_back({ replaceAll(path,L"\\",L"\\\\") + L" : Known category not supported",ERROR_UNSUPPORTED_TYPE });
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
				categorie = new CustomDestinationCategory(buffer, size, path, _sid,  _errors);
			}
			else {
				_errors->push_back({ replaceAll(path,L"\\",L"\\\\") + L" : Empty customdestination, no LNK to parse",ERROR_INVALID_DATA });
			}
			delete [] buffer;
		}
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		std::wstring result = tab(i) + L"{ \n"
			+ tab(i + 1) + L"\"SID\":\"" + Sid + L"\", \n"
			+ tab(i + 1) + L"\"SIDName\":\"" + SidName + L"\", \n"
			+ tab(i + 1) + L"\"Application\":\"" + application + L"\", \n"
			+ tab(i + 1) + L"\"Path\":\"" + pathOriginal + L"\", \n"
			+ tab(i + 1) + L"\"Type\":\"" + type + L"\", \n"
			+ tab(i + 1) + L"\"Created\":\"" + time_to_wstring(created) + L"\", \n"
			+ tab(i + 1) + L"\"CreatedUtc\":\"" + time_to_wstring(createdUtc) + L"\", \n"
			+ tab(i + 1) + L"\"Modified\":\"" + time_to_wstring(modified) + L"\", \n"
			+ tab(i + 1) + L"\"ModifiedUtc\":\"" + time_to_wstring(modifiedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"Accessed\":\"" + time_to_wstring(accessed) + L"\", \n"
			+ tab(i + 1) + L"\"AccessedUtc\":\"" + time_to_wstring(accessedUtc) + L"\"";
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
		delete categorie;
	}
};

/*! Représente un objet représentant un objet Jumplist contenant les Custom Destinations
*/
struct JumplistCustoms {
	std::vector<CustomDestination> customDestinations; //!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errorsCustomDestinations;//!< tableau contenant les erreurs de traitement des objets


	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		
		std::string rep = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			std::string path = wstring_to_string(conf.mountpoint + replaceAll(get<1>(profile), L"C:", L"")) + rep;
			struct stat sb;
			if (stat(path.c_str(), &sb) == 0) { // directory Exists
				for (const auto& entry : std::filesystem::directory_iterator(path)) {
					if (entry.is_regular_file() && (entry.path().extension() == ".customDestinations-ms")) {
						customDestinations.push_back(CustomDestination(entry.path(), get<0>(profile),  &errorsCustomDestinations));
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
		myfile << result;
		myfile.close();

		if(conf._debug == true && errorsCustomDestinations.size() > 0) {
			//errors
			result = L"";
			for (auto e : errorsCustomDestinations) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(conf._errorOutputDir +"/jumplistCustomDestinations_errors.txt");
			myfile << result;
			myfile.close();
		}

		return ERROR_SUCCESS;
	};

	/* liberation mémoire */
	void clear() {
		for (CustomDestination temp : customDestinations)
			temp.clear();
	}
};
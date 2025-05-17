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
#include "recent_docs.hpp"
#include "oleParser.hpp"

////////////////////////////////////////////////////
// Documentation : https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
// Documentation : https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
// Documentation : https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
///////////////////////////////////////////////////

/*! Représente un objet représentant un objet Automatic Destination
*/
struct AutomaticDestination {
	std::wstring path=L""; //!< chemin du fichier 
	std::wstring Sid = L"";//!< SID de l'utilisateur propriétaire du fichier
	std::wstring SidName = L"";//!< nom de l'utilisateur propriétaire du fichier
	std::wstring application = L"";//!< nom de l'application liée
	
	oleParser ole; //!< Parser ole utilisé pour décompresser l'objet ole
	std::vector<RecentDoc> recentDocs; //!< tableau contenant les objets Shell Entries du fichier
	FILETIME created = { 0 }; //!< date de création du fichier
	FILETIME createdUtc = { 0 }; //!< date de création du fichier au format utc
	FILETIME modified = { 0 };//!< date de modification  du fichier
	FILETIME modifiedUtc = { 0 };//!< date de modification du fichier au format utc
	FILETIME accessed = { 0 };//!< date d'accès du fichier
	FILETIME accessedUtc = { 0 };//!< date d'accès du fichier au format utc

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _path est le chemin contenant les Automatic Destinations
	* @param _sid est le SID de l'utilisateur propriétaire du LNK
	* @param _debug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	* @param _dump est issue de la ligne de commande. Si true le contenu du buffer sera ajouté au fichier de sortie au format hexadécimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	AutomaticDestination(std::filesystem::path _path, std::wstring _sid, bool _debug, bool _dump, std::vector<std::tuple<std::wstring, HRESULT>>* _errors) {
		size_t bufferSize = 0; // taille du buffer
		Sid = _sid;
		SidName = getNameFromSid(Sid);
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = ansi_to_utf8(_path.wstring());
		path = replaceAll(path, L"\\", L"\\\\");//escape \ in std::string
		std::ifstream file(_path.wstring(), std::ios::binary);
		//conversion de l'appid contenu dans le nom de fichier en nom d'application
		std::wstring::size_type const p(_path.filename().wstring().find_last_of('.'));
		std::wstring baseName = _path.filename().wstring().substr(0, p);
		application = ansi_to_utf8(from_appId(baseName));

		//ouverture du fichier
		if (file.good()) {
			file.unsetf(std::ios::skipws);
			file.seekg(0, std::ios::end);
			const size_t size = file.tellg();
			bufferSize = size;
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

			//parsing
			try {
				ole = oleParser(buffer, size);
			}
			catch (const std::exception e) {
				_errors->push_back({ L"Error parsing " + path + L" : " + string_to_wstring(e.what()),ERROR_INVALID_DATA });
				return;
			}


			// 2. Find DestList
			Directory destlistDirectory = ole.findDirectory(L"destlist");
			std::vector<BYTE> destlistDirectoryBytes;
			if (destlistDirectory.directorySize == 0) // Directory vide, rien à faire
				return;
			destlistDirectoryBytes = ole.Getdata(destlistDirectory);

			// 3. Process DestList entries
			DestFileDirectory destlistArray = DestFileDirectory(&destlistDirectoryBytes[0]);

			// TODO 4. For each DestList entry, find the corresponding Directory entry where DestListEntry.EntryNumber == DirectoryEntry.Name
			for (DestFile df : destlistArray.destfiles) {
				Directory d = ole.findDirectory(to_hex(df.entryNumber));
				if (d.name != L"") {
					// TODO 5. Once we have the Directory entry for the lnk file, we can go get the bytes that make up the lnk file.
					std::vector<BYTE> directoryBytes = ole.Getdata(d);
					RecentDoc s = RecentDoc(&directoryBytes[0], path, _sid, _debug, _dump, _errors);
					recentDocs.push_back(s);
				}
			}
			delete buffer;
		}
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		std::wstring result = L"";
		result += tab(i) + L"{ \n"
			+ tab(i + 1) + L"\"File\":\"" + path + L"\", \n"
			+ tab(i + 1) + L"\"SID\":\"" + Sid + L"\", \n"
			+ tab(i + 1) + L"\"SIDName\":\"" + SidName + L"\", \n"
			+ tab(i + 1) + L"\"Application\":\"" + application + L"\", \n"
			+ tab(i + 1) + L"\"Created\":\"" + time_to_wstring(created) + L"\", \n"
			+ tab(i + 1) + L"\"CreatedUtc\":\"" + time_to_wstring(createdUtc) + L"\", \n"
			+ tab(i + 1) + L"\"Modified\":\"" + time_to_wstring(modified) + L"\", \n"
			+ tab(i + 1) + L"\"ModifiedUtc\":\"" + time_to_wstring(modifiedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"Accessed\":\"" + time_to_wstring(accessed) + L"\", \n"
			+ tab(i + 1) + L"\"AccessedUtc\":\"" + time_to_wstring(accessedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"LNKs\" : [\n";
		std::vector<RecentDoc>::iterator it;
		for (it = recentDocs.begin(); it != recentDocs.end(); it++) {
			result += it->to_json(i + 2);
			if (it != recentDocs.end() - 1) result += L",\n";
			else result += L"\n";
		}
		result += tab(i + 1) + L"] \n";

		result += tab(i) + L"}";
		// TODO le reste
		return result;
	};
};

/*! Représente un objet représentant un objet Jumplist contenant les Automatic Destinations
*/
struct JumplistAutomatics {
	std::vector<AutomaticDestination> automaticDestinations; //!< tableau contenant les objets
	std::vector<std::tuple<std::wstring, HRESULT>> errorsAutomaticDestinations;//!< tableau contenant les erreurs de traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData(AppliConf conf) {
		_conf=conf;
		std::string rep = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
		for (std::tuple<std::wstring, std::wstring> profile : _conf.profiles) {
			std::string path = wstring_to_string(get<1>(profile)) + rep;
			struct stat sb;
			if (stat(path.c_str(), &sb) == 0) { // directory Exists
				for (const auto& entry : std::filesystem::directory_iterator(path)) {
					if (entry.is_regular_file() && (entry.path().extension() == ".automaticDestinations-ms")) {
						automaticDestinations.push_back(AutomaticDestination(entry.path(), get<0>(profile), _conf._debug, _conf._dump, &errorsAutomaticDestinations));
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

		std::vector<AutomaticDestination>::iterator it2;
		for (it2 = automaticDestinations.begin(); it2 != automaticDestinations.end(); it2++) {
			result += it2->to_json(1);
			if (it2 != automaticDestinations.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]\n";
		//enregistrement dans fichier json
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(_conf._outputDir +"/jumplistAutomaticDestinations.json");
		myfile << result;
		myfile.close();

		if(_conf._debug == true && errorsAutomaticDestinations.size() > 0) {
			//errors
			result = L"";
			for (auto e : errorsAutomaticDestinations) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir +"/jumplistAutomaticDestinations_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	};
};
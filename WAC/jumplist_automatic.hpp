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
	std::wstring path = L""; //!< chemin du fichier dans le snapshot
	std::wstring pathOriginal = L""; //!< chemin du fichier sur le disque
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

	*/
	AutomaticDestination(std::filesystem::path _path, std::wstring _sid) {
		size_t bufferSize = 0; // taille du buffer
		Sid = _sid;
		
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = _path.wstring();
		log(3, L"🔈replaceAll pathOriginal");
		pathOriginal = replaceAll(path, conf.mountpoint, L"C:");
		pathOriginal = replaceAll(pathOriginal, L"\\", L"\\\\");//escape \ in std::string
		log(2, L"❇️AutomaticDestination Path : " + pathOriginal);

		// get user name
		log(3, L"🔈getNameFromSid SidName");
		SidName = getNameFromSid(Sid);

		//conversion de l'appid contenu dans le nom de fichier en nom d'application
		std::wstring::size_type const p(_path.filename().wstring().find_last_of('.'));
		std::wstring baseName = _path.filename().wstring().substr(0, p);
		log(3, L"🔈from_appId application");
		application = from_appId(baseName);

		//ouverture du fichier
		std::ifstream file(_path.wstring(), std::ios::binary);
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
			log(3, L"🔈CreateFile hFile");
			HANDLE hFile = CreateFile(_path.wstring().c_str(),  // name of the write
				GENERIC_READ,          // open for reading
				0,                      // do not share
				NULL,                   // default security
				OPEN_EXISTING,          // open existing file only
				FILE_ATTRIBUTE_NORMAL,  // normal file
				NULL);                  // no attr. template
			if (hFile != INVALID_HANDLE_VALUE) {
				FILE_BASIC_INFO fileInfo;
				log(3, L"🔈GetFileInformationByHandleEx hFile");
				if (GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO))) {
					memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
					memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
					memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
					log(3, L"🔈FileTimeToLocalFileTime createdUtc");
					FileTimeToLocalFileTime(&createdUtc, &created);
					log(3, L"🔈FileTimeToLocalFileTime modifiedUtc");
					FileTimeToLocalFileTime(&modifiedUtc, &modified);
					log(3, L"🔈FileTimeToLocalFileTime accessedUtc");
					FileTimeToLocalFileTime(&accessedUtc, &accessed);
				}
				else {
					log(2, L"🔥GetFileInformationByHandleEx hFile", GetLastError());// show cause of failure
				}
			}
			else {
				log(2, L"🔥CreateFile hFile", GetLastError());// show cause of failure
			}
			CloseHandle(hFile);
			//parsing
			try {
				log(3, L"🔈oleParser buffer");
				ole = oleParser(buffer, size);
			}
			catch (const std::exception e) {
				log(2, L"🔥oleparser", ERROR_INVALID_DATA);// show cause of failure
				return;
			}

			// 2. Find DestList
			log(3, L"🔈ole.findDirectory destlistDirectory");
			Directory destlistDirectory = ole.findDirectory(L"destlist");
			std::vector<BYTE> destlistDirectoryBytes;
			if (destlistDirectory.directorySize <= 0) // Directory vide, rien à faire
				return;
			log(3, L"🔈ole.Getdata destlistDirectory");
			destlistDirectoryBytes = ole.Getdata(destlistDirectory);
			if (destlistDirectoryBytes.empty()) {// rien à faire
				log(2, L"🔥ole.Getdata destlistDirectory", ERROR_EMPTY);// show cause of failure
				return;
			}
			// 3. Process DestList entries
			log(3, L"🔈DestFileDirectory destlistArray");
			DestFileDirectory destlistArray = DestFileDirectory(&destlistDirectoryBytes[0]);

			// 4. For each DestList entry, find the corresponding Directory entry where DestListEntry.EntryNumber == DirectoryEntry.Name
			for (DestFile df : destlistArray.destfiles) {
				
				log(3, L"🔈ole.findDirectory d");
				Directory d = ole.findDirectory(to_hex(df.entryNumber));
				if (d.name != L"") {
					// 5. Once we have the Directory entry for the lnk file, we can go get the bytes that make up the lnk file.
					log(3, L"🔈ole.Getdata d");
					std::vector<BYTE> directoryBytes = ole.Getdata(d);
					log(3, L"🔈RecentDoc");
					recentDocs.push_back(RecentDoc(&directoryBytes[0], directoryBytes.size(), path, _sid));
				}
				else {
					log(2, L"🔥ole.findDirectory d", ERROR_EMPTY);// show cause of failure
					return;
				}
			}
			delete[] buffer;
		}
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		log(3, L"🔈AutomaticDestination to_json");
		std::wstring result = L"";
		result += tab(i) + L"{ \n";
			result+= tab(i + 1) + L"\"File\":\"" + pathOriginal + L"\", \n";
			result+= tab(i + 1) + L"\"SID\":\"" + Sid + L"\", \n";
			result+= tab(i + 1) + L"\"SIDName\":\"" + SidName + L"\", \n";
			result+= tab(i + 1) + L"\"Application\":\"" + application + L"\", \n";
			log(3, L"🔈time_to_wstring created");
			result+= tab(i + 1) + L"\"Created\":\"" + time_to_wstring(created) + L"\", \n";
			log(3, L"🔈time_to_wstring createdUtc");
			result+= tab(i + 1) + L"\"CreatedUtc\":\"" + time_to_wstring(createdUtc) + L"\", \n";
			log(3, L"🔈time_to_wstring modified");
			result+= tab(i + 1) + L"\"Modified\":\"" + time_to_wstring(modified) + L"\", \n";
			log(3, L"🔈time_to_wstring modifiedUtc");
			result+= tab(i + 1) + L"\"ModifiedUtc\":\"" + time_to_wstring(modifiedUtc) + L"\", \n";
			log(3, L"🔈time_to_wstring accessed");
			result+= tab(i + 1) + L"\"Accessed\":\"" + time_to_wstring(accessed) + L"\", \n";
			log(3, L"🔈time_to_wstring accessedUtc");
			result+= tab(i + 1) + L"\"AccessedUtc\":\"" + time_to_wstring(accessedUtc) + L"\", \n";
			result += tab(i + 1) + L"\"LNKs\" : [\n";
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

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈AutomaticDestination clear");
		for (RecentDoc temp : recentDocs)
			temp.clear();
	}
};

/*! Représente un objet représentant un objet Jumplist contenant les Automatic Destinations
*/
struct JumplistAutomatics {
	std::vector<AutomaticDestination> automaticDestinations; //!< tableau contenant les objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️JumplistAutomatics : ");
		log(0, L"*******************************************************************************************************************");

		std::string rep = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations";
		for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
			log(3, L"🔈replaceAll Profile");
			std::wstring temp = replaceAll(get<1>(profile), L"C:", L"");
			log(3, L"🔈wstring_to_string path");
			std::string path = wstring_to_string(conf.mountpoint + temp) + rep;
			struct stat sb;
			if (stat(path.c_str(), &sb) == 0) { // directory Exists
				for (const auto& entry : std::filesystem::directory_iterator(path)) {
					if (entry.is_regular_file() && (entry.path().extension() == ".automaticDestinations-ms")) {
						log(1, L"➕AutomaticDestination");
						automaticDestinations.push_back(AutomaticDestination(entry.path(), get<0>(profile)));
					}
				}
			}
			else {
				log(2, L"🔥Directory " + string_to_wstring(path), ERROR_DIRECTORY);// show cause of failure
				continue;
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈AutomaticDestinations to_json");
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
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir + "/jumplistAutomaticDestinations.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	};

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈AutomaticDestinations clear");
		for (AutomaticDestination temp : automaticDestinations)
			temp.clear();
	}
};
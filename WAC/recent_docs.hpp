#pragma once
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "trans_id.h"
#include "idList.h"



/* structure représentant un document récent
*/
struct RecentDoc {
public:
	std::wstring Sid = L""; //!< SID de l'utilisateur propriétaire de l'objet
	std::wstring path_original = L"";//!< chemin d'accès à l'objet sur le disque
	std::wstring path = L"";//!< chemin d'accès à l'objet dans le snapshot
	std::wstring target = L"";//!< chemin pour accéder à l'objet d'origine
	std::wstring description = L""; //!< description du recentDoc
	std::wstring relativePath = L"";//!< chemin relatif d'accès au fichier d'origine
	std::wstring workingDirectory = L"";//!< repertoire contenant le fichier d'origine
	std::wstring arguments = L"";//!< arguments du fichier d'origine 
	std::wstring iconLocation = L"";//!< chemin de l’icône représentatif du type de fichier si différent des icônes standards
	unsigned int fileSize = 0;//!< taille du fichier d'origine
	unsigned int iconIndex = 0;//! index de l’icône
	std::wstring commandOption = L"";//!< option d'ouverture du fichier d'origine
	GUID guid = { 0 }; //!< 
	FILETIME sourceCreated = { 0 }; //!< date de création du recentdoc
	FILETIME sourceCreatedUtc = { 0 };//!< date de création du recentdoc au format UTC
	FILETIME sourceModified = { 0 };//!< date de modification du recentdoc
	FILETIME sourceModifiedUtc = { 0 };//!< date de modification du recentdoc au format UTC
	FILETIME sourceAccessed = { 0 };//!< date d'accès du recentdoc
	FILETIME sourceAccessedUtc = { 0 };//!< date d'accès du recentdoc au format UTC
	FILETIME targetCreated = { 0 };//!< date de création du fichier d'origine
	FILETIME targetCreatedUtc = { 0 };//!< date de création du fichier d'origine au format UTC
	FILETIME targetModified = { 0 };//!< date de modification du fichier d'origine
	FILETIME targetModifiedUtc = { 0 };//!< date de modification du fichier d'origine au format UTC
	FILETIME targetAccessed = { 0 };//!< date d'accès au fichier d'origine
	FILETIME targetAccessedUtc = { 0 };//!< date d'accès au fichier d'origine au format UTC
	LinkFlags flags = { 0 };//!< attributs du recentDoc
	FileAttributes attributes = { 0 };//!< attributs du fichier d'origine
	std::wstring volumeDriveType = L""; //!< type de volume de disque
	std::wstring volumeSerial = L"";//!< numéro de série du volume
	std::wstring volumeLabel = L"";//!< label du volume
	std::wstring netName = L"";//!< nom du réseau
	std::wstring netDeviceName = L"";//!< nom du périphérique réseau
	std::wstring netProviderType = L"";//!< type de provider de réseau
	std::vector<IdList> idLists;//!< tableau contenant des Idlist 

	/*! fonction permettant de parser un fichier LNK
	* @param buffer contient les données à parser

	*/
	void parseLNK(LPBYTE buffer) {
		unsigned int header_size = *reinterpret_cast<unsigned int*>(buffer);
		guid = *reinterpret_cast<GUID*>(buffer + 4);
		log(3, L"🔈guid_to_wstring guid");
		if (guid_to_wstring(guid).compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
			flags = LinkFlags(*reinterpret_cast<unsigned int*>(buffer + 20));
			unsigned int fileAttributes = *reinterpret_cast<unsigned int*>(buffer + 24);
			log(3, L"🔈FileAttributes");
			attributes = FileAttributes(fileAttributes);
			targetCreated = *reinterpret_cast<FILETIME*>(buffer + 28);
			log(3, L"🔈time_to_wstring targetCreated");
			if (time_to_wstring(targetCreated) != L"") {
				log(3, L"🔈LocalFileTimeToFileTime targetCreatedUtc");
				LocalFileTimeToFileTime(&targetCreated, &targetCreatedUtc);
			}

			targetAccessed = *reinterpret_cast<FILETIME*>(buffer + 36);
			log(3, L"🔈time_to_wstring targetCreated");
			if (time_to_wstring(targetAccessed) != L"") {
				log(3, L"🔈LocalFileTimeToFileTime targetAccessedUtc");
				LocalFileTimeToFileTime(&targetAccessed, &targetAccessedUtc);
			}

			targetModified = *reinterpret_cast<FILETIME*>(buffer + 44);
			log(3, L"🔈time_to_wstring targetModified");
			if (time_to_wstring(targetModified) != L"") {
				log(3, L"🔈LocalFileTimeToFileTime targetModifiedUtc");
				LocalFileTimeToFileTime(&targetModified, &targetModifiedUtc);
			}
			iconIndex = *reinterpret_cast<unsigned int*>(buffer + 56);
			log(3, L"🔈showCommandOption commandOption");
			commandOption = showCommandOption(*reinterpret_cast<unsigned int*>(buffer + 60)); //
			//debug
			if (commandOption == L"UNKOWN")
				log(2, L"🔥commandOption Unknown 0x" + to_hex(*reinterpret_cast<unsigned int*>(buffer + 60)));

			//-------------------------------------------------------------------------
			// Shell item id list (starts at 76 with 2 byte length -> so we can skip):
			//-------------------------------------------------------------------------

			unsigned short int LinkTargetIDList_size = 0;
			int LinkTargetIDList_offset = header_size;
			if (flags.HasLinkTargetIDList)
			{
				LinkTargetIDList_size = *reinterpret_cast<unsigned short int*>(buffer + LinkTargetIDList_offset); //size of item id list

				int offset = LinkTargetIDList_offset + 2;
				unsigned short int item_size = 1;
				while (item_size != 0 && offset < LinkTargetIDList_size) {
					item_size = *reinterpret_cast<unsigned short int*>(buffer + offset);
					if (item_size != 0) {
						idLists.push_back(IdList(buffer + offset, 2)); // lvl 1 is object itself
					}
					offset += item_size;
				}

			}
			//-------------------------------------------------------------------------
			// File location info:
			//-------------------------------------------------------------------------
			// Follows the shell item id list and starts with 4 byte structure length,
			// followed by 4 byte offset for skipping.
			//-------------------------------------------------------------------------
			unsigned int LinkInfo_size = 0;
			int LinkInfo_offset = LinkTargetIDList_offset + 2 + LinkTargetIDList_size;

			if (flags.HasLinkInfo) {
				LinkInfo_size = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset);
				unsigned int link_flags = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + 8);
				bool VolumeIDAndLocalBasePath = link_flags & 0x1;
				bool CommonNetworkRelativeLinkAndPathSuffix = link_flags & 0x2;
				//-------------------------------------------------------------------------
				// Volume Id info:
				//-------------------------------------------------------------------------
				unsigned int volumeId_offset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + 12); //volume id offset
				if (VolumeIDAndLocalBasePath == true && volumeId_offset != 0) {
					unsigned int driveType = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + volumeId_offset + 4);
					log(3, L"🔈driveType_to_wstring volumeDriveType");
					volumeDriveType = driveType_to_wstring(driveType);
					//debug
					if (volumeDriveType == L"BAD TYPE")
						log(2, L"🔥volumeDriveType BAD TYPE 0x" + to_hex(driveType), ERROR_UNSUPPORTED_TYPE);
					unsigned int serial = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + volumeId_offset + 8);
					
					log(3, L"🔈to_hex volumeSerial");
					volumeSerial = to_hex(serial);
					transform(volumeSerial.begin(), volumeSerial.end(), volumeSerial.begin(), ::toupper);
					
					unsigned int labeloffset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + volumeId_offset + 12);
					if (labeloffset != 0x14) {
						log(3, L"🔈string_to_wstring volumeSerial");
						volumeLabel = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + volumeId_offset + labeloffset)));
					}
					else {
						unsigned int labeloffsetunicode = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + volumeId_offset + 16);
						log(3, L"🔈string_to_wstring volumeLabel");
						volumeLabel = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + volumeId_offset + labeloffset)));
					}
				}
				//-------------------------------------------------------------------------
				// Local path std::string (ending with 0x00):
				//-------------------------------------------------------------------------
				unsigned int LocalPath_offset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + 16); //local path offset from start of fileinfo
				log(3, L"🔈string_to_wstring target");
				target = string_to_wstring((char*)(buffer + LinkInfo_offset + LocalPath_offset));
				log(3, L"🔈replaceAll target");
				target = replaceAll(target, L"\\", L"\\\\"); ; // escape \ in std::string
				//-------------------------------------------------------------------------
				// Common Network Relative Link info:
				//-------------------------------------------------------------------------
				unsigned int network_offset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + 20); //common network offset
				if (CommonNetworkRelativeLinkAndPathSuffix && network_offset != 0) {
					unsigned int net_flags = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 4);
					bool ValidDevice = net_flags && 0x1;
					bool ValidNetType = net_flags && 0x2;
					unsigned int NetNameOffset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 8);
					log(3, L"🔈string_to_wstring netName");
					netName = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + network_offset + NetNameOffset)));
					log(3, L"🔈replaceAll netName");
					netName = replaceAll(netName, L"\\", L"\\\\"); // escape \ in std::string
					unsigned int DeviceNameOffset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 12);
					if (ValidDevice == true && DeviceNameOffset != 0) {
						log(3, L"🔈string_to_wstring netDeviceName");
						netDeviceName = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + network_offset + NetNameOffset)));
						log(3, L"🔈replaceAll netDeviceName");
						netDeviceName = replaceAll(netDeviceName, L"\\", L"\\\\"); // escape \ in std::string
					}
					if (ValidNetType == true) {
						log(3, L"🔈networkProvider_to_wstring netProviderType");
						netProviderType = networkProvider_to_wstring(*reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 14));
						//debug
						if (netProviderType == L"BAD NET PROVIDER")
							log(2, L"🔥netProviderType Unknown 0x" + to_hex(*reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 14)), ERROR_UNSUPPORTED_TYPE);
					}
				}
			}
			else
				target = L"";

			//-------------------------------------------------------------------------
			// String Data info:
			//-------------------------------------------------------------------------
			int stringData_offset = LinkInfo_offset + LinkInfo_size;

			unsigned short int namestring_size = 0;
			int nameString_offset = stringData_offset;
			int relativePath_offset = stringData_offset;
			if (flags.HasName == true) {
				namestring_size = *reinterpret_cast<unsigned short int*>(buffer + nameString_offset);
				description = std::wstring((wchar_t*)(buffer + stringData_offset + 2));
				log(3, L"🔈replaceAll description");
				description = replaceAll(description, L"\\", L"\\\\");//escape \ in std::string
				relativePath_offset = nameString_offset + 2 + namestring_size * 2;
			}
			else {
				description = L"";
			}

			unsigned short int relativePath_size = 0;
			int workingDirectory_offset = relativePath_offset;
			if (flags.HasRelativePath == true) {
				relativePath_size = *reinterpret_cast<unsigned short int*>(buffer + relativePath_offset);
				relativePath = std::wstring((wchar_t*)(buffer + relativePath_offset + 2));
				log(3, L"🔈replaceAll relativePath");
				relativePath = replaceAll(relativePath, L"\\", L"\\\\");//escape \ in std::string
				workingDirectory_offset = relativePath_offset + 2 + relativePath_size * 2;
			}
			else
				relativePath = L"";
			unsigned short int workingDirectory_size = 0;
			int arguments_offset = workingDirectory_offset;
			if (flags.HasWorkingDir == true) {
				workingDirectory_size = *reinterpret_cast<unsigned short int*>(buffer + workingDirectory_offset);
				workingDirectory = std::wstring((wchar_t*)(buffer + workingDirectory_offset + 2));
				log(3, L"🔈replaceAll workingDirectory");
				workingDirectory = replaceAll(workingDirectory, L"\\", L"\\\\");//escape \ in std::string
				arguments_offset = workingDirectory_offset + 2 + workingDirectory_size * 2;
			}
			else
				workingDirectory = L"";

			unsigned short int arguments_size = 0;
			int iconLocation_offset = arguments_offset;
			if (flags.HasArguments == true) {
				arguments_size = *reinterpret_cast<unsigned short int*>(buffer + workingDirectory_offset);
				arguments = std::wstring((wchar_t*)(buffer + arguments_offset + 2));
				log(3, L"🔈replaceAll arguments");
				arguments = replaceAll(arguments, L"\\", L"\\\\");//escape \ in std::string
				arguments = replaceAll(arguments, L"\"", L"\\\"");//escape " in std::string
				iconLocation_offset = arguments_offset + 2 + arguments_size * 2;
			}
			else
				arguments = L"";

			unsigned short int iconLocation_size = 0;
			if (flags.HasIconLocation == true) {
				iconLocation_size = *reinterpret_cast<unsigned short int*>(buffer + iconLocation_offset);
				iconLocation = std::wstring((wchar_t*)(buffer + iconLocation_offset + 2));
				log(3, L"🔈replaceAll iconLocation");
				iconLocation = replaceAll(iconLocation, L"\\", L"\\\\");//escape \ in std::string
			}
			else
				iconLocation = L"";
		}
	}


	/*! constructeur à partir d'un fichier
	* @param _path contient le chemin vers le fichier à parser
	* @param _sid contient le SID de l'utilisateur propriétaire du fichier

	*/
	RecentDoc(std::filesystem::path _path, std::wstring _sid)
	{
		//Parsing
		Sid = _sid;
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = _path.wstring();
		log(3, L"🔈replaceAll path");
		path = replaceAll(path, L"\\", L"\\\\");//escape \ in std::string
		log(3, L"🔈replaceAll path_original");
		path_original = replaceAll(path, conf.mountpoint, L"C:");
		log(2, L"❇️RecentDoc path " + path_original);
		target = L"";
		if (_path.extension() == ".lnk" || _path.extension() == ".LNK") {
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
				log(3, L"🔈parseLNK");
				parseLNK(buffer);
				delete[] buffer;
			}
		}
		if (_path.extension() == ".url" || _path.extension() == ".URL") {
			std::ifstream file(_path);
			std::string line;
			if (file.is_open()) {
				getline(file, line); //skip first line
				getline(file, line);
				line = line.substr(4);//suppression de URL= en début de ligne
				log(3, L"🔈decodeURIComponent line");
				line = decodeURIComponent(line);
				log(3, L"🔈string_to_wstring line");
				target = string_to_wstring(line);
				file.close();
			}
		}

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
			log(3, L"🔈GetFileInformationByHandleEx hFile");
			GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
			memcpy(&sourceCreatedUtc, &fileInfo.CreationTime, sizeof(sourceCreatedUtc));
			memcpy(&sourceModifiedUtc, &fileInfo.LastWriteTime, sizeof(sourceModifiedUtc));
			memcpy(&sourceAccessedUtc, &fileInfo.LastAccessTime, sizeof(sourceAccessedUtc));
			log(3, L"🔈FileTimeToLocalFileTime sourceCreated");
			FileTimeToLocalFileTime(&sourceCreatedUtc, &sourceCreated);
			log(3, L"🔈FileTimeToLocalFileTime sourceModified");
			FileTimeToLocalFileTime(&sourceModifiedUtc, &sourceModified);
			log(3, L"🔈FileTimeToLocalFileTime sourceAccessed");
			FileTimeToLocalFileTime(&sourceAccessedUtc, &sourceAccessed);
		}
		CloseHandle(hFile);
	}

	/*! constructeur à partir d'un buffer
	* @param buffer contient les données à parser
	* @param _path contient le chemin vers le fichier contenant le buffer
	* @param _sid contient le SID de l'utilisateur propriétaire de la donnée

	*/
	RecentDoc(LPBYTE buffer, std::wstring _path, std::wstring _sid) {
		Sid = _sid;
		path = _path;
		path_original = replaceAll(_path, conf.mountpoint, L"C:");
		log(2, L"❇️RecentDoc path " + path_original);
		target = L"";
		log(3, L"🔈parseLNK");
		parseLNK(buffer);
	}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		log(3, L"🔈RecentDoc to_json");
		std::wstring result = L"";
		result += tab(i) + L"{ \n";
		result += tab(i + 1) + L"\"Path\":\"" + path_original + L"\", \n";
		result += tab(i + 1) + L"\"Target\":\"" + target + L"\", \n";
		log(3, L"🔈time_to_wstring sourceCreated");
		result += tab(i + 1) + L"\"SourceCreated\":\"" + time_to_wstring(sourceCreated) + L"\", \n";
		log(3, L"🔈time_to_wstring sourceCreatedUtc");
		result += tab(i + 1) + L"\"SourceCreatedUtc\":\"" + time_to_wstring(sourceCreatedUtc) + L"\", \n";
		log(3, L"🔈time_to_wstring sourceModified");
		result += tab(i + 1) + L"\"SourceModified\":\"" + time_to_wstring(sourceModified) + L"\", \n";
		log(3, L"🔈time_to_wstring sourceModifiedUtc");
		result += tab(i + 1) + L"\"SourceModifiedUtc\":\"" + time_to_wstring(sourceModifiedUtc) + L"\", \n";
		log(3, L"🔈time_to_wstring sourceAccessed");
		result += tab(i + 1) + L"\"SourceAccessed\":\"" + time_to_wstring(sourceAccessed) + L"\", \n";
		log(3, L"🔈time_to_wstring sourceAccessedUtc");
		result += tab(i + 1) + L"\"SourceAccessedUtc\":\"" + time_to_wstring(sourceAccessedUtc) + L"\", \n";
		log(3, L"🔈time_to_wstring targetCreated");
		result += tab(i + 1) + L"\"TargetCreated\":\"" + time_to_wstring(targetCreated) + L"\", \n";
		log(3, L"🔈time_to_wstring targetCreatedUtc");
		result += tab(i + 1) + L"\"TargetCreatedUtc\":\"" + time_to_wstring(targetCreatedUtc) + L"\", \n";
		log(3, L"🔈time_to_wstring targetModified");
		result += tab(i + 1) + L"\"TargetModified\":\"" + time_to_wstring(targetModified) + L"\", \n";
		log(3, L"🔈time_to_wstring targetModifiedUtc");
		result += tab(i + 1) + L"\"TargetModifiedUtc\":\"" + time_to_wstring(targetModifiedUtc) + L"\", \n";
		log(3, L"🔈time_to_wstring targetAccessed");
		result += tab(i + 1) + L"\"TargetAccessed\":\"" + time_to_wstring(targetAccessed) + L"\", \n";
		log(3, L"🔈time_to_wstring targetAccessedUtc");
		result += tab(i + 1) + L"\"TargetAccessedUtc\":\"" + time_to_wstring(targetAccessedUtc) + L"\", \n";
		log(3, L"🔈to_wstring flags");
		result += tab(i + 1) + L"\"LNKFlags\":\"" + flags.to_wstring() + L"\", \n";
		log(3, L"🔈to_wstring attributes");
		result += tab(i + 1) + L"\"FileAttributes\":\"" + attributes.to_wstring() + L"\", \n"
			+ tab(i + 1) + L"\"IconIndex\":\"" + std::to_wstring(iconIndex) + L"\", \n"
			+ tab(i + 1) + L"\"CommandOption\":\"" + commandOption + L"\", \n"
			+ tab(i + 1) + L"\"Description\":\"" + description + L"\", \n"
			+ tab(i + 1) + L"\"RelativePath\":\"" + relativePath + L"\", \n"
			+ tab(i + 1) + L"\"WorkingDirectory\":\"" + workingDirectory + L"\", \n"
			+ tab(i + 1) + L"\"Arguments\":\"" + arguments + L"\", \n"
			+ tab(i + 1) + L"\"IconLocation\":\"" + iconLocation + L"\", \n"
			+ tab(i + 1) + L"\"VolumeDrive Type\":\"" + volumeDriveType + L"\", \n"
			+ tab(i + 1) + L"\"VolumeSerial\":\"" + volumeSerial + L"\", \n"
			+ tab(i + 1) + L"\"VolumeLabel\":\"" + volumeLabel + L"\", \n"
			+ tab(i + 1) + L"\"NetName\":\"" + netName + L"\", \n"
			+ tab(i + 1) + L"\"NetProviderType\":\"" + netProviderType + L"\", \n"
			+ tab(i + 1) + L"\"NetDeviceName\":\"" + netDeviceName + L"\", \n"
			+ tab(i + 1) + L"\"IdList\" : [ \n";
		std::vector<IdList>::iterator it;
		for (it = idLists.begin(); it != idLists.end(); it++) {
			result += it->to_json(i);
			if (it != idLists.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(i + 1) + L"]\n"
			+ tab(i) + L"}";
		return result;
	}

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈RecentDoc clear");
		for (IdList temp : idLists)
			temp.clear();
	}
};

/*! structure contenant l'ensemble des objets
*/
struct RecentDocs {
	std::vector<RecentDoc> recentdocs; //!< tableau contenant l'ensemble des objets

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {
		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Recent Docs : ");
		log(0, L"*******************************************************************************************************************");

		std::string reps[2] = { "\\AppData\\Roaming\\Microsoft\\Windows\\Recent","\\AppData\\Roaming\\Microsoft\\Office\\Recent" };
		for (std::string rep : reps) {
			for (std::tuple<std::wstring, std::wstring> profile : conf.profiles) {
				log(3, L"🔈replaceAll Profile");
				std::wstring temp = replaceAll(get<1>(profile), L"C:", L"");
				log(3, L"🔈wstring_to_string path");
				std::string path = wstring_to_string(conf.mountpoint + temp) + rep;
				struct stat sb;
				if (stat(path.c_str(), &sb) == 0) { // directory Exists
					for (const auto& entry : std::filesystem::directory_iterator(path)) {
						if (entry.is_regular_file() && ((entry.path().extension() == ".lnk" || entry.path().extension() == ".LNK") || (entry.path().extension() == ".url" || entry.path().extension() == ".URL"))) {
							log(1, L"➕RecentDoc");
							recentdocs.push_back(RecentDoc(entry.path(), get<0>(profile)));
						}
					}
				}
				else {
					continue;
				}
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈RecentDocs to_json");
		std::wofstream myfile;
		std::wstring result = L"[\n";

		std::vector<RecentDoc>::iterator it;
		for (it = recentdocs.begin(); it != recentdocs.end(); it++) {
			result += it->to_json(1);
			if (it != recentdocs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]\n";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir + "/recentdocs.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/*liberation mémoire */
	void clear() {
		log(3, L"🔈RecentDocs clear");
		for (RecentDoc temp : recentdocs)
			temp.clear();
	}

};
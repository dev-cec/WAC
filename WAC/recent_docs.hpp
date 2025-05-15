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
	std::wstring path = L"";//!< chemin d'accès à l'objet sur le disque
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
	* @param _debug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	* @param _dump est issue de la ligne de commande. Si true le contenu du buffer sera ajouté au fichier de sortie au format hexadécimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	void parseLNK(LPBYTE buffer, bool _debug, bool _dump, std::vector<std::tuple<std::wstring, HRESULT>>* errors) {
		unsigned int header_size = *reinterpret_cast<unsigned int*>(buffer);
		guid = *reinterpret_cast<GUID*>(buffer + 4);
		if (guid_to_wstring(guid).compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
			flags = LinkFlags(bytes_to_unsigned_int(buffer + 20));
			unsigned int fileAttributes = bytes_to_unsigned_int(buffer + 24);
			attributes = FileAttributes(fileAttributes);
			targetCreated = bytes_to_filetime(buffer + 28);
			if (time_to_wstring(targetCreated) != L"")
				LocalFileTimeToFileTime(&targetCreated, &targetCreatedUtc);

			targetAccessed = bytes_to_filetime(buffer + 36);
			if (time_to_wstring(targetAccessed) != L"")
				LocalFileTimeToFileTime(&targetAccessed, &targetAccessedUtc);

			targetModified = bytes_to_filetime(buffer + 44);
			if (time_to_wstring(targetModified) != L"")
				LocalFileTimeToFileTime(&targetModified, &targetModifiedUtc);
			iconIndex = bytes_to_unsigned_int(buffer + 56);
			commandOption = showCommandOption(bytes_to_unsigned_int(buffer + 60)); //
			//debug
			if (commandOption == L"UNKOWN" && _debug == true)
				errors->push_back({ L"commandOption Unknown 0x" + to_hex(bytes_to_unsigned_int(buffer + 60)),ERROR_UNIDENTIFIED_ERROR });

			//-------------------------------------------------------------------------
			// Shell item id list (starts at 76 with 2 byte length -> so we can skip):
			//-------------------------------------------------------------------------

			unsigned short int LinkTargetIDList_size = 0;
			int LinkTargetIDList_offset = header_size;
			if (flags.HasLinkTargetIDList)
			{
				LinkTargetIDList_size = bytes_to_unsigned_short(buffer + LinkTargetIDList_offset); //size of item id list

				int offset = LinkTargetIDList_offset + 2;
				unsigned short int item_size = 1;
				while (item_size != 0 && offset < LinkTargetIDList_size) {
					item_size = bytes_to_unsigned_short(buffer + offset);
					if (item_size != 0) {
						idLists.push_back(IdList(buffer + offset, 2, _debug, _dump, errors)); // lvl 1 is object itself
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
				LinkInfo_size = bytes_to_unsigned_int(buffer + LinkInfo_offset);
				unsigned int link_flags = bytes_to_unsigned_int(buffer + LinkInfo_offset + 8);
				bool VolumeIDAndLocalBasePath = link_flags & 0x1;
				bool CommonNetworkRelativeLinkAndPathSuffix = link_flags & 0x2;
				//-------------------------------------------------------------------------
				// Volume Id info:
				//-------------------------------------------------------------------------
				unsigned int volumeId_offset = bytes_to_unsigned_int(buffer + LinkInfo_offset + 12); //volume id offset
				if (VolumeIDAndLocalBasePath == true && volumeId_offset != 0) {
					unsigned int driveType = bytes_to_unsigned_int(buffer + LinkInfo_offset + volumeId_offset + 4);
					volumeDriveType = driveType_to_wstring(driveType);
					//debug
					if (volumeDriveType == L"BAD TYPE" && _debug == true)
						errors->push_back({ L"volumeDriveType BAD TYPE 0x" + to_hex(driveType),ERROR_UNIDENTIFIED_ERROR });
					unsigned int serial = bytes_to_unsigned_int(buffer + LinkInfo_offset + volumeId_offset + 8);
					std::stringstream ss;
					ss << std::hex << serial;
					volumeSerial = string_to_wstring((ss.str()));
					transform(volumeSerial.begin(), volumeSerial.end(), volumeSerial.begin(), ::toupper);
					unsigned int labeloffset = bytes_to_unsigned_int(buffer + LinkInfo_offset + volumeId_offset + 12);
					if (labeloffset != 0x14) {
						volumeLabel = string_to_wstring(ansi_to_utf8(std::string((char*)(buffer + LinkInfo_offset + volumeId_offset + labeloffset))));
					}
					else {
						unsigned int labeloffsetunicode = bytes_to_unsigned_int(buffer + LinkInfo_offset + volumeId_offset + 16);
						volumeLabel = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + volumeId_offset + labeloffset)));
					}
				}
				//-------------------------------------------------------------------------
				// Local path std::string (ending with 0x00):
				//-------------------------------------------------------------------------
				unsigned int LocalPath_offset = bytes_to_unsigned_int(buffer + LinkInfo_offset + 16); //local path offset from start of fileinfo

				target = string_to_wstring(ansi_to_utf8((char*)(buffer + LinkInfo_offset + LocalPath_offset)));
				target = replaceAll(target, L"\\", L"\\\\"); ; // escape \ in std::string
				//-------------------------------------------------------------------------
				// Common Network Relative Link info:
				//-------------------------------------------------------------------------
				unsigned int network_offset = bytes_to_unsigned_int(buffer + LinkInfo_offset + 20); //common network offset
				if (CommonNetworkRelativeLinkAndPathSuffix && network_offset != 0) {
					unsigned int net_flags = bytes_to_unsigned_int(buffer + LinkInfo_offset + network_offset + 4);
					bool ValidDevice = net_flags && 0x1;
					bool ValidNetType = net_flags && 0x2;
					unsigned int NetNameOffset = bytes_to_unsigned_int(buffer + LinkInfo_offset + network_offset + 8);
					netName = string_to_wstring(ansi_to_utf8(std::string((char*)(buffer + LinkInfo_offset + network_offset + NetNameOffset))));
					netName = replaceAll(netName, L"\\", L"\\\\"); // escape \ in std::string
					unsigned int DeviceNameOffset = bytes_to_unsigned_int(buffer + LinkInfo_offset + network_offset + 12);
					if (ValidDevice == true && DeviceNameOffset != 0) {
						netDeviceName = string_to_wstring(ansi_to_utf8(std::string((char*)(buffer + LinkInfo_offset + network_offset + NetNameOffset))));
						netDeviceName = replaceAll(netDeviceName, L"\\", L"\\\\"); // escape \ in std::string
					}
					if (ValidNetType == true) {
						netProviderType = networkProvider_to_wstring(bytes_to_unsigned_int(buffer + LinkInfo_offset + network_offset + 14));
						//debug
						if (netProviderType == L"BAD NET PROVIDER" && _debug == true)
							errors->push_back({ L"netProviderType Unknown 0x" + to_hex(bytes_to_unsigned_int(buffer + LinkInfo_offset + network_offset + 14)),ERROR_UNIDENTIFIED_ERROR });
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
				namestring_size = bytes_to_unsigned_short(buffer + nameString_offset);
				description = ansi_to_utf8(std::wstring((wchar_t*)(buffer + stringData_offset + 2), (wchar_t*)(buffer + stringData_offset + 2 + namestring_size * 2)));
				description = replaceAll(description, L"\\", L"\\\\");//escape \ in std::string
				relativePath_offset = nameString_offset + 2 + namestring_size * 2;
			}
			else {
				description = L"";
			}

			unsigned short int relativePath_size = 0;
			int workingDirectory_offset = relativePath_offset;
			if (flags.HasRelativePath == true) {
				relativePath_size = bytes_to_unsigned_short(buffer + relativePath_offset);
				relativePath = ansi_to_utf8(std::wstring((wchar_t*)(buffer + relativePath_offset + 2), (wchar_t*)(buffer + relativePath_offset + 2 + relativePath_size * 2)));
				relativePath = replaceAll(relativePath, L"\\", L"\\\\");//escape \ in std::string
				workingDirectory_offset = relativePath_offset + 2 + relativePath_size * 2;
			}
			else
				relativePath = L"";
			unsigned short int workingDirectory_size = 0;
			int arguments_offset = workingDirectory_offset;
			if (flags.HasWorkingDir == true) {
				workingDirectory_size = bytes_to_unsigned_short(buffer + workingDirectory_offset);
				workingDirectory = ansi_to_utf8(std::wstring((wchar_t*)(buffer + workingDirectory_offset + 2), (wchar_t*)(buffer + workingDirectory_offset + 2 + workingDirectory_size * 2)));
				workingDirectory = replaceAll(workingDirectory, L"\\", L"\\\\");//escape \ in std::string
				arguments_offset = workingDirectory_offset + 2 + workingDirectory_size * 2;
			}
			else
				workingDirectory = L"";

			unsigned short int arguments_size = 0;
			int iconLocation_offset = arguments_offset;
			if (flags.HasArguments == true) {
				arguments_size = bytes_to_unsigned_short(buffer + workingDirectory_offset);
				arguments = ansi_to_utf8(std::wstring((wchar_t*)(buffer + arguments_offset + 2), (wchar_t*)(buffer + arguments_offset + 2 + arguments_size * 2)));
				arguments = replaceAll(arguments, L"\\", L"\\\\");//escape \ in std::string
				arguments = replaceAll(arguments, L"\"", L"\\\"");//escape " in std::string
				iconLocation_offset = arguments_offset + 2 + arguments_size * 2;
			}
			else
				arguments = L"";

			unsigned short int iconLocation_size = 0;
			if (flags.HasIconLocation == true) {
				iconLocation_size = bytes_to_unsigned_short(buffer + iconLocation_offset);
				iconLocation = ansi_to_utf8(std::wstring((wchar_t*)(buffer + iconLocation_offset + 2), (wchar_t*)(buffer + iconLocation_offset + 2 + iconLocation_size * 2)));
				iconLocation = replaceAll(iconLocation, L"\\", L"\\\\");//escape \ in std::string
			}
			else
				iconLocation = L"";
		}
	}


	/*! constructeur à partir d'un fichier
	* @param _path contient le chemin vers le fichier à parser
	* @param _sid contient le SID de l'utilisateur propriétaire du fichier
	* @param _debug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	* @param _dump est issue de la ligne de commande. Si true le contenu du buffer sera ajouté au fichier de sortie au format hexadécimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	RecentDoc(std::filesystem::path _path, std::wstring _sid, bool _debug, bool _dump, std::vector<std::tuple<std::wstring, HRESULT>>* errors)
	{
		//Parsing
		Sid = _sid;
		//path retourne un codage ANSI mais on veut de l'UTF8
		path = ansi_to_utf8(_path.wstring());
		path = replaceAll(path, L"\\", L"\\\\");//escape \ in std::string
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

				parseLNK(buffer, _debug, _dump, errors);

			}
		}
		if (_path.extension() == ".url" || _path.extension() == ".URL") {
			std::ifstream file(_path);
			std::string line;
			if (file.is_open()) {
				getline(file, line); //skip first line
				getline(file, line);
				line = ansi_to_utf8(line); //ensure utf8
				line = line.substr(4);//suppression de URL= en début de ligne
				line = decodeURIComponent(line);
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
			GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
			memcpy(&sourceCreatedUtc, &fileInfo.CreationTime, sizeof(sourceCreatedUtc));
			memcpy(&sourceModifiedUtc, &fileInfo.LastWriteTime, sizeof(sourceModifiedUtc));
			memcpy(&sourceAccessedUtc, &fileInfo.LastAccessTime, sizeof(sourceAccessedUtc));
			FileTimeToLocalFileTime(&sourceCreatedUtc, &sourceCreated);
			FileTimeToLocalFileTime(&sourceModifiedUtc, &sourceModified);
			FileTimeToLocalFileTime(&sourceAccessedUtc, &sourceAccessed);
		}
	}

	/*! constructeur à partir d'un buffer
	* @param buffer contient les données à parser
	* @param _path contient le chemin vers le fichier contenant le buffer
	* @param _sid contient le SID de l'utilisateur propriétaire de la donnée
	* @param _debug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	* @param _dump est issue de la ligne de commande. Si true le contenu du buffer sera ajouté au fichier de sortie au format hexadécimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	RecentDoc(LPBYTE buffer, std::wstring _path, std::wstring _sid, bool _debug, bool _dump, std::vector<std::tuple<std::wstring,HRESULT>>* _errors) {
		Sid = _sid;
		path = _path;
		target = L"";
		parseLNK(buffer, _debug, _dump, _errors);
	}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		std::wstring result = L"";
		result += tab(i) + L"{ \n"
			+ tab(i + 1) + L"\"Path\":\"" + replaceAll(path, L"\\", L"\\\\") + L"\", \n"
			+ tab(i + 1) + L"\"Target\":\"" + target + L"\", \n"
			+ tab(i + 1) + L"\"SourceCreated\":\"" + time_to_wstring(sourceCreated) + L"\", \n"
			+ tab(i + 1) + L"\"SourceCreatedUtc\":\"" + time_to_wstring(sourceCreatedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"SourceModified\":\"" + time_to_wstring(sourceModified) + L"\", \n"
			+ tab(i + 1) + L"\"SourceModifiedUtc\":\"" + time_to_wstring(sourceModifiedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"SourceAccessed\":\"" + time_to_wstring(sourceAccessed) + L"\", \n"
			+ tab(i + 1) + L"\"SourceAccessedUtc\":\"" + time_to_wstring(sourceAccessedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"TargetCreated\":\"" + time_to_wstring(targetCreated) + L"\", \n"
			+ tab(i + 1) + L"\"TargetCreatedUtc\":\"" + time_to_wstring(targetCreatedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"TargetModified\":\"" + time_to_wstring(targetModified) + L"\", \n"
			+ tab(i + 1) + L"\"TargetModifiedUtc\":\"" + time_to_wstring(targetModifiedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"TargetAccessed\":\"" + time_to_wstring(targetAccessed) + L"\", \n"
			+ tab(i + 1) + L"\"TargetAccessedUtc\":\"" + time_to_wstring(targetAccessedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"LNKFlags\":\"" + flags.to_wstring() + L"\", \n"
			+ tab(i + 1) + L"\"FileAttributes\":\"" + attributes.to_wstring() + L"\", \n"
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
};

/*! structure contenant l'ensemble des objets
*/
struct RecentDocs {
	std::vector<RecentDoc> recentdocs; //!< tableau contenant l'ensemble des objets
	std::vector<std::tuple<std::wstring, HRESULT>> errors;//!< tableau contenant les erreurs remontées lors du traitement des objets
	AppliConf _conf = {0};//! contient les paramètres de l'application issue des paramètres de la ligne de commande

	/*! Fonction permettant de parser les objets
	* @param userprofiles contient les profiles des utilisateurs de la machine
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera généré
	* @param pdump est issu de la ligne de commande. Si true alors le fichier de sortie contiendra le dump hexa de l'objet
	*/
	HRESULT getData(AppliConf conf) {
		_conf=conf;
		std::string reps[2] = { "\\AppData\\Roaming\\Microsoft\\Windows\\Recent","\\AppData\\Roaming\\Microsoft\\Office\\Recent" };
		for (std::string rep : reps) {
			for (std::tuple<std::wstring, std::wstring> profile : _conf.profiles) {
				std::string path = wstring_to_string(get<1>(profile)) + rep;
				struct stat sb;
				if (stat(path.c_str(), &sb) == 0) { // directory Exists
					for (const auto& entry : std::filesystem::directory_iterator(path)) {
						if (entry.is_regular_file() && ((entry.path().extension() == ".lnk" || entry.path().extension() == ".LNK") || (entry.path().extension() == ".url" || entry.path().extension() == ".URL"))) {
							recentdocs.push_back(RecentDoc(entry.path(), get<0>(profile), _conf._debug, _conf._dump, &errors));
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
		std::filesystem::create_directory(_conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(_conf._outputDir +"/recentdocs.json");
		myfile << result;
		myfile.close();

		if(_conf._debug == true && errors.size() > 0) {
			//errors
			result = L"";
			for (auto e : errors) {
				result += L"" + std::get<0>(e) + L" : " + getErrorWstring(get<1>(e)) + L"\n";
			}
			std::filesystem::create_directory(_conf._errorOutputDir); //crée le repertoire, pas d'erreur s'il existe déjà
			myfile.open(_conf._errorOutputDir +"/recentdocs_errors.txt");
			myfile << result;
			myfile.close();
		}
		return ERROR_SUCCESS;
	}

};
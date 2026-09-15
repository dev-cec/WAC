#include "recent_docs.h"

namespace {

/*! Lit un champ StringData d'un raccourci .lnk.
*
*  FORMAT (MS-SHLLINK). Chaque champ est un compteur de CARACTÈRES sur deux
*  octets, suivi des caractères eux-mêmes — **sans terminateur nul**. Le code
*  d'origine ignorait ce compteur et construisait la chaîne jusqu'au premier
*  zéro rencontré : correct par accident quand Windows en écrit un, mais sinon la
*  chaîne débordait sur le champ suivant, et sur un fichier tronqué ou forgé la
*  lecture sortait du tampon.
*
*  @param buffer début du fichier .lnk en mémoire
*  @param taille taille totale du tampon
*  @param offset position du champ
*  @param suivant reçoit la position du champ suivant
*  @return la chaîne lue, ou "" si le champ est incohérent
*/
std::wstring lireStringData(LPBYTE buffer, size_t taille, size_t offset, size_t* suivant) {
	*suivant = offset;
	if (offset + 2 > taille) {
		log(2, L"🔥StringData hors tampon a l'offset " + std::to_wstring(offset));
		return L"";
	}
	const unsigned short nbCar = *reinterpret_cast<unsigned short*>(buffer + offset);
	const size_t octets = (size_t)nbCar * sizeof(wchar_t);
	if (offset + 2 + octets > taille) {
		log(2, L"🔥StringData annonce " + std::to_wstring(nbCar)
		     + L" caracteres, au-dela du tampon");
		return L"";
	}
	*suivant = offset + 2 + octets;
	return std::wstring((wchar_t*)(buffer + offset + 2), nbCar);
}

} // namespace

void RecentDoc::parseLNK(LPBYTE buffer, size_t taille) {
	unsigned int header_size = *reinterpret_cast<unsigned int*>(buffer);
	guid = *reinterpret_cast<GUID*>(buffer + 4);
	log(3, L"🔈guid_to_wstring guid");
	if (guid_to_wstring(guid).compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
		flags = LinkFlags(*reinterpret_cast<unsigned int*>(buffer + 20));
		unsigned int fileAttributes = *reinterpret_cast<unsigned int*>(buffer + 24);
		log(3, L"🔈FileAttributes");
		attributes = FileAttributes(fileAttributes);
		/* CORRECTION (double decalage, meme defaut que les dates FAT en miroir).
		   Dans l'en-tete d'un fichier .lnk, CreationTime / LastAccessTime /
		   LastWriteTime de la cible sont en UTC (MS-SHLLINK 2.1). Le code les
		   affectait aux champs LOCAUX puis appelait LocalFileTimeToFileTime :
		   la cle locale portait donc de l'UTC non converti, et la cle *Utc de
		   l'UTC decale une fois de trop.
		   Le sens correct : la valeur native est UTC, on en derive le local.
		   Le test « si la date formatee est non vide » qui encadrait la
		   conversion est supprime : formater une date pour savoir si elle est
		   nulle est inutile, et convertir une date nulle est sans effet. */
		targetCreatedUtc = *reinterpret_cast<FILETIME*>(buffer + 28);
		log(3, L"🔈utcVersLocalSuspect targetCreated");
		utcVersLocalSuspect(targetCreatedUtc, &targetCreated);

		targetAccessedUtc = *reinterpret_cast<FILETIME*>(buffer + 36);
		log(3, L"🔈utcVersLocalSuspect targetAccessed");
		utcVersLocalSuspect(targetAccessedUtc, &targetAccessed);

		targetModifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 44);
		log(3, L"🔈utcVersLocalSuspect targetModified");
		utcVersLocalSuspect(targetModifiedUtc, &targetModified);
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
			std::string targetPath((char*)(buffer + LinkInfo_offset + LocalPath_offset));
			log(3, L"🔈string_to_wstring target");
			target = string_to_wstring(targetPath);
			// Valeur BRUTE : l'echappement est centralise dans json.h.
			if (conf.md5) {
				log(3, L"🔈fileToHash md5Target " + string_to_wstring(targetPath));
				md5Target = QuickDigest5::fileToHash((char*)(buffer + LinkInfo_offset + LocalPath_offset));
			}
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
				unsigned int DeviceNameOffset = *reinterpret_cast<unsigned int*>(buffer + LinkInfo_offset + network_offset + 12);
				if (ValidDevice == true && DeviceNameOffset != 0) {
					log(3, L"🔈string_to_wstring netDeviceName");
					netDeviceName = string_to_wstring(std::string((char*)(buffer + LinkInfo_offset + network_offset + NetNameOffset)));
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

		/* Les cinq champs StringData se suivent, chacun donnant la position du
		   suivant par sa longueur. Un seul décalage faux décale donc tout ce qui
		   suit : c'est exactement ce qui se produisait ici, `arguments_size`
		   étant lu à l'offset du RÉPERTOIRE DE TRAVAIL au lieu du sien. Le
		   champ `iconLocation`, calculé à partir de cette taille, était donc lu
		   au mauvais endroit. Valeurs BRUTES : l'echappement est centralise
		   dans json.h. */
		size_t suivant = (size_t)stringData_offset;
		description      = flags.HasName         ? lireStringData(buffer, taille, suivant, &suivant) : L"";
		relativePath     = flags.HasRelativePath ? lireStringData(buffer, taille, suivant, &suivant) : L"";
		workingDirectory = flags.HasWorkingDir   ? lireStringData(buffer, taille, suivant, &suivant) : L"";
		arguments        = flags.HasArguments    ? lireStringData(buffer, taille, suivant, &suivant) : L"";
		iconLocation     = flags.HasIconLocation ? lireStringData(buffer, taille, suivant, &suivant) : L"";
	}
}

RecentDoc::RecentDoc(std::filesystem::path _path, std::wstring _sid) {
	//Parsing
	Sid = _sid;
	//path retourne un codage ANSI mais on veut de l'UTF8
	path = _path.wstring();
	log(3, L"🔈replaceAll path_original");
	path_original = cheminOriginal(path);
	log(2, L"❇️RecentDoc path " + path_original);
	target = L"";
	if (_path.extension() == ".lnk" || _path.extension() == ".LNK") {
		std::ifstream file(_path, std::ios::binary);
		if (file.good())
		{
			file.unsetf(std::ios::skipws);
			file.seekg(0, std::ios::end);
			const size_t size = file.tellg();
			file.seekg(0, std::ios::beg);

			LPBYTE buffer = new BYTE[size];
			file.read(reinterpret_cast<CHAR*>(buffer), size);
			file.close();
			if (conf.md5) {
				log(3, L"🔈fileToHash md5Source " + _path.wstring());
				md5Source = QuickDigest5::fileToHash(_path.string());
			}
			log(3, L"🔈parseLNK");
			parseLNK(buffer, size);
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
		log(3, L"🔈utcVersLocalSuspect sourceCreated");
		utcVersLocalSuspect(sourceCreatedUtc, &sourceCreated);
		log(3, L"🔈utcVersLocalSuspect sourceModified");
		utcVersLocalSuspect(sourceModifiedUtc, &sourceModified);
		log(3, L"🔈utcVersLocalSuspect sourceAccessed");
		utcVersLocalSuspect(sourceAccessedUtc, &sourceAccessed);
	}
	CloseHandle(hFile);
}

RecentDoc::RecentDoc(LPBYTE buffer, size_t size, std::wstring _path, std::wstring _sid) {
	Sid = _sid;
	path = _path;

	path_original = cheminOriginal(path);
	log(2, L"❇️RecentDoc path " + path_original);
	if (conf.md5) {
		log(3, L"🔈fileToHash md5Source " + _path);
		md5Source = QuickDigest5::fileToHash(wstring_to_string(_path));
	}
	target = L"";
	log(3, L"🔈parseLNK");
	parseLNK(buffer, size);
}

Json RecentDoc::toJson() {
	log(3, L"🔈RecentDoc toJson");
	Json o = Json::obj();
	o.add(L"Path",              Json::str(path_original));
	if (!md5Source.empty()) o.add(L"Md5Source", Json::str(md5Source));
	o.add(L"Target",            Json::str(target));
	if (!md5Target.empty()) o.add(L"Md5Target", Json::str(md5Target));
	o.add(L"SourceCreated",     Json::str(timeToIso8601Local(sourceCreated)));
	o.add(L"SourceCreatedUtc",  Json::str(timeToIso8601Utc(sourceCreatedUtc)));
	o.add(L"SourceModified",    Json::str(timeToIso8601Local(sourceModified)));
	o.add(L"SourceModifiedUtc", Json::str(timeToIso8601Utc(sourceModifiedUtc)));
	o.add(L"SourceAccessed",    Json::str(timeToIso8601Local(sourceAccessed)));
	o.add(L"SourceAccessedUtc", Json::str(timeToIso8601Utc(sourceAccessedUtc)));
	o.add(L"TargetCreated",     Json::str(timeToIso8601Local(targetCreated)));
	o.add(L"TargetCreatedUtc",  Json::str(timeToIso8601Utc(targetCreatedUtc)));
	o.add(L"TargetModified",    Json::str(timeToIso8601Local(targetModified)));
	o.add(L"TargetModifiedUtc", Json::str(timeToIso8601Utc(targetModifiedUtc)));
	o.add(L"TargetAccessed",    Json::str(timeToIso8601Local(targetAccessed)));
	o.add(L"TargetAccessedUtc", Json::str(timeToIso8601Utc(targetAccessedUtc)));
	o.add(L"LNKFlags",          Json::str(flags.to_wstring()));
	o.add(L"FileAttributes",    Json::str(attributes.to_wstring()));
	o.add(L"IconIndex",         Json::num((long long)iconIndex));   // nombre
	o.add(L"CommandOption",     Json::str(commandOption));
	o.add(L"Description",       Json::str(description));
	o.add(L"RelativePath",      Json::str(relativePath));
	o.add(L"WorkingDirectory",  Json::str(workingDirectory));
	o.add(L"Arguments",         Json::str(arguments));
	o.add(L"IconLocation",      Json::str(iconLocation));
	o.add(L"VolumeDrive Type",  Json::str(volumeDriveType));
	o.add(L"VolumeSerial",      Json::str(volumeSerial));
	o.add(L"VolumeLabel",       Json::str(volumeLabel));
	o.add(L"NetName",           Json::str(netName));
	o.add(L"NetProviderType",   Json::str(netProviderType));
	o.add(L"NetDeviceName",     Json::str(netDeviceName));
	Json ids = Json::arr();
	for (IdList& id : idLists) ids.push(id.toJson());
	o.add(L"IdList", std::move(ids));
	return o;
}

void RecentDoc::clear() {
	log(3, L"🔈RecentDoc clear");
	idLists.clear();   // detruit les elements -> libere reellement
}

HRESULT RecentDocs::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Recent Docs : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring reps[2] = { L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent", L"\\AppData\\Roaming\\Microsoft\\Office\\Recent" };
	for (const std::wstring& rep : reps) {
		for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
			// cheminExtrait() gere le cas d'un profil situe sur un autre volume
			// que Windows, que replaceAll(conf.systemDrive) laissait absolu.
			const std::filesystem::path repertoire =
				cheminExtrait(std::get<1>(profile)) + rep;
			const std::vector<std::filesystem::path> fichiers =
				listFilesByExtension(repertoire, { L".lnk", L".url" });
			size_t iFichier = 0;
			for (const std::filesystem::path& fichier : fichiers) {
				log(1, L"➕RecentDoc");
				printProgress(L"RecentDoc " + fichier.filename().wstring(),
				              ++iFichier, fichiers.size(), L"lnk");
				recentdocs.push_back(RecentDoc(fichier, std::get<0>(profile)));
			}
		}
	}
	return ERROR_SUCCESS;
}

HRESULT RecentDocs::toJson() {
	log(3, L"🔈RecentDocs toJson");
	Json arr = Json::arr();
	for (RecentDoc& r : recentdocs) arr.push(r.toJson());
	return writeJsonFile("recentdocs.json", arr);
}

void RecentDocs::clear() {
	log(3, L"🔈RecentDocs clear");
	recentdocs.clear();   // detruit les elements -> libere reellement
}

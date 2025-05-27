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
#include <sys/stat.h>
#include "tools.h"
#include "quickdigest5.hpp"



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
	MFTInformation(LPBYTE data)
	{
		sequenceNumber = *reinterpret_cast<unsigned int*>(data + 6);
		unsigned int entryIndex1 = *reinterpret_cast<unsigned int*>(data);
		unsigned short int entryIndex2 = *reinterpret_cast<unsigned short int*>(data + 4);
		if (entryIndex2 == 0)
		{
			entryIndex = entryIndex1;
		}
		else
		{
			entryIndex2 *= (unsigned short)16777216; //2^24
			entryIndex = entryIndex1 + entryIndex2;
		}
		if (sequenceNumber == 0)
		{
			sequenceNumber = NULL;
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		log(3, L"🔈MFTInformation to_json");
		std::wstring result = tab(5) + L"{\n"
			+ tab(6) + L"\"EntryIndex\":" + std::to_wstring(entryIndex) + L",\n"
			+ tab(6) + L"\"SequenceNumber\":" + std::to_wstring(sequenceNumber) + L"\n"
			+ tab(5) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈MFTInformation clear");
	}
};

struct DirStrings {
	std::wstring dir = L"";//!< original string presents in prefetch
	std::wstring fullPath = L""; //!< full path on hard drive

	std::wstring to_json(int niveau) {
		return tab(niveau) + L"{\n"
			+ tab(niveau + 1) + L"\"Dir\" : \"" + dir + L"\",\n"
			+ tab(niveau + 1) + L"\"FullPath\" : \"" + fullPath + L"\"\n"
			+ tab(niveau) + L"}";
	}
};

struct Filename {
	std::wstring filename = L"";//!< original string presents in prefetch
	std::wstring fullPath = L""; //!< full path on hard drive
	std::wstring md5 = L""; //!< hash md5 of the file

	std::wstring to_json(int niveau) {
		return tab(niveau) + L"{\n"
			+ tab(niveau + 1) + L"\"Filename\" : \"" + filename + L"\",\n"
			+ tab(niveau + 1) + L"\"FullPath\" : \"" + fullPath + L"\",\n"
			+ tab(niveau + 1) + L"\"Md5\" : \"" + md5 + L"\"\n"
			+ tab(niveau) + L"}";
	}
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
	VolumeInfo(LPBYTE data, int indice) {
		LPBYTE indVolume = data + indice * 96;
		unsigned int offset = *reinterpret_cast<unsigned int*>(indVolume);
		unsigned int numChar = *reinterpret_cast<unsigned int*>(indVolume + 4);
		creationTimeUtc = *reinterpret_cast<FILETIME*>(indVolume + 8);
		log(3, L"🔈FileTimeToLocalFileTime creationTime");
		FileTimeToLocalFileTime(&creationTimeUtc, &creationTime);
		deviceName = std::wstring((wchar_t*)(data + offset)).data();
		log(3, L"🔈replaceAll deviceName");
		deviceName = replaceAll(deviceName, L"\\", L"\\\\");//on échappe les \ dans le path
		//récupération du serialnumber en std::hexa
		std::wostringstream temp;
		temp << std::hex << indVolume[19] << indVolume[18] << indVolume[17] << indVolume[16]; // serialnumber in std::hexa little indian
		serialNumber = temp.str();
		mountPoint = getVolumeLetter(serialNumber);
		int dirsOffset = *reinterpret_cast<int*>(indVolume + 28);
		int nbDirs = *reinterpret_cast<int*>(indVolume + 32);
		size_t pos = 1;
		for (int k = 0; k < nbDirs; k++) {
			std::wstring temp = std::wstring((wchar_t*)(data + dirsOffset) + pos).data();
			pos += temp.size() + 2;//+2 pour \x0000
			DirStrings d;
			d.dir = temp;
			d.dir = replaceAll(d.dir, L"\\", L"\\\\");
			d.fullPath = replaceAll(d.dir, deviceName, mountPoint);
			dirStrings.push_back(d);
		}

		int fileRefOffset = *reinterpret_cast<int*>(indVolume + 20);
		int fileRefSize = *reinterpret_cast<int*>(indVolume + 24);
		LPBYTE fileRefsIndex = indVolume + fileRefOffset;
		int fileRefVer = *reinterpret_cast<int*>(fileRefsIndex);
		int numFileRefs = *reinterpret_cast<int*>(fileRefsIndex + 4);
		if (fileRefVer == 3) {
			for (int k = 0; k < numFileRefs; k++) {
				log(3, L"🔈MFTInformation");
				fileReferences.push_back(MFTInformation(fileRefsIndex + 16 + k * 8));
			}
		}
	}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		log(3, L"🔈VolumeInfo to_json");
		std::wstring result = L"";
		result += tab(i) + L"{\n"
			+ tab(i + 1) + L"\"DeviceName\":\"" + deviceName + L"\", \n"
			+ tab(i + 1) + L"\"SerialNumber\":\"" + serialNumber + L"\", \n"
			+ tab(i + 1) + L"\"MountPoint\":\"" + mountPoint + L"\", \n"
			+ tab(i + 1) + L"\"CreationTime\":\"" + time_to_wstring(creationTime) + L"\", \n"
			+ tab(i + 1) + L"\"CreationTimeUtc\":\"" + time_to_wstring(creationTimeUtc) + L"\", \n"
			+ tab(i + 1) + L"\"NbDirs\":\"" + std::to_wstring(dirStrings.size()) + L"\", \n"
			+ tab(i + 1) + L"\"Dirs\":[\n";
		std::vector<DirStrings>::iterator it;
		for (it = dirStrings.begin(); it != dirStrings.end(); it++) {
			result += it->to_json(i + 2);
			if (it != dirStrings.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(i + 1) + L"]\n";

		//File refs n'apporte rien à l'investigation numérique, juste commenter pour le réactiver si besoin
		//+ tab(i + 1) + L"\"FileReferences\":[\n";
		//std::vector<MFTInformation>::iterator it;
		//for (it = fileReferences.begin(); it != fileReferences.end(); it++) {
		//	result += it->to_json();
		//	if (it != fileReferences.end() - 1) result += L",\n";
		//	else result += L"\n";
		//}
		//result += tab(i + 1) + L"] \n";
		result += tab(i) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈VolumeInfo clear");
		for (MFTInformation temp : fileReferences)
			temp.clear();
	}
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
	Prefetch(const std::wstring file_path) {
		path = file_path;
		log(3, L"🔈replaceAll pathOriginal");
		pathOriginal = replaceAll(path, conf.mountpoint, L"C:");
		pathOriginal = replaceAll(pathOriginal, L"\\", L"\\\\");
	}

	/* lecture du fichier prefetch
	*/
	HRESULT read() {
		const int sig = 0x41434353;
		LPBYTE buffer = NULL; // buffer contenant le prefetch
		LPBYTE data = NULL;// buffer contenant les données du prefetch
		DWORD posBuffer = 0;
		std::ifstream file(path, std::ios::binary);
		if (!file.good()) {
			return ERROR_FILE_CORRUPT;
		}

		file.unsetf(std::ios::skipws);
		file.seekg(0, std::ios::end);
		const ULONG size = (ULONG)file.tellg();
		file.seekg(0, std::ios::beg);
		buffer = new BYTE[size];
		file.read(reinterpret_cast<char*>(buffer), size);
		file.close();

		//récupération des dates
		HANDLE hFile = CreateFile(path.c_str(),  // name of the write
			GENERIC_READ,          // open for writing
			0,                      // do not share
			NULL,                   // default security
			OPEN_EXISTING,          // open existing file only
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);                  // no attr. template
		if (hFile != INVALID_HANDLE_VALUE) {
			FILE_BASIC_INFO fileInfo;
			log(3, L"🔈GetFileInformationByHandleEx hFile");
			GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
			memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
			memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
			memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
			log(3, L"🔈FileTimeToLocalFileTime created");
			FileTimeToLocalFileTime(&createdUtc, &created);
			log(3, L"🔈FileTimeToLocalFileTime modified");
			FileTimeToLocalFileTime(&modifiedUtc, &modified);
			log(3, L"🔈FileTimeToLocalFileTime accessed");
			FileTimeToLocalFileTime(&accessedUtc, &accessed);
		}
		CloseHandle(hFile);

		//DECOMPRESSION SI BESOIN
		if (buffer[0] == 'M' && buffer[1] == 'A' && buffer[2] == 'M') {
			const unsigned short CompressionFormatXpressHuff = 4;
			using RtlDecompressBufferEx = NTSTATUS(__stdcall*)(
				USHORT CompressionFormat,
				PUCHAR UncompressedBuffer,
				ULONG UncompressedBufferSize,
				PUCHAR CompressedBuffer,
				ULONG CompressedBufferSize,
				PULONG FinalUncompressedSize,
				PVOID WorkSpace);
			using RtlGetCompressionWorkSpaceSize = NTSTATUS(__stdcall*)(
				USHORT CompressionFormatAndEngine,
				PULONG CompressBufferWorkSpaceSize,
				PULONG CompressFragmentWorkSpaceSize);

			static auto compression_workspace_size = reinterpret_cast<RtlGetCompressionWorkSpaceSize>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize"));
			static auto decompress_buffer_ex = reinterpret_cast<RtlDecompressBufferEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBufferEx"));

			const int decompressed_size = *reinterpret_cast<int*>(buffer + 4);
			posBuffer += 8;
			ULONG compressed_buffer_workspace_size, compress_fragment_workspace_size;
			log(3, L"🔈compression_workspace_size");
			HRESULT hr = compression_workspace_size(CompressionFormatXpressHuff, &compressed_buffer_workspace_size, &compress_fragment_workspace_size);
			if (hr != ERROR_SUCCESS)
				return hr;

			data = new BYTE[decompressed_size];

			ULONG final_uncompressed_size;

			auto* const workspace = malloc(compressed_buffer_workspace_size);
			if (!workspace)
				return ERROR_DECRYPTION_FAILED;

			log(3, L"🔈decompress_buffer_ex");
			decompress_buffer_ex(
				CompressionFormatXpressHuff,
				reinterpret_cast<PUCHAR>(data),
				decompressed_size,
				reinterpret_cast<PUCHAR>(buffer + posBuffer),
				size,
				&final_uncompressed_size,
				workspace);
			free(workspace);
		}
		else { // PAS DE COMPRESSION
			data = buffer;
		}



		version = *reinterpret_cast<int*>(data);
		signature = *reinterpret_cast<int*>(data + 4);
		hash_string = std::wstring(data + 76, data + 80).data();
		filename = std::wstring((wchar_t*)data + 8).data();

		//récupération du hash en std::hexa
		std::wostringstream temp;
		temp << std::hex << data[79] << data[78] << data[77] << data[76]; // HASH in std::hexa little indian
		hash_string = temp.str();

		//verification de la version
		if (version < 30) {
			log(2, L"🔥Prefetch version before 30 not supported", ERROR_INVALID_DATA);
			return ERROR_INVALID_DATA; // version non prise en charge (<win10)
		}
		//LECTURE DES DONNEES
		//FILE INFORMATION
		int start = *reinterpret_cast<int*>(data + 84);
		int nb_entries = *reinterpret_cast<int*>(data + 84 + 4);

		int trace_offset = *reinterpret_cast<int*>(data + 84 + 8);
		int nb_traces = *reinterpret_cast<int*>(data + 84 + 12);

		int filename_offset = *reinterpret_cast<int*>(data + 84 + 16);
		int filename_size = *reinterpret_cast<int*>(data + 84 + 20);

		int volume_offset = *reinterpret_cast<int*>(data + 84 + 24);
		int nb_volumes = *reinterpret_cast<int*>(data + 84 + 28);

		int volume_size = *reinterpret_cast<int*>(data + 84 + 32);
		//run times
		for (int i = 0; i < 8; i++) {
			FILETIME tempUtc = *reinterpret_cast<FILETIME*>(data + 84 + 44 + i * 8);
			FILETIME temp_locale;
			// on ne garde pas les date nulles, il n'y a pas toujours 8 dates
			log(3, L"🔈time_to_wstring last_runsUtc");
			if (time_to_wstring(tempUtc) != L"") {
				last_runsUtc.push_back(tempUtc);
				log(3, L"🔈FileTimeToLocalFileTime last_runs");
				FileTimeToLocalFileTime(&tempUtc, &temp_locale);
				last_runs.push_back(temp_locale);
			}
		}
		if (*reinterpret_cast<int*>(data + 84 + 120) == 0) // old_format
		{
			run_count = *reinterpret_cast<int*>(data + 84 + 124);
		}
		else { // new format
			run_count = *reinterpret_cast<int*>(data + 84 + 116);
		}
		//VOLUMES
		for (int i = 0; i < nb_volumes; i++) {
			log(3, L"🔈VolumeInfo");
			volumes.push_back(VolumeInfo(data + volume_offset, i));
		}
		//FILENAMES
		log(3, L"🔈multiWstring_to_vector filenames");
		std::vector<std::wstring> tv = multiWstring_to_vector(data + filename_offset, filename_size);
		for (std::wstring w : tv) {
			Filename f;
			f.filename = w.data();
			f.filename = replaceAll(f.filename, L"\\", L"\\\\").data();
			for (VolumeInfo v : volumes)
				if (f.filename.substr(0, 35).compare(v.deviceName) == 0) {
					f.fullPath = replaceAll(f.filename, v.deviceName, v.mountPoint).data();
					if (conf.md5) {
						//Le premier module retourne le exe path
						log(3, L"🔈fileToHash md5Source");
						f.md5 = QuickDigest5::fileToHash(wstring_to_string(replaceAll(f.fullPath,L"\\\\",L"\\"))).data();
					}
					if (f.fullPath.substr(f.fullPath.find_last_of(L'\\') + 1).compare(filename) == 0) {
						fullPath = f.fullPath.data();
						md5 = f.md5;
					}

					break;
				}
			filenames.push_back(f);
		}
		delete[] data;
		delete[] buffer;
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		log(3, L"🔈Prefetch to_json");
		std::wstring result = L"";

		result += tab(i) + L"{ \n";
		result += tab(i + 1) + L"\"Path\":\"" + pathOriginal + L"\", \n";
		result += tab(i + 1) + L"\"Hash\":\"" + hash_string + L"\", \n";
		result += tab(i + 1) + L"\"Filename\":\"" + filename + L"\", \n";
		result += tab(i + 1) + L"\"FullPath\":\"" + fullPath + L"\", \n";
		result += tab(i + 1) + L"\"Md5\":\"" + md5 + L"\", \n";
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
		result += tab(i + 1) + L"\"AccessedUtc\":\"" + time_to_wstring(accessedUtc) + L"\", \n";
		result += tab(i + 1) + L"\"RunCount\":\"" + std::to_wstring(run_count) + L"\", \n";
		log(3, L"🔈multiFiletime_to_json last_runs");
		result += tab(i + 1) + L"\"Runs\":" + multiFiletime_to_json(last_runs, i + 1) + L",\n";
		log(3, L"🔈multiFiletime_to_json last_runsUtc");
		result += tab(i + 1) + L"\"RunsUtc\":" + multiFiletime_to_json(last_runsUtc, i + 1) + L",\n";
		result += tab(i + 1) + L"\"NbVolumes\":\"" + std::to_wstring(volumes.size()) + L"\",\n";
		result += tab(i + 1) + L"\"Volumes\":[\n";
		std::vector<VolumeInfo>::iterator it;
		for (it = volumes.begin(); it != volumes.end(); it++) {
			result += it->to_json(i + 2);
			if (it != volumes.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(i + 1) + L"],\n";
		result += tab(i + 1) + L"\"NbFilesStrings\":\"" + std::to_wstring(filenames.size()) + L"\",\n";
		result += tab(i + 1) + L"\"FilesStrings\":[\n";
		std::vector<Filename>::iterator it2;
		for (it2 = filenames.begin(); it2 != filenames.end(); it2++) {
			result += it2->to_json(i + 2);
			if (it2 != filenames.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(i + 1) + L"]\n";
		result += tab(i) + L"}";
		return result;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Prefetch clear");
		for (VolumeInfo temp : volumes)
			temp.clear();
	}
};

/*! structure contenant l'ensemble des objets
*/
struct Prefetchs {
	std::vector<Prefetch> prefetchs; //!< tableau contenant tout les prefetch

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData() {

		log(0, L"*******************************************************************************************************************");
		log(0, L"ℹ️Prefetchs : ");
		log(0, L"*******************************************************************************************************************");


		log(3, L"🔈wstring_to_string path");
		std::string path = wstring_to_string(conf.mountpoint + L"\\Windows\\Prefetch");

		for (const auto& entry : std::filesystem::directory_iterator(path)) {
			if (entry.is_regular_file() && entry.path().extension() == ".pf") {
				log(1, L"➕Prefetch");
				Prefetch p(entry.path().wstring());
				HRESULT hresult = p.read();
				if (hresult != ERROR_SUCCESS) {
					log(2, L"🔥" + entry.path().wstring(), hresult);
					continue;
				} // prefetch non lisible
				else prefetchs.push_back(p);
			}
		}
		return ERROR_SUCCESS;
	}

	/*! conversion de l'objet au format json
	*/
	HRESULT to_json() {
		log(3, L"🔈Prefetchs to_json");
		std::wofstream myfile;
		std::wstring result = L"[\n";
		std::vector<Prefetch>::iterator it;
		for (it = prefetchs.begin(); it != prefetchs.end(); it++) {
			result += it->to_json(1);
			if (it != prefetchs.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += L"]";
		//enregistrement dans fichier json
		std::filesystem::create_directory(conf._outputDir); //crée le repertoire, pas d'erreur s'il existe déjà
		myfile.open(conf._outputDir + "/prefetchs.json");
		myfile << ansi_to_utf8(result);
		myfile.close();

		return ERROR_SUCCESS;
	}

	/* liberation mémoire */
	void clear() {
		log(3, L"🔈Prefetchs clear");
		for (Prefetch temp : prefetchs)
			temp.clear();
	}
};
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
	std::wstring name;//!< nom du Directory
	std::wstring type;//!< Type de directory
	std::wstring classId;//!< Identifiant de classe du Directory
	std::wstring nodeColor;//!< Couleur du nœud du Directory

	/*! retourne le nom du type de directory à partir d'un entier
	*/
	std::wstring getType(BYTE value) {
		switch (value) {
		case 0: return L"Empty"; break;
		case 1: return L"Storage"; break;
		case 2: return L"Stream"; break;
		case 3: return L"LockBytes"; break;
		case 4: return L"Property"; break;
		case 5: return L"RootStorage"; break;
		default: return L"Unknown"; break;
		}
	}

	/*! retourne la couleur du nœud du directory à partir d'un entier
	*/
	std::wstring getNodeColor(BYTE value) {
		switch (value) {
		case 0: return L"Red"; break;
		case 1: return L"Black"; break;
		default: return L"Unknown"; break;
		}
	}

	/*! Constructeur par défaut
	*/
	Directory() {};

	/*!Constructeur
	* @param data contient un pointeur sur les données à parser
	*/
	Directory(LPBYTE data) {
		nameLength = bytes_to_short(data + 64);
		name = ansi_to_utf8(std::wstring((wchar_t*)(data)));
		type = getType(data[66]);
		nodeColor = getNodeColor(data[67]);

		previousDirectoryId = bytes_to_int(data + 68);
		nextDirectoryId = bytes_to_int(data + 72);
		subDirectoryId = bytes_to_int(data + 76);

		classId = guid_to_wstring(*reinterpret_cast<GUID*>(data + 80));
		userFlags = bytes_to_unsigned_int(data + 96);
		created = bytes_to_filetime(data + 100);
		LocalFileTimeToFileTime(&created, &createdUtc);
		modified = bytes_to_filetime(data + 108);
		LocalFileTimeToFileTime(&modified, &modifiedUtc);

		firstSectorID = bytes_to_unsigned_int(data + 116);
		directorySize = bytes_to_unsigned_int(data + 120);
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {

		std::wstring result = tab(i) + L"{\n"
			+ tab(i + 1) + L"\"DirectoryName\":\"" + name + L"\", \n"
			+ tab(i + 1) + L"\"DirectoryType\":\"" + type + L"\", \n"
			+ tab(i + 1) + L"\"NodeColor\":\"" + nodeColor + L"\", \n"
			+ tab(i + 1) + L"\"PreviousDirectoryId\":" + std::to_wstring(previousDirectoryId) + L", \n"
			+ tab(i + 1) + L"\"NextDirectoryId\":" + std::to_wstring(nextDirectoryId) + L", \n"
			+ tab(i + 1) + L"\"SubDirectoryId\":" + std::to_wstring(subDirectoryId) + L", \n"
			+ tab(i + 1) + L"\"ClassId\":\"" + classId + L"\", \n"
			+ tab(i + 1) + L"\"UserFlags\":" + std::to_wstring(userFlags) + L", \n"
			+ tab(i + 1) + L"\"CreationTime\":\"" + time_to_wstring(created) + L"\", \n"
			+ tab(i + 1) + L"\"CreationTimeUtc\":\"" + time_to_wstring(createdUtc) + L"\", \n"
			+ tab(i + 1) + L"\"ModifiedTime\":\"" + time_to_wstring(modified) + L"\", \n"
			+ tab(i + 1) + L"\"ModifiedTimeUtc\":\"" + time_to_wstring(modifiedUtc) + L"\", \n"
			+ tab(i + 1) + L"\"FirstDirectorySectorId\":" + std::to_wstring(firstSectorID) + L", \n"
			+ tab(i + 1) + L"\"DirectorySize\":" + std::to_wstring(directorySize) + L", \n";
		result += tab(i) + L"}";
		return result;
	}
};

/*! représente une structure destfile*/
struct DestFile {
	std::wstring guidDroidVolume;//!< GUID containing an NTFS object identifier
	std::wstring guidDroidFile;//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidVolume;//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidFile;//!< GUID containing an NTFS object identifier
	std::wstring hostname;//!< Contains an ASCII string unused characters are filled with 0 - byte values
	std::wstring pathObject;//!< Contains a UTF-16 little-endian string without an end-of-string character
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
	DestFile(LPBYTE buffer) {
		guidDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
		guidDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 24));
		guidBirthDroidVolume = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 56));
		guidBirthDroidFile = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 56));
		hostname = string_to_wstring(ansi_to_utf8(std::string((char*)(buffer + 72))));
		entryNumber = bytes_to_unsigned_int(buffer + 88);
		lastModificationTimeUtc = bytes_to_filetime(buffer + 100);
		if (time_to_wstring(lastModificationTimeUtc) != L"")
			FileTimeToLocalFileTime(&lastModificationTimeUtc, &lastModificationTime);
		pinStatus = bytes_to_int(buffer + 108);
		pathObjectSize = bytes_to_unsigned_short(buffer + 128);
		pathObject = ansi_to_utf8(std::wstring((wchar_t*)(buffer + 130)));
		size = 130 + pathObjectSize * 2 + 4; // +2 fin de chaîne +2 Unknown 
	};

	/*! retourne le statut de pinned à partir de la valeur entière
	*/
	std::wstring getPinnedStatus() {
		if (pinStatus >= 0)
			return L"Pinned";
		else
			return L"Unpinned";
	}

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {

		std::wstring result = tab(i) + L"{\n"
			+ tab(i + 1) + L"\"GuidDroidVolume\":\"" + guidDroidVolume + L"\", \n"
			+ tab(i + 1) + L"\"GuidDroidFile\":\"" + guidDroidFile + L"\", \n"
			+ tab(i + 1) + L"\"GuidBirthDroidVolume\":\"" + guidBirthDroidVolume + L"\", \n"
			+ tab(i + 1) + L"\"GuidBirthDroidFile\":\"" + guidBirthDroidFile + L"\", \n"
			+ tab(i + 1) + L"\"Hostname\":\"" + hostname + L"\", \n"
			+ tab(i + 1) + L"\"EntryNumber\":" + std::to_wstring(entryNumber) + L", \n"
			+ tab(i + 1) + L"\"LastModificationTimeUtc\":\"" + time_to_wstring(lastModificationTimeUtc) + L"\", \n"
			+ tab(i + 1) + L"\"LastModificationTime\":\"" + time_to_wstring(lastModificationTime) + L"\", \n"
			+ tab(i + 1) + L"\"PinStatus\":" + getPinnedStatus() + L", \n"
			+ tab(i + 1) + L"\"PathObject\":\"" + pathObject + L"\", \n";
		result += tab(i) + L"}";
		return result;
	}
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
	DestFileDirectory(LPBYTE buffer) {
		formatVersion = bytes_to_int(buffer);
		numberOfEntries = bytes_to_int(buffer + 4);
		numberPinnedEntries = bytes_to_int(buffer + 8);
		buffer += 32; //en-tête
		int offset = 0;
		for (int x = 0; x < numberOfEntries; x++) {
			DestFile d = DestFile(buffer + offset);
			offset += d.size; //size variable en fonction des entrée à cause de la longueur du path
			destfiles.push_back(d);
		}
	};

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i) {
		std::wstring result = tab(i) + L"[\n";
		for (DestFile d : destfiles)
			result += d.to_json(i + 1) + L",\n";
		result += tab(i) + L"]";
		return result;

	}
};

/*! structure représentant l’entête de l'objet OLE
*/
struct oleHeader {
	bool littleIndian = false; //!< format littleindian ou Bigindian
	unsigned long _signature = 0xe11ab1a1e011cfd0; //!< signature attendue de l'objet OLE
	unsigned long signature = 0; //!< signature de l'objet OLE
	short int sectorSize = 0; //!< taille des secteurs de l'objet OLE
	short int shortSectorSize = 0; //!< taille des petits secteurs de l'objet OLE
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
	oleHeader(LPBYTE buffer, size_t _bufferSize) {
		signature = bytes_to_unsigned_long(buffer);
		if (signature != _signature)
			throw std::runtime_error("bad signature");

		littleIndian = (bytes_to_short(buffer + 28) == (short)0xfffe); //0xfeff = big indian
		if (littleIndian == false) {
			throw std::runtime_error("Big indian Format not Handle, please handle this file specifically");
		}

		sectorSize = pow(2, bytes_to_short(buffer + 30)); // Sector size at offset 30, en puissance de 2
		shortSectorSize = pow(2, bytes_to_short(buffer + 32)); // Short sector size at offset 32, en puissance de 2
		totalSATSectors = bytes_to_int(buffer + 44); // Total Sector Allocation Table(SAT) sectors at offset 44
		directoryStreamFirstSectorId = bytes_to_int(buffer + 48); // Sector ID of first sector used by Directory at offset 48
		minimumStandardStreamSize = bytes_to_unsigned_int(buffer + 56); // Minimum size of a standard stream in bytes at offset 56
		SSATFirstSectorId = bytes_to_int(buffer + 60); // Sector ID of the first sector used for the Short Sector Allocation Table(SSAT) at offset 60
		totalSSATSectors = bytes_to_unsigned_int(buffer + 64); // Total sectors used for SSAT at offset 64
		MSATFirstSectorId = bytes_to_int(buffer + 68);
		MSATTotalSectors = bytes_to_int(buffer + 72);
		// Process MSAT
		if (_bufferSize < 516)
			throw std::length_error("File corrupt - file smaller than header size"); // header = 76 + 109*4 + 4

		for (int i = 0; i < 109; i++) {
			int addr = bytes_to_int(buffer + 76 + i * 4);

			if (addr >= 0) {
				if (i < totalSATSectors)
					SATSectors.push_back(addr * sectorSize + 512); // 512 is for the header
				else
					throw std::length_error("File corrupt - The total number of sectors was larger than the one expected from the header data");
			}
		}
	}

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_json() {
		std::wstring result = L"";
		result += L"\"SectorSize \": " + std::to_wstring(sectorSize) + L"\n";
		result += L"\"ShortSectorSize \": " + std::to_wstring(shortSectorSize) + L"\n";
		result += L"\"TotalSATSectors \": " + std::to_wstring(totalSATSectors) + L"\n";
		result += L"\"DirectoryStreamFirstSectorId \": " + std::to_wstring(directoryStreamFirstSectorId) + L"\n";
		result += L"\"MinimumStandardStreamSize \": " + std::to_wstring(minimumStandardStreamSize) + L"\n";
		result += L"\"SSATFirstSectorId \": " + std::to_wstring(SSATFirstSectorId) + L"\n";
		result += L"\"TotalSSATSectors \": " + std::to_wstring(totalSSATSectors) + L"\n";
		result += L"\"MSATFirstSectorId \": " + std::to_wstring(MSATFirstSectorId) + L"\n";
		result += L"\"MSATTotalSectors \": " + std::to_wstring(MSATTotalSectors) + L"\n";
		result += L"\"SectorsIds \": \n";
		for (int sector : SATSectors) {
			result += std::to_wstring(sector) + L" \n";
		}

		return result;

	}
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
	int bufferSize = 0;//!< taille du buffer


	/*! Constructeur par défaut
	*/
	oleParser() {};

	/*!Constructeur
	* @param buffer contient un pointeur sur les données à parser
	* @param _bufferSize contient la taille du buffer
	*/
	oleParser(LPBYTE _buffer, int _bufferSize) {
		buffer = _buffer;
		bufferSize = _bufferSize;

		// 0. Process header
		header = oleHeader(buffer, _bufferSize);


		//Big Files
		if (header.MSATFirstSectorId > -2) {
			int maxSlotsPerBlock = header.sectorSize / 4;
			int remainingSlots = header.totalSATSectors - 109; // 109 for header part already done
			int remainingByteLen = 4 * remainingSlots;
			int msatOffset = (header.MSATFirstSectorId + 1) * header.sectorSize;
			int startOffset = 0;
			LPBYTE remainingBytes = new BYTE[remainingByteLen];
			while (remainingSlots > 0) {
				if (remainingSlots > maxSlotsPerBlock) {
					// in this case we have to only take so many
					for (int x = 0; x < header.sectorSize - 4; x++) {
						remainingBytes[x] = buffer[msatOffset + x];
					}
					remainingSlots -= maxSlotsPerBlock - 1;
					int newOffset = bytes_to_int(buffer + msatOffset + (4 * (maxSlotsPerBlock - 1)));
					msatOffset = (newOffset + 1) * header.sectorSize;
					startOffset += (maxSlotsPerBlock - 1) * 4;
				}
				else {
					//copy it and be done with it
					for (int x = 0; x < remainingSlots * 4; x++) {
						remainingBytes[startOffset + x] = buffer[msatOffset + x];
						remainingSlots -= remainingSlots;
					}
				}
			}

			remainingSlots = header.totalSATSectors - 109;

			for (int i = 0; i < remainingSlots; i += 4)
			{
				int sectorId = bytes_to_int(remainingBytes + i * 4) * header.sectorSize + 512; // 512 is for the header
				header.SATSectors.push_back(sectorId);
			}
			delete remainingBytes;
		}

		//We need to get all the bytes that make up the SectorAllocationTable
		//start with empty array to hold our bytes


		for (int sector : header.SATSectors)
		{
			if (sector + header.sectorSize > _bufferSize)
				throw std::length_error("file corrupt - Error copying data from the Sector Allocation Table");


			//fill the Sat
			for (int x = 0; x < header.sectorSize; x += 4) { // a chaque "sector" on copie sectorSize entiers
				sat.push_back(bytes_to_int(buffer + sector + x));
			}
		}

		//Just as with the SAT, but this time, with the SmallSectorAllocationTable
		if (header.SSATFirstSectorId != -2)
		{
			ssat = GetIntFromSat(header.SSATFirstSectorId);
		}

		// 1. Process all Directory entries
		// https://github.com/EricZimmerman/OleCf/blob/master/OleCf/OleCfFile.cs#L138

		std::vector<BYTE> dirBytes = GetBytesFromSat(header.directoryStreamFirstSectorId);
		LPBYTE pDirBytes = &dirBytes[0];
		int dirIndex = 0;
		if (dirIndex + 128 > dirBytes.size())
			throw std::length_error("file corrupt - Error copying data from directory index");

		while (dirIndex < dirBytes.size())
		{
			int dirLen = bytes_to_short(pDirBytes + dirIndex + 64);
			if (pDirBytes[dirIndex + 66] != 0 && dirLen > 0) { //0 is empty directory structure
				Directory d = Directory(pDirBytes + dirIndex);
				directories.push_back(d);
			}
			dirIndex += 128;
		}

		//the Root Entry directory item contains all the sectors we need for small sector stuff, so get the data and cut it up so we can use it later
	   //when we are done we will have a list of byte arrays, each 64 bytes long, that we can string together later based on SSAT

		rootEntry = findDirectory(L"root entry");
		if (rootEntry.name != L"" && rootEntry.directorySize > 0) {
			std::vector<BYTE> b = GetBytesFromSat((int)rootEntry.firstSectorID);
			int shortIndex = 0;
			while (shortIndex < b.size())
			{
				std::vector<BYTE> shortChunk;
				if (shortIndex + header.shortSectorSize > b.size())
					throw std::length_error("file corrupt - Error copying data for short sector");

				for (int x = 0; x < header.shortSectorSize; x++)
					shortChunk.push_back(b[shortIndex + x]);
				shortSectors.push_back(shortChunk);
				shortIndex += header.shortSectorSize;
			}
		}
	};

	/*! permet de retrouver un Directory dans l'objet ole à partir de son nom
	* @param nom du Directory
	*/
	Directory findDirectory(std::wstring name) {

		transform(name.begin(), name.end(), name.begin(), towlower);
		for (Directory d : directories) {
			transform(d.name.begin(), d.name.end(), d.name.begin(), towlower);
			if (d.name == name)
				return d;
		}
		return Directory();
	}

	/*! permet de parser un secteur de la sat en tableau d'entiers
	* @param sectorNumber correspond au numéro du secteur à parser
	*/
	std::vector<int> GetIntFromSat(int sectorNumber) {

		int sn = sectorNumber;
		std::vector<int> runInfo;
		runInfo.push_back(sectorNumber);
		int sectorSize = header.sectorSize;

		while (sat[sn] >= 0)
		{
			runInfo.push_back(sat[sn]);
			sn = sat[sn];
		}

		std::vector<int>retBytes;
		for (int i : runInfo)
		{
			int index = 512 + sectorSize * i; //header + relative offset
			int readSize = sectorSize;
			if (bufferSize - index < sectorSize)
				readSize = bufferSize - index;
			if (readSize > 0) {
				if (index + readSize > bufferSize)
					throw std::length_error("file corrupt - Error retrieving data from SAT");
				for (int x = 0; x < readSize; x += 4) {
					retBytes.push_back(bytes_to_int(buffer + index + x));
				}
			}
		}
		return retBytes;
	};

	/*! permet de parser un secteur de la sat en tableau de bytes
	* @param sectorNumber correspond au numéro du secteur à parser
	*/
	std::vector<BYTE> GetBytesFromSat(int sectorNumber) {

		int sn = sectorNumber;
		std::vector<int> runInfo;
		runInfo.push_back(sectorNumber);
		int sectorSize = header.sectorSize;

		while (sat[sn] >= 0)
		{
			runInfo.push_back(sat[sn]);
			sn = sat[sn];
		}
		std::vector<BYTE>retBytes;
		for (int i : runInfo)
		{
			int index = 512 + sectorSize * i; //header + relative offset
			int readSize = sectorSize;
			if (bufferSize - index < sectorSize)
				readSize = bufferSize - index;
			if (readSize > 0) {
				if (index + readSize > bufferSize)
					throw std::length_error("file corrupt - Error retrieving data from SAT");
				for (int x = 0; x < readSize; x++) {
					retBytes.push_back(buffer[index + x]);
				}
			}
		}
		return retBytes;
	};

	/*! permet de parser un secteur de la ssat en tableau de bytes
	* @param sectorNumber correspond au numéro du secteur à parser
	*/
	std::vector<BYTE> GetBytesFromSSat(int sectorNumber)
	{
		int sn = sectorNumber;
		std::vector<int> runInfo;
		runInfo.push_back(sectorNumber);
		while (ssat[sn] >= 0)
		{
			runInfo.push_back(ssat[sn]);
			sn = ssat[sn];
		}
		std::vector<BYTE> retBytes;
		for (int i : runInfo)
		{
			if (i > shortSectors.size() || header.shortSectorSize > shortSectors[i].size())
				throw std::length_error("file corrupt - Error retrieving data from SSAT");
			for (int x = 0; x < header.shortSectorSize; x++)
				retBytes.push_back(shortSectors[i][x]);
		}
		return retBytes;
	}

	/*! permet de parser les données d'un Directory
	* @param d correspond au directory contenant les données à récupérer
	*/
	std::vector<BYTE> Getdata(Directory d) { // Pour récupérer les Bytes correspondant d'un directory
		if (d.directorySize >= 4096)
			return GetBytesFromSat(d.firstSectorID);
		else if (d.directorySize > 0)
			return GetBytesFromSSat(d.firstSectorID);
		return {};
	}

};
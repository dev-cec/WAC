#pragma once

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include <algorithm>
#include "tools.h"



/*! \file
* \brief OLE PARSER
* Documentation: https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
* Documentation: https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
* Documentation: https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
*/

/*! Holds information about the files held, with a sector ID (SID) for the
* starting sector of a chain, and so on.
*/
struct Directory {
	short int nameLength = 0; //!< length of the name
	unsigned int firstSectorID = 0;//!< id of the first sector
	unsigned int userFlags = 0;//!< attributes of the directory
	int directorySize = 0; //!< size of the directory
	int previousDirectoryId = 0; //!< id of the previous directory
	int nextDirectoryId = 0; //!< id of the next directory
	int subDirectoryId = 0; //!< id of the subdirectory
	FILETIME createdUtc = { 0 }; //!< creation date in UTC
	FILETIME created = { 0 }; //!< creation date
	FILETIME modifiedUtc = { 0 }; //!< modification date in UTC
	FILETIME modified = { 0 };//!< modification date
	std::wstring name = L"";//!< name of the directory
	std::wstring type = L"";//!< type of the directory
	std::wstring classId = L"";//!< class identifier of the directory
	std::wstring nodeColor = L"";//!< colour of the directory's node

	/*! Returns the name of the directory type from an integer.
	*/
	std::wstring getType(BYTE value);

	/*! Returns the colour of the directory's node from an integer.
	*/
	std::wstring getNodeColor(BYTE value);

	/*! Builds an empty directory.
	*/
	Directory() {};

	/*! Reads a directory entry.
	* @param data pointer to the data to parse
	*/
	Directory(LPBYTE data);

	/*! Converts the directory to JSON.
	* @return its JSON object
	*/
	Json toJson();
};

/*! Represents a destfile structure. */
struct DestFile {
	std::wstring guidDroidVolume=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidDroidFile=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidVolume=L"";//!< GUID containing an NTFS object identifier
	std::wstring guidBirthDroidFile=L"";//!< GUID containing an NTFS object identifier
	std::wstring hostname=L"";//!< Contains an ASCII string unused characters are filled with 0 - byte values
	std::wstring pathObject=L"";//!< Contains a UTF-16 little-endian string without an end-of-string character
	FILETIME lastModificationTime = { 0 };//!< last modification date
	FILETIME lastModificationTimeUtc = { 0 };//!< last modification date in UTC
	short int pathObjectSize = 0; //!< size of the path object
	unsigned int entryNumber = 0;//!< number of the entry
	int pinStatus = 0;//!< Where a value of -1 (0xffffffff) indicates unpinned and a value of 0 or greater pinned.
	int size = 0;//!< size of the entry

	/*! Builds an empty destfile.
	*/
	DestFile() {};

	/*! Reads a destfile.
	* @param buffer pointer to the data to parse
	* @param limit bytes available from `buffer` to the end of the DestList
	*        stream: no read goes beyond; an entry that does not fit is left
	*        with `size` 0, which stops the caller's walk
	*/
	DestFile(LPBYTE buffer, size_t limit);

	/*! Returns the pinned status from the integer value.
	*/
	std::wstring getPinnedStatus();

	/*! Converts the destfile to JSON.
	* @return its JSON object
	*/
	Json toJson();
};

/*! Represents a destfile directory, holding a set of DestFiles. */
struct DestFileDirectory {
	int formatVersion = 0;//!< format of the entry
	int numberOfEntries = 0;//!< number of entries
	int numberPinnedEntries = 0;//!< number of pinned entries
	std::vector<DestFile> destfiles;//!< the destfile objects

	/*! Builds an empty destfile directory.
	*/
	DestFileDirectory() {};

	/*! Reads a destfile directory (the DestList stream).
	* @param buffer pointer to the data to parse
	* @param size size of the stream, in bytes
	*/
	DestFileDirectory(LPBYTE buffer, size_t size);

	/*! Converts the destfile directory to JSON.
	* @return its JSON object
	*/
	Json toJson();
};

/*! Header of an OLE / CFB (Compound File Binary) container.
*
* These fields are navigation coordinates inside the container (sector sizes,
* allocation tables), NOT investigation data: the usable traces of an automatic
* jump list are in the DestList stream and in the shell items, which oleParser
* reaches thanks to this header.
*
* The files parsed come from a suspect machine: they are not trusted. Every
* value that serves to compute an offset is therefore validated here, before
* use.
*/
struct oleHeader {
	bool littleIndian = false; //!< little-endian or big-endian
	unsigned long long _signature = 0xe11ab1a1e011cfd0; //!< expected signature of the OLE object
	unsigned long long signature = 0; //!< signature of the OLE object
	unsigned short versionMajor = 0; //!< major version (3 = 512-byte sectors, 4 = 4096-byte)
	unsigned short versionMinor = 0; //!< minor version
	int sectorSize = 0; //!< size of the sectors, in bytes (validated)
	int shortSectorSize = 0; //!< size of the short sectors, in bytes (validated)
	int totalSATSectors = 0; //!< total number of sectors in the SAT
	int directoryStreamFirstSectorId = 0;//!< id of the first sector holding the list of directories
	unsigned int minimumStandardStreamSize = 0;//!< minimum size of a stream
	unsigned int totalSSATSectors = 0; //!< total size of the SAT
	int MSATTotalSectors = 0;//!< total number of sectors in the MSAT
	int SSATFirstSectorId = 0; //!< id of the first sector of the SSAT
	int MSATFirstSectorId = 0;//!< id of the first sector of the MSAT
	std::vector<int> SATSectors; //!< the sectors of the SAT
	std::vector<int> ShortSATSectors;//!< the sectors of the SSAT
	/*! Builds an empty header.
	*/
	oleHeader() {}

	/*! Reads and validates the header.
	* @param buffer pointer to the data to parse
	* @param _bufferSize size of that buffer
	*/
	oleHeader(LPBYTE buffer, size_t _bufferSize);

};

/*! Reader of an OLE container.
*/
struct oleParser {
	oleHeader header; //!< header of the OLE file
	Directory rootEntry;//!< main entry of the OLE object
	std::vector<Directory> directories;//!< list of the directories of the OLE object
	std::vector<std::vector<BYTE>> shortSectors; //!< list of the short sectors of the OLE object
	std::vector<int> sat; //!< list of the sectors of the SAT
	std::vector<int> ssat;//!< list of the sectors of the SSAT
	LPBYTE buffer = NULL; //!< buffer holding the data of the OLE object to parse
	size_t bufferSize = 0;//!< size of that buffer


	/*! Builds an empty reader.
	*/
	oleParser() {};

	/*! Reads an OLE container.
	* @param _buffer pointer to the data to parse
	* @param _bufferSize size of that buffer
	*/
	oleParser(LPBYTE _buffer, size_t _bufferSize);

	/*! Finds a directory in the OLE object by its name.
	* @param name name of the directory
	*/
	Directory findDirectory(std::wstring name);

	/*! Follows a chain of sectors in an allocation table (SAT or SSAT).
	*
	* The indexes come from the file parsed, hence from an untrusted source: this
	* function validates every index against the table's size and detects cyclic
	* chains, which would loop for ever. It replaces the same walk written three
	* times, each copy with holes of its own.
	* @param table the allocation table to walk (sat or ssat)
	* @param first index of the first sector of the chain
	* @return the indexes of the chain, the first one included
	* @throws std::length_error if an index is out of bounds or the chain is cyclic
	*/
	static std::vector<int> sectorChain(const std::vector<int>& table, int first);

	/*! Reads a chain of sectors as an array of 32-bit integers — an allocation
	*  table (the SSAT) stored in sectors chained by the SAT.
	* @param sectorNumber first sector of the chain
	* @return the integers read, in order
	* @throws std::length_error if the chain points outside the file
	*/
	std::vector<int> GetIntFromSat(int sectorNumber);

	/*! Parses a sector of the SAT into an array of bytes.
	* @param sectorNumber number of the sector to parse
	*/
	std::vector<BYTE> GetBytesFromSat(int sectorNumber);

	/*! Parses a sector of the SSAT into an array of bytes.
	* @param sectorNumber number of the sector to parse
	*/
	std::vector<BYTE> GetBytesFromSSat(int sectorNumber);

	/*! Parses the data of a directory.
	* @param d the directory holding the data to read
	*/
	std::vector<BYTE> Getdata(Directory d) { // To read the bytes of a directory
		if (d.directorySize >= 4096) {
			log(3, L"🔈GetBytesFromSat firstSectorID");
			return GetBytesFromSat(d.firstSectorID);
		}
		else if (d.directorySize > 0) {
			log(3, L"🔈GetBytesFromSSat firstSectorID");
			return GetBytesFromSSat(d.firstSectorID);
		}
		return {};
	}

};
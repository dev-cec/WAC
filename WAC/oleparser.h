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

/*! One entry of the OLE directory: a stream or a storage, found by its name.
*
*  Only what WAC uses is read: the name, the first sector and the size. The
*  entry also carries a type, a colour, sibling ids, a CLSID, flags and two
*  dates; they were decoded into members that only an uncalled toJson() read —
*  dead code, whose dates were moreover converted as local times while MS-CFB
*  defines them in UTC.
*/
struct Directory {
	std::wstring name = L"";//!< name of the stream or storage
	unsigned int firstSectorID = 0;//!< id of its first sector
	int directorySize = 0; //!< size of its content, in bytes

	/*! Builds an empty entry (the "not found" result of findDirectory).
	*/
	Directory() {};

	/*! Reads a directory entry.
	* @param data the entry's 128 bytes
	*/
	Directory(LPBYTE data);
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
	int sectorSize = 0; //!< size of the sectors, in bytes (validated)
	int shortSectorSize = 0; //!< size of the short sectors, in bytes (validated)
	int totalSATSectors = 0; //!< total number of sectors in the SAT
	int directoryStreamFirstSectorId = 0;//!< id of the first sector holding the list of directories
	unsigned int minimumStandardStreamSize = 0;//!< minimum size of a stream
	int SSATFirstSectorId = 0; //!< id of the first sector of the SSAT
	int MSATFirstSectorId = 0;//!< id of the first sector of the MSAT
	std::vector<int> SATSectorIds; //!< ids of the sectors holding the SAT (the MSAT's content)
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

	/*! Position in the file of sector `id`.
	*
	*  The header occupies the first sector, so sector `id` starts at
	*  (id + 1) × sectorSize. "512 + id × sectorSize", used until now, holds for
	*  512-byte sectors only (version 3): in version 4 the sectors are 4096
	*  bytes and the header is padded to 4096, so every read landed 3584 bytes
	*  too early — a valid-looking but wrong content.
	*  @param id sector id, >= 0
	*  @return its offset from the start of the file */
	size_t sectorOffset(int id) const;

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

	/*! Reads the content of a stream, cut to its declared size.
	* @param d the directory entry of the stream
	* @return its bytes; empty for an empty stream
	* @throws std::length_error if its chain points outside the file
	*/
	std::vector<BYTE> Getdata(const Directory& d);

};
/*! \file
 *  \brief Prefetch: which executables ran, how many times, and what they loaded.
 *
 *  WHAT IT SHOWS. To speed up the next start, Windows records for each
 *  executable the files it loaded during its first ten seconds, the number of
 *  runs, and the last eight run times. It is the strongest execution proof on a
 *  workstation: a file exists only because the program RAN. And the list of
 *  loaded files says what it did — the DLLs it pulled in, the documents it
 *  opened, the volumes it reached.
 *
 *  WHERE IT IS READ. `C:\Windows\Prefetch\<NAME>-<HASH>.pf`, the hash being
 *  computed over the executable's path: two copies of the same binary in two
 *  directories therefore give two files, and a same name with two different
 *  hashes means two distinct paths. The content is compressed (MAM/XPRESS
 *  Huffman) since Windows 8.
 *
 *  WHAT IT DOES NOT SAY. Which user ran the program — Prefetch is machine-wide.
 *  And the service is disabled on some systems (SSD, server, group policy):
 *  the absence of a file is then no proof of non-execution.
 *
 *  Format: https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc
 */
#pragma once

#include "binaires.h"
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <sstream>
#include "tools.h"
#include "quickdigest5.h"



/*! A file reference in the $MFT: what identifies a file on the volume
 *  independently of its name. */
struct MFTInformation {
	unsigned int entryIndex = 0;     //!< record number in the $MFT
	unsigned int sequenceNumber = 0; //!< sequence number, which a reuse of the record increments

	//! Builds an empty reference.
	MFTInformation() {}

	/*! Reads a reference from a Prefetch file.
	 *  @param data the six bytes of the reference. */
	MFTInformation(LPBYTE data);

	/*! Converts the reference to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the reference.
	void clear();
};

/*! One directory the executable reached, as listed by the Prefetch file. */
struct DirStrings {
	std::wstring dir = L"";      //!< the string as the Prefetch file holds it, in NT form
	std::wstring fullPath = L""; //!< the same path with its drive letter

	/*! Converts the directory to JSON.
	 *  @return its JSON object. */
	Json toJson();
};

/*! One file the executable loaded during its first ten seconds. */
struct Filename {
	std::wstring filename = L"";//!< the string as the Prefetch file holds it, in NT form
	std::wstring fullPath = L""; //!< the same path with its drive letter
	EmpreinteBinaire empreinte; //!< fingerprints of that file, if `--binary` was given
	/*! $MFT reference of the loaded file, read from the metrics array.
	*
	*  It identifies the file on the volume INDEPENDENTLY of its name: an
	*  executable renamed or deleted since is found again by its record number,
	*  which the path alone does not allow. Null when the metrics array does not
	*  give it, or when the match with the name is not certain — no reference is
	*  better than a reference attributed to the wrong file.
	*/
	MFTInformation reference;
	bool referenceConnue = false;   //!< true if `reference` was read

	/*! Converts the loaded file to JSON.
	 *  @return its JSON object. */
	Json toJson();
};

/*! One volume the executable reached, as described by the Prefetch file. */
struct VolumeInfo { 
	FILETIME creationTime = { 0 };    //!< creation of the volume, suspect's local time
	FILETIME creationTimeUtc = { 0 }; //!< the same instant in UTC
	std::wstring serialNumber = L""; //!< serial number of the volume
	std::wstring mountPoint = L"";   //!< drive letter it was mounted on
	std::wstring deviceName = L"";   //!< device name, in NT form
	std::vector<DirStrings> dirStrings; //!< the directories reached on this volume
	std::vector<MFTInformation> fileReferences; //!< references of the files loaded from
	                                 //!< this volume, kept for completeness

	//! Builds an empty volume.
	VolumeInfo() {}

	/*! Reads a volume block from a Prefetch file.
	 *  @param data the block's bytes.
	 *  @param indice rank of the volume in the Prefetch file. */
	VolumeInfo(LPBYTE data, int indice);

	/*! Converts the volume to JSON.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the volume.
	void clear();
};

/*! One Prefetch file: an executable that ran, and what it loaded. */
struct Prefetch {
public:
	std::wstring path = L"";         //!< path of the .pf file in the working directory
	std::wstring pathOriginal = L"";	//!< path it was read from on the examined volume
	//HEADER
	std::wstring filename = L"";//!< name of the executable, as the .pf file names it
	std::wstring fullPath = L"";//!< full path of the executable, once resolved
	EmpreinteBinaire empreinte; //!< fingerprints of that executable, if `--binary` was given
	int signature = 0; //!< signature of the .pf file, which identifies its format
	int version = 0;   //!< format version, which follows the Windows version
	int size = 0;      //!< size the .pf file declares
	// FILE INFORMATION
	FILETIME created = { 0 };     //!< creation of the .pf FILE, suspect's local time
	FILETIME createdUtc = { 0 };  //!< the same instant in UTC
	FILETIME modified = { 0 };    //!< last modification of the .pf file, local time
	FILETIME modifiedUtc = { 0 };	//!< the same instant in UTC
	FILETIME accessed = { 0 };    //!< last access to the .pf file, local time
	FILETIME accessedUtc = { 0 };	//!< the same instant in UTC
	std::vector<FILETIME> last_runs;    //!< the last eight runs, suspect's local time
	std::vector<FILETIME> last_runsUtc;	//!< the same instants in UTC
	int run_count = 0; //!< number of runs counted since the file was created
	std::wstring hash_string = L"";//!< hash in the file's name, computed over the
	                               //!< executable's path: it distinguishes two
	                               //!< copies of the same binary

	//Filename strings
	std::vector<Filename> filenames; //!< the files loaded during the first ten seconds

	//volume information
	std::vector<VolumeInfo> volumes; //!< the volumes those files were loaded from

	/*! Prepares the reading of a Prefetch file.
	 *  @param file_path path of the .pf file in the working directory. */
	Prefetch(const std::wstring file_path);

	/*! Reads the file: decompresses it if need be, then parses it.
	 *  @return the result of the read. */
	HRESULT read();

	/*! Converts the Prefetch file to JSON, loaded files and volumes included.
	 *  @return its JSON object. */
	Json toJson();

	//! Releases the memory held by the Prefetch file.
	void clear();
};

/*! All the Prefetch files of the examined machine. */
struct Prefetchs {
	std::vector<Prefetch> prefetchs; //!< the files read, in the order they were listed

	/*! Lists the Prefetch directory and reads each .pf file.
	 *  @return S_OK, or the failure of the last read attempted. */
	HRESULT getData();

	/*! Writes `prefetchs.json` into the output directory.
	 *  @return the result of the write. */
	HRESULT toJson();

	//! Releases the memory held by the Prefetch files.
	void clear();
};
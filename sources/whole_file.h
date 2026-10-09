/*! \file
 *  \brief Reading a whole file, bounded: the one function every decoder uses.
 *
 *  Header-only and without WAC's other headers, so that the programs built
 *  from a few sources (raw_hive_test) and the modules that do not include
 *  tools.h use it too.
 */
#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "long_path.h"

/*! A file's bytes, whole, in one read at its size — THE reading of a whole
*  file (B-044): each decoder used to have its own, a byte-wise stream
*  iterator for most, several without any bound on the size.
*  BOUNDED. A file of the examined machine is hostile: its size is checked
*  against `maximum`, named by each caller after what its format holds,
*  before any allocation.
* @tparam Bytes std::vector<uint8_t>, or std::string for a text
* @param file the file
* @param maximum the largest size accepted: a file beyond it is not read
* @param bytes receives its content; emptied on a failure
* @return false if it is unreadable, or larger than `maximum` — an empty file
*         is read, and gives true */
template <class Bytes>
bool readWholeFile(const std::filesystem::path& file, uintmax_t maximum, Bytes& bytes) {
	bytes.clear();
	// Whatever the length of its path: an exhibit's working copy can pass MAX_PATH (B-049).
	uint64_t size = 0;
	if (!fileSizeOf(file.wstring(), size) || size > maximum) return false;
	std::ifstream in(std::filesystem::path(extendedPath(file.wstring())), std::ios::binary);
	if (!in) return false;
	bytes.resize((size_t)size);
	if (size != 0 && !in.read(reinterpret_cast<char*>(bytes.data()), (std::streamsize)size)) {
		bytes.clear();
		return false;
	}
	return true;
}

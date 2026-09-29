/*! \file
 *  \brief A file taken out of an archive — cabinet (cab.h) or ZIP (zip.h),
 *         the two containers --update-trust downloads.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

/*! A file of an archive. */
struct ArchiveFile {
	std::string name;              //!< its name, as the archive gives it
	std::vector<uint8_t> content;  //!< its content
};

/*! Little-endian reads, the byte order of both formats. The caller has
 *  checked the bytes lie within the archive. */
inline uint16_t archiveLe16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
//! @copydoc archiveLe16
inline uint32_t archiveLe32(const uint8_t* p) {
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

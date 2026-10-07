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


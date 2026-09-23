#pragma once

/*! \file
 *  \brief Reading the resources of a PE binary, offline.
 *
 *  WHY. An event's plain-text message is NOT in the log: the log holds only the
 *  event's identifier and its data. The text lives in the provider's resource
 *  file, and it was `EvtFormatMessage` that brought them together — at the price
 *  of a call to the examined system. Measured on a real collection: 14,046
 *  events out of 102,627 carried a message, 97 % of which came from modern
 *  providers.
 *
 *  Two resources are needed, and they live in the same binary:
 *
 *    MESSAGETABLE   the table of texts, indexed by message identifier. On a
 *                   localised system it is not in the DLL but in its satellite
 *                   file `<language>\<name>.mui`.
 *    WEVT_TEMPLATE  the provider's metadata, which tie an EVENT identifier to a
 *                   MESSAGE identifier. Without it, one does not know which
 *                   text goes with which event.
 *
 *  This module does one thing only: return the raw content of a given resource.
 *  Interpreting it belongs to message_table.h and wevt.h.
 *
 *  WHAT MAKES READING A PE DELICATE HERE. The addresses in the resource
 *  directory are VIRTUAL addresses (RVA), not positions in the file. Every RVA
 *  must therefore be translated through the section table — and that
 *  translation is the one place where an implementation goes wrong silently, by
 *  reading bytes taken elsewhere in the binary.
 *
 *  The files come from the examined machine: every header, every offset and
 *  every counter is bounded by the file's real size, and a malformed binary
 *  returns an empty resource rather than having memory read out of range.
 *
 *  Portable C++, no dependency: verifiable outside Windows (see
 *  pe_resource_test).
 */

#include <cstdint>
#include <string>
#include <vector>

//! Resource types useful here. RT_MESSAGETABLE is standard (11);
//! WEVT_TEMPLATE is a NAMED type, specific to the event providers.
const uint32_t PE_RT_MESSAGETABLE = 11;

/*! Loads a PE binary into memory and gives access to its resources. */
class PeResource {
public:
	/*! Opens the file and validates its headers.
	*  @param path the binary to read (an extracted copy, never the original)
	*  @return true if the file is a PE whose resource directory is usable */
	bool open(const std::wstring& path);

	//! Vrai si `ouvrir` a abouti.
	bool open() const { return open_; }

	//! Error message if `open` failed.
	const std::wstring& error() const { return error_; }

	/*! Content of a resource named by a NUMERIC type.
	*  @param type for example PE_RT_MESSAGETABLE
	*  @param language wanted language identifier, or 0 for the first one found
	*  @return the bytes of the resource, empty if absent */
	std::vector<uint8_t> resource(uint32_t type, uint32_t language = 0) const;

	/*! Content of a resource named by a NAMED type.
	*  @param typeName for example L"WEVT_TEMPLATE" (comparison without regard to case)
	*  @param language wanted language identifier, or 0 for the first one found
	*  @return the bytes of the resource, empty if absent */
	std::vector<uint8_t> namedResource(const std::wstring& typeName,
	                                     uint32_t language = 0) const;

	/*! Resource types present, for diagnosis.
	*  @return "11" for the numeric types, the name for the others */
	std::vector<std::wstring> typesPresent() const;

private:
	std::vector<uint8_t> file_;
	bool open_ = false;
	std::wstring error_;
	uint32_t resourcesRva_ = 0;     //!< RVA of the resource directory
	uint32_t resourcesSize_ = 0;
	size_t   resourcesOffset_ = 0;  //!< its position IN THE FILE

	//! Translates a virtual address into a position in the file, 0 if out of range.
	size_t offsetDeRva(uint32_t rva) const;
	struct Section { uint32_t rva, virtualSize, fileOffset, rawSize; };
	std::vector<Section> sections_;

	//! Walks one level of the resource directory.
	std::vector<uint8_t> find(uint32_t type, const std::wstring& typeName,
	                             uint32_t language) const;
};

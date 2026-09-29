/*! \file
 *  \brief THE VERSION RESOURCE of a PE (VS_VERSIONINFO): what a binary says
 *         it is.
 *
 *  WHY. Microsoft's blocklist of vulnerable drivers denies some signers for
 *  given files only — "this authority, for AsIO.sys up to version 1.2" —,
 *  and a file is named there by its ORIGINAL name, the one its version
 *  resource carries: an attacker who brings a vulnerable driver renames it
 *  on disk, not inside. Reading that resource is what tells a vulnerable
 *  driver under another name from a sound one of the same signer.
 *
 *  THE FORMAT, a tree of nodes, each: WORD wLength, WORD wValueLength, WORD
 *  wType, the key in UTF-16 up to its NUL, padding to 32 bits, the value,
 *  padding, then the children, up to wLength. The root "VS_VERSION_INFO"
 *  holds the fixed part (VS_FIXEDFILEINFO: signature 0xFEEF04BD, file
 *  version); its child "StringFileInfo" holds tables by language, each
 *  holding the texts — OriginalFilename, InternalName, ProductName,
 *  FileDescription…
 *
 *  The binary comes from the examined machine: every length is bounded by
 *  its parent's and by the resource's real size; a malformed node ends the
 *  reading, keeping what was read.
 *
 *  Portable C++: checked against Windows' own reading (see
 *  version_info_test).
 */
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

/*! What a version resource says. */
struct VersionInfo {
	bool fixed = false;             //!< the fixed part was read
	uint64_t fileVersion = 0;       //!< its file version: major.minor.build.revision, 16 bits each
	//! The texts, by key, from the first language table that holds each.
	std::map<std::wstring, std::wstring> strings;
};

/*! Reads a version resource.
 *  @param resource its bytes (PeResource::resource(PE_RT_VERSION))
 *  @param info receives what it says
 *  @return true if its root is a VS_VERSION_INFO */
bool ReadVersionInfo(const std::vector<uint8_t>& resource, VersionInfo& info);

/*! "a.b.c.d" to the 64-bit form of VersionInfo::fileVersion.
 *  @return false if the text is not four numbers of 16 bits */
bool ParseFileVersion(const std::wstring& text, uint64_t& version);

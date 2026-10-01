/*! \file
 *  \brief NTFS security descriptors ($Secure:$SDS): the owner and the access rights of every file.
 *
 *  WHAT THE ARTEFACT PROVES. NTFS keeps each distinct security descriptor
 *  ONCE, in the $SDS stream of the metafile $Secure; a file's
 *  $STANDARD_INFORMATION only holds its number (`SecurityId`, in mft.json).
 *  The descriptor names the file's OWNER — the account that created it, or
 *  took it over — and its DACL says who may read, write or run it. An
 *  intruder's tool dropped by their account, a system file whose owner is no
 *  longer TrustedInstaller, an ACL opened to Everyone: all are read here, for
 *  every file of the $MFT, deleted ones included while their record lasts.
 *
 *  ONE ENTRY PER DESCRIPTOR, NOT PER FILE. Thousands of files share a
 *  descriptor; security_descriptors.json gives each once, and mft.json the
 *  number that points to it (Volume + SecurityId).
 *
 *  THE FORMAT ($SDS). 256 KiB blocks, each followed by its mirror copy (the
 *  odd blocks are skipped). An entry: hash (4), SecurityId (4), its own offset
 *  in the stream (8), its length header included (4), then the self-relative
 *  descriptor; entries are aligned on 16 bytes and never cross a block. An
 *  entry whose recorded offset is not its place, or whose length leaves the
 *  block, ends the block's reading.
 *
 *  A CHECK OF ITS OWN. The hash is computed by NTFS over the descriptor's
 *  bytes; it is recomputed here, and a descriptor that does not match it is
 *  flagged (`HashMismatch`) rather than trusted silently.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! One descriptor of $SDS. */
struct SecurityDescriptorEntry {
	std::wstring volume;            //!< its volume, "C:"
	uint32_t securityId = 0;        //!< the number files carry in $STANDARD_INFORMATION
	uint32_t hash = 0;              //!< the hash NTFS stored
	bool hashMatches = true;        //!< the stored hash is that of the descriptor's bytes
	std::vector<uint8_t> descriptor;  //!< the self-relative SECURITY_DESCRIPTOR
	//! @return the descriptor as a JSON object
	Json toJson() const;
};

/*! The hash NTFS stores with a descriptor: over its 32-bit words, each added
 *  to the running hash rotated left by 3.
 *  @param data the descriptor's bytes
 *  @param size their number (a final partial word is not counted, as NTFS does)
 *  @return the hash */
uint32_t securityDescriptorHash(const uint8_t* data, size_t size);

/*! Decodes an $SDS stream: every entry of the main blocks, the mirrors skipped,
 *  a SecurityId kept once (the first met). Every read is bounded by `size`.
 *  @param data the stream's bytes
 *  @param size their number
 *  @param volume the volume, copied into each entry
 *  @return the entries, in the stream's order */
std::vector<SecurityDescriptorEntry> parseSds(const uint8_t* data, size_t size, const std::wstring& volume);

/*! The security descriptors of every NTFS volume collected (security_descriptors.json). */
class SecurityDescriptors {
public:
	/*! Reads the $SDS copy of each fixed NTFS volume, from the exhibit store.
	 *  @return ERROR_SUCCESS if at least one volume gave its stream */
	HRESULT getData();
	/*! Writes security_descriptors.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the descriptors read.
	void clear();
private:
	std::vector<SecurityDescriptorEntry> entries_;   //!< every volume's, in order
};

/*! \file
 *  \brief LEVEL 3 OF THE DELETED FILES' RECOVERY: files found in the free
 *         clusters by their structure (carving), when even their record is
 *         gone (backlog B-036).
 *
 *  WHY ONLY THREE FORMATS. A carved file has no name, no date, no record:
 *  only its bytes, cut from a start the signature gives to an end something
 *  must give too. Cut wrong, it is a file that looks right and is not —
 *  what the recovery must never publish. Only the formats whose own
 *  structure gives their exact size, and lets it be checked, are carved:
 *    - PE (executables, libraries, drivers): the end of the last section's
 *      raw data, of the Authenticode signature, or of the COFF symbol and
 *      string tables a MinGW build leaves — the headers checked first
 *      (machine, sections, alignment); an overlay no header describes (an
 *      installer's payload) is cut off;
 *    - ZIP, and the Office documents and archives built on it: the end of
 *      the end-of-central-directory record, which must say where the
 *      central directory lies, just before it, starting with its signature;
 *    - PDF: the first "%%EOF" whose "startxref" points back into the file at
 *      a cross-reference table or stream — an incrementally updated PDF is
 *      then cut at its first version, which is a whole document too.
 *  Anything else — a text, a JPEG, an event log — is left: its end cannot be
 *  told from what follows it.
 *
 *  Portable C++: tested natively and under Wine (deleted_files_test).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

/*! The formats carved. */
enum class CarvedFormat { None, Pe, Zip, Pdf };

//! The format's name in deleted_files.json, and the extension of its exhibit.
const wchar_t* carvedFormatName(CarvedFormat format);
const wchar_t* carvedFormatExtension(CarvedFormat format);

/*! What a start of cluster says of the file it may begin. */
struct CarvedStart {
	CarvedFormat format = CarvedFormat::None;
	/*! The file's size, when the bytes given suffice to tell it (a PE's
	 *  headers, without a COFF symbol table); 0 when the end must be found
	 *  in what follows (carvedEnd). */
	uint64_t size = 0;
	/*! When size is 0: the bytes from the start carvedEnd needs at least — a
	 *  PE's COFF symbol table and the length of its string table (MinGW
	 *  leaves them after the sections); 0 for a ZIP or a PDF, whose end is
	 *  looked for as far as the bytes go. */
	uint64_t needed = 0;
};

/*! Whether a cluster starts a file of a carved format.
 *  @param head the first bytes of the cluster — a PE needs its headers,
 *         4 KiB hold them in practice
 *  @param length their number: nothing beyond is read
 *  @return the format (None if none), and the size when the head gives it */
CarvedStart carvedStart(const uint8_t* head, size_t length);

/*! The end of a file that starts at `data`, when carvedStart could not tell
 *  it from the head: a ZIP's or a PDF's looked for in what follows, a PE's
 *  read in its COFF string table.
 *  @param format the format carvedStart gave
 *  @param data the bytes from the file's start
 *  @param length their number: nothing beyond is read
 *  @return the file's exact size, or 0 if no checked end lies within `length` */
uint64_t carvedEnd(CarvedFormat format, const uint8_t* data, size_t length);

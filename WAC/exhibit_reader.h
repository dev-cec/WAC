/*! \file
 *  \brief Files of the examined machine, read from the exhibit store of a
 *         collection made earlier (--convert).
 *
 *  WHY. A conversion on an analysis workstation must never read that
 *  workstation's own disk in place of the examined machine's: a cited binary
 *  "C:\Windows\System32\cmd.exe" is the one collected, found through the
 *  manifest, which ties every source path to the exhibit holding its content
 *  — its own file, or one it shares (see ExhibitStoreIndex). A file the
 *  collection did not take is ABSENT for the conversion — never looked for
 *  elsewhere.
 *
 *  Read-only: the exhibit store is sealed. The fingerprints are recomputed
 *  while reading, as the raw reader does on the volume.
 */
#pragma once
#include "raw_hive.h"

/*! A FileSource that serves the files of the examined machine from the
 *  exhibit store (see raw_hive.h, FileSource). */
class ExhibitReader : public FileSource {
public:
    /*! Reads the collected copy of a file of the examined machine.
     *  @param absolutePath the file, as it was on the machine ("X:\\…")
     *  @param output file to write the copy to; empty for fingerprints only
     *  @param line receives the record and the fingerprints
     *  @param observer if `output` is empty, receives the content
     *  @return ERROR_SUCCESS, or ERROR_FILE_NOT_FOUND (as HRESULT) if the
     *          collection does not hold that file */
    HRESULT read(const std::wstring& absolutePath, const std::wstring& output,
                 RawHiveExtraction& line, std::streambuf* observer = nullptr) override;

    /*! Lists the collected copy of a directory of the examined machine.
     *  @param absoluteFolder the directory, as it was on the machine
     *  @param entries receives its entries (mftIndex: a rank, unique per call)
     *  @return ERROR_SUCCESS, or ERROR_PATH_NOT_FOUND (as HRESULT) */
    HRESULT list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) override;
};

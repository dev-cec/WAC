/*! \file
 *  \brief Test support: a data file placed as the collection places an
 *         exhibit — in the exhibit store and in its working copy — then
 *         registered in the manifest.
 *
 *  WHY. The conversion reads every exhibit in the WORKING copy, never in the
 *  exhibit store (B-040): an exhibit registered with a path outside the
 *  store has no working copy, and a reader finds nothing. mft_test and
 *  usn_journal_test registered their fixtures where mft_fixtures.sh wrote
 *  them, and failed since the working copy is found by the store's folder
 *  only (2026-10-22). Used by the test harnesses only: never compiled into WAC.
 */
#pragma once
#include <filesystem>
#include <string>
#include "consigne.h"
#include "tools.h"

/*! Copies a file as an exhibit of `volumePath`, under the exhibit store and
 *  the working directory of `outputFolder` (which becomes the output
 *  folder), and returns its record for ExhibitStoreAdd.
 *  @param outputFolder the test's output folder
 *  @param volumePath the path the exhibit had on the examined volume ("C:\\$MFT")
 *  @param source the data file
 *  @param storedAs where the store keeps it, as a path on the volume, when
 *         `volumePath` names a stream ("C:\\$Extend\\$J" for
 *         "$UsnJrnl:$J", as the collection stores it); `volumePath` otherwise
 *  @return the record, its result S_OK if both copies were written */
inline RawHiveExtraction placedExhibit(const std::wstring& outputFolder, const std::wstring& volumePath,
                                       const std::wstring& source, const std::wstring& storedAs = std::wstring()) {
	const std::wstring stored = storedAs.empty() ? volumePath : storedAs;
	conf._outputDir = outputFolder;
	RawHiveExtraction line;
	line.volumePath = volumePath;
	line.outputPath = pathUnder(exhibitStoreFolder(), stored);
	line.result = S_OK;
	std::error_code ec;
	for (const std::wstring& target : { line.outputPath, pathUnder(workingFolder(), stored) }) {
		std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);
		/* Removed first: MinGW's copy_file fails on an existing target even
		   with overwrite_existing, and a second test of the same fixtures
		   found its exhibit failed. */
		std::filesystem::remove(target, ec);
		if (!std::filesystem::copy_file(source, target, ec))
			line.result = E_FAIL;
	}
	return line;
}

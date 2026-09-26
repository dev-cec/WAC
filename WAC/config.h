/*! \file
 *  \brief THE CONFIGURATION FILE, wac.yml: the collection's procedure, written
 *         once, applied the same way every time.
 *
 *  WHY A FILE. The options multiplied (--binary, --binary-all, --events,
 *  --threads…), and each run had to repeat them: a procedure typed by hand
 *  is a procedure that varies. wac.yml, next to WAC.exe, holds it; the
 *  command line still overrides it, for an exception without retouching the
 *  reference file.
 *
 *  WHAT IT HOLDS: one setting per top-level key, then `artefacts:`, one
 *  switch per artefact — all the hives being one artefact, `registry`:
 *
 *      convert: true          # true: collect and convert here; false: collect only
 *      binary: none           # none | unverified | all
 *      threads: 0             # analysis threads for the binaries, 0: automatic
 *      output: output
 *      log_level: 0
 *      dump: false
 *      artefacts:
 *        registry: true
 *        events: false
 *        ...
 *
 *  STRICT: an unknown key, a value outside the ones allowed, a duplicate key
 *  refuse the collection before it starts, with the line at fault — a typo
 *  must not switch an artefact off silently. A key left out keeps its
 *  default.
 *
 *  RECORDED: the file's path, SHA-256 and content go into investigation.json:
 *  the procedure applied is part of the evidence.
 */
#pragma once

#include "tools.h"
#include <string>

/*! The configuration file read, for the investigation log. */
struct ConfigurationFile {
	bool present = false;       //!< a file was found and applied
	std::wstring path;          //!< where
	std::string text;           //!< its content, as read (UTF-8)
	std::wstring sha256;        //!< its fingerprint, uppercase hexadecimal
};

/*! Reads a configuration file and applies it to `conf`.
 *  @param path the file; absent, nothing is applied and `file.present` stays false
 *  @param conf receives the settings
 *  @param file receives what was read
 *  @param error receives "line N: why" when refused
 *  @return false if the file is present and refused */
bool LoadConfiguration(const std::wstring& path, AppliConf& conf, ConfigurationFile& file, std::string& error);

/*! @return the reference configuration, commented — what --write-config
 *  writes: WAC/wac.yml, built into the executable as a resource (see WAC.rc),
 *  the file build-windows.sh also copies to WAC/bin; empty if the resource is
 *  missing */
std::string DefaultConfiguration();

/*! @return the default place of the file: wac.yml, next to WAC.exe */
std::wstring DefaultConfigurationPath();

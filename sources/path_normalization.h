/*! \file
 *  \brief THE normalisation of a file path, shared with WAE word for word.
 *
 *  One rule for every path WAC writes and WAE relates (shared rules, §5: two
 *  projects that share a logic share the file). WAE keeps a copy in
 *  wae/shared/, compared byte for byte with this one by its check-shared.sh:
 *  a change is made here, then copied.
 *
 *  PORTABLE C++, without windows.h: the system drive is a parameter (WAC
 *  gives conf.systemDrive, through normalizeFilePath(path) of tools.h; WAE
 *  the one of the collection). Only ASCII is compared without case — the
 *  prefixes and variables it recognises are ASCII, so the result is the one
 *  of towlower — and only an ASCII drive letter is put in upper case.
 */
#pragma once

#include <string>

/*! Normalises a file path: NT prefixes (`\??\`, `\\?\`), the kernel's
 *  `\SystemRoot\`, `SYSVOL\` (the ShimCache of Windows 8 and 8.1), system
 *  variables (`%windir%`, `%ProgramFiles%`…) expanded from \a systemDrive,
 *  surrounding quotes and spaces, drive letter in upper case. The case of
 *  the rest is kept: Windows keeps it, and so does the evidence.
 *  @param path the path as a source writes it
 *  @param systemDrive the examined installation's system drive, `C:`
 *  @return the normalised path, or an EMPTY string if it does not name a
 *          determinable local file: network share, relative path, variable
 *          specific to a user, or unknown variable */
std::wstring normalizeFilePath(std::wstring path, const std::wstring& systemDrive);

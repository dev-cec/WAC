/*! \file
 *  \brief Matching a name with a pattern where `*` stands for any run of
 *         characters and `?` for one: the filter of the raw folder reading
 *         (raw_hive.cpp), of the applications' traces table
 *         (application_traces.cpp) and of the web servers' Include masks
 *         (web_installations.cpp) — one function, where there were two.
 *
 *  A header of its own, inline and portable: the NTFS reader and the table
 *  both use it without depending on each other, and the table's test builds
 *  natively as well as under MinGW.
 */
#pragma once
#include <string>

/*! ASCII lower case: the names compared are NTFS names, whose accents Windows
 *  folds by a table no pattern here needs.
 *  @param c a character
 *  @return its lower case for A to Z, itself otherwise */
inline wchar_t wildcardFolded(wchar_t c) { return c >= L'A' && c <= L'Z' ? (wchar_t)(c + (L'a' - L'A')) : c; }

/*! Compares a name with a pattern, case-insensitively (ASCII). `*` stands for any
 *  run of characters, none included; `?` for exactly one; every other character
 *  for itself.
 *  Iterative: a forged name of any length costs at most pattern × name, never a
 *  deep recursion.
 *  @param pattern the pattern
 *  @param name the name
 *  @return whether it matches */
inline bool wildcardMatch(const std::wstring& pattern, const std::wstring& name) {
	size_t p = 0, n = 0, star = std::wstring::npos, resume = 0;
	while (n < name.size()) {
		if (p < pattern.size() && pattern[p] == L'*') { star = p++; resume = n; }
		else if (p < pattern.size() && (pattern[p] == L'?' || wildcardFolded(pattern[p]) == wildcardFolded(name[n]))) { ++p; ++n; }
		else if (star != std::wstring::npos) { p = star + 1; n = ++resume; }
		else return false;
	}
	while (p < pattern.size() && pattern[p] == L'*') ++p;
	return p == pattern.size();
}

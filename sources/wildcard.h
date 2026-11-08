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
#include <cwctype>
#include <string>
#include <vector>

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

/*! Compares a file name with a filter, as the raw folder reading keeps a file
 *  and the conversion finds it again: an entry starting with "." is an
 *  extension, one holding `*` or `?` a pattern ("connections*.txt"), any other a
 *  whole name ("Thumbs.db"). Extensions and whole names ignore case as Windows
 *  does (towlower), patterns in ASCII (wildcardMatch).
 *  @param name the file name
 *  @param filter the entries; empty keeps every name
 *  @return whether the name is kept */
inline bool nameMatchesFilter(const std::wstring& name, const std::vector<std::wstring>& filter) {
	if (filter.empty()) return true;
	auto same = [](const std::wstring& a, const std::wstring& b) {
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i)
			if (towlower(a[i]) != towlower(b[i])) return false;
		return true;
	};
	const size_t point = name.rfind(L'.');
	const std::wstring extension = point == std::wstring::npos ? std::wstring() : name.substr(point);
	for (const std::wstring& expected : filter)
		if (expected.find_first_of(L"*?") != std::wstring::npos ? wildcardMatch(expected, name)
		    : !expected.empty() && expected[0] == L'.' ? same(extension, expected) : same(name, expected)) return true;
	return false;
}

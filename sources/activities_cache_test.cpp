/*! \file
 *  \brief Checks the Timeline reader against Python's SQLite on a real
 *         Windows 10 ActivitiesCache.db, and against a truncated copy.
 *
 *  WHY THIS TEST. The reader converts every column by its declared type: a
 *  Unix time read as another unit, a GUID in the wrong byte order, a payload
 *  cut would give dates and identifiers that are valid and false. The
 *  reference is Python's own SQLite on the plaso project's Timeline database
 *  (activities_cache_fixtures.sh), each column converted by the rules of
 *  activities_cache.h written again there: every row must come back with the
 *  same columns and values, and none more. The local forms of the dates are
 *  left out — they depend on the examined machine's time zone, checked
 *  elsewhere (time_zone) — and their UTC form compared.
 *
 *  Usage: activities_cache_test `<folder of activities_cache_fixtures.sh>`
 *  Built by `build-windows.sh --test`; runs under Wine or on Windows.
 */
#include <windows.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include "activities_cache.h"
#include "tools.h"

AppliConf conf; //!< WAC's global configuration, which tools.cpp references

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the first failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 30) std::printf("  FAILED  %s\n", what.c_str());
}

/*! The members of an object that carry a value (an empty text or a null is
 *  no value: the writer leaves it out).
 *  @param o the object
 *  @return its members by name */
std::map<std::wstring, const Json*> valued(const Json& o) {
	std::map<std::wstring, const Json*> m;
	for (const auto& [name, value] : o.members())
		if (!value.isEmptyValue()) m[name] = &value;
	return m;
}

/*! @return true if two JSON values are the same, members in any order */
bool same(const Json& a, const Json& b) {
	if (a.kind() != b.kind()) return false;
	if (a.kind() == Json::Kind::Obj) {
		const auto ma = valued(a), mb = valued(b);
		if (ma.size() != mb.size()) return false;
		for (const auto& [name, value] : ma) {
			const auto other = mb.find(name);
			if (other == mb.end() || !same(*value, *other->second)) return false;
		}
		return true;
	}
	if (a.kind() == Json::Kind::Arr) {
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i)
			if (!same(a.members()[i].second, b.members()[i].second)) return false;
		return true;
	}
	return a.text() == b.text();
}

/*! A record as the reference writes it: its table and its columns, the
 *  local form of each date left out.
 *  @param a the record read by WAC
 *  @return the comparable object */
Json comparable(const TimelineActivity& a) {
	Json o = Json::obj();
	o.add(L"Table", Json::str(a.table));
	for (const auto& [name, value] : a.columns.members())
		if (!a.columns.find(name + L"Utc")) o.add(name, value);
	return o;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) { std::printf("usage: activities_cache_test <folder of activities_cache_fixtures.sh>\n"); return 2; }
	const std::wstring folder = argv[1];
	const std::wstring database = folder + L"\\ActivitiesCache.db";

	std::vector<Json> reference;
	std::ifstream ref(std::filesystem::path(folder + L"\\activities-reference.jsonl"), std::ios::binary);
	for (std::string text; std::getline(ref, text);) {
		Json record = Json::null();
		std::wstring error;
		check(Json::parse(decodeText(text, CP_UTF8), record, error), "reference: a line parses");
		reference.push_back(std::move(record));
	}
	check(reference.size() == 112, "reference: 112 records");

	std::vector<TimelineActivity> read;
	TimelineActivity base;
	base.path = L"C:\\Users\\x\\AppData\\Local\\ConnectedDevicesPlatform\\L.x\\ActivitiesCache.db";
	check(readActivitiesCache(database, base, read) == ERROR_SUCCESS, "the database opens");
	check(read.size() == reference.size(), "as many records as Python's SQLite reads: "
	      + std::to_string(read.size()) + " / " + std::to_string(reference.size()));
	size_t identical = 0;
	for (size_t i = 0; i < read.size() && i < reference.size(); ++i) {
		const Json mine = comparable(read[i]);
		if (same(mine, reference[i])) ++identical;
		else check(false, "record " + std::to_string(i) + " differs: " + encodeText(mine.dump()));
	}
	check(identical == reference.size(), "every record identical, column by column");
	size_t engaged = 0;
	for (const TimelineActivity& a : read) {
		const Json* payload = a.columns.find(L"Payload");
		const Json* type = payload ? payload->find(L"type") : nullptr;
		if (type && type->text() == L"UserEngaged" && a.columns.find(L"EndTimeUtc")) ++engaged;
	}
	check(engaged > 0, "focus time (UserEngaged) read with its start and end");

	// A truncated copy: whatever SQLite still reads, no crash, no invented row.
	const std::filesystem::path cut = std::filesystem::temp_directory_path() / L"wac_activities_cut.db";
	std::filesystem::copy_file(database, cut, std::filesystem::copy_options::overwrite_existing);
	std::filesystem::resize_file(cut, std::filesystem::file_size(cut) / 3);
	std::vector<TimelineActivity> partial;
	readActivitiesCache(cut.wstring(), base, partial);
	check(partial.size() <= reference.size(), "a truncated database: no more rows than the whole one");
	std::filesystem::remove(cut);

	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}

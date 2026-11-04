/*! \file
 *  \brief Logs in the W3C extended format (see w3c_log.h).
 */
#include "w3c_log.h"
#include "registry_common.h"
#include <algorithm>
#include <set>

namespace {

//! The words of a line, separated by spaces.
std::vector<std::wstring> words(const std::wstring& line) {
	std::vector<std::wstring> out;
	size_t i = 0;
	while (i < line.size()) {
		while (i < line.size() && line[i] == L' ') ++i;
		const size_t start = i;
		while (i < line.size() && line[i] != L' ') ++i;
		if (i > start) out.push_back(line.substr(start, i - start));
	}
	return out;
}

//! The JSON key of a field of "#Fields:".
std::wstring fieldKey(const std::wstring& field, const std::vector<W3cFieldKey>& keys) {
	for (const W3cFieldKey& k : keys)
		if (field == k.field) return k.key;
	return registryNameToJsonKey(field);
}

//! A value that is a decimal number, as a JSON number; anything else as text.
Json value(const std::wstring& text) {
	const bool digits = !text.empty() && text.size() < 19
	                    && text.find_first_not_of(L"0123456789") == std::wstring::npos;
	return digits ? Json::num(std::stoull(text)) : Json::str(text);
}

} // namespace

std::vector<W3cLogEntry> parseW3cLog(const std::wstring& text, const std::wstring& file,
                                     const std::vector<W3cFieldKey>& keys, W3cTime zone) {
	std::vector<W3cLogEntry> entries;
	std::vector<std::wstring> fields;
	const std::vector<std::wstring> lines = splitLines(text);
	for (size_t i = 0; i < lines.size(); ++i) {
		std::wstring line = lines[i];
		if (!line.empty() && line.back() == L'\r') line.pop_back();
		/* Windows leaves zeros in the file where it reopened it (the
		   firewall's logging switched back on): seen before the first line's
		   date. */
		line.erase(std::remove(line.begin(), line.end(), L'\0'), line.end());
		if (line.compare(0, 8, L"#Fields:") == 0) { fields = words(line.substr(8)); continue; }
		if (line.compare(0, 13, L"#Time Format:") == 0) {
			const std::vector<std::wstring> format = words(line.substr(13));
			const std::wstring named = format.size() == 1 ? toLower(format[0]) : L"";
			zone = named == L"local" ? W3cTime::Local : named == L"utc" ? W3cTime::Utc : W3cTime::Unknown;
			continue;
		}
		if (line.empty() || line[0] == L'#' || fields.empty()) continue;
		const std::vector<std::wstring> values = words(line);
		W3cLogEntry e;
		e.file = file;
		e.line = i + 1;
		e.zone = zone;
		std::wstring date, time;
		for (size_t f = 0; f < fields.size() && f < values.size(); ++f) {
			if (values[f] == L"-") continue;
			if (fields[f] == L"date") date = values[f];
			else if (fields[f] == L"time") time = values[f];
			else e.fields.emplace_back(fieldKey(fields[f], keys), values[f]);
		}
		if (!date.empty() && !time.empty()) {
			/* "2026-10-24" and "15:01:02": read as ISO 8601, which checks each
			   field; the instant obtained is the one written, in its zone. */
			FILETIME read;
			if (zone != W3cTime::Unknown && iso8601UtcToFiletime(date + L"T" + time + L"Z", read)) e.time = read;
			else e.timeAsStored = date + L" " + time;
		}
		entries.push_back(std::move(e));
	}
	return entries;
}

Json W3cLogEntry::toJson() const {
	Json o = Json::obj();
	if (time.dwLowDateTime || time.dwHighDateTime)
		addDate(o, L"Time", zone == W3cTime::Local ? suspectLocalToUtc(time) : time);
	o.add(L"TimeAsStored", Json::str(timeAsStored));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	/* "#Fields:" is written by whoever writes the log: a field named "File"
	   or twice the same would give two keys in one object, and a reader would
	   keep the forged one. Such a field stays, under OtherFields, by its name. */
	std::set<std::wstring> taken = { L"Time", L"TimeAsStored", L"File", L"Line" };
	Json others = Json::arr();
	for (const auto& [key, text] : fields) {
		if (taken.insert(key).second) { o.add(key, value(text)); continue; }
		Json other = Json::obj();
		other.add(L"Name", Json::str(key));
		other.add(L"Value", Json::str(text));
		others.push(std::move(other));
	}
	o.add(L"OtherFields", std::move(others));
	return o;
}

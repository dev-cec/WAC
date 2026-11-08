/*! \file
 *  \brief The applications' traces converted (see application_trace_files.h).
 */
#include "application_trace_files.h"
#include "consigne.h"
#include "group_policies.h"
#include "tools.h"
#include "whole_file.h"
#include "xml_light.h"
#include <filesystem>

namespace {

//! Largest file converted: a log past it is said, not read (the copy stays in the store).
const uintmax_t TRACE_FILE_MAX = 256ULL * 1024 * 1024;
//! Bytes looked at to tell a text from a binary.
const size_t TEXT_PROBE = 64 * 1024;
//! Deepest XML element written: a hostile nesting costs no more.
const unsigned XML_DEPTH_MAX = 64;

//! Days since 1970-01-01 of a civil date (proleptic Gregorian, H. Hinnant's algorithm).
long long daysFromCivil(int year, unsigned month, unsigned day) {
	year -= month <= 2;
	const long long era = (year >= 0 ? year : year - 399) / 400;
	const unsigned yearOfEra = static_cast<unsigned>(year - era * 400);
	const unsigned dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const unsigned dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
	return era * 146097 + static_cast<long long>(dayOfEra) - 719468;
}

//! The civil date of a count of days since 1970-01-01.
void civilFromDays(long long days, int& year, unsigned& month, unsigned& day) {
	days += 719468;
	const long long era = (days >= 0 ? days : days - 146096) / 146097;
	const unsigned dayOfEra = static_cast<unsigned>(days - era * 146097);
	const unsigned yearOfEra = (dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096) / 365;
	const unsigned dayOfYear = dayOfEra - (365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100);
	const unsigned monthIndex = (5 * dayOfYear + 2) / 153;
	day = dayOfYear - (153 * monthIndex + 2) / 5 + 1;
	month = monthIndex < 10 ? monthIndex + 3 : monthIndex - 9;
	year = static_cast<int>(yearOfEra + era * 400) + (month <= 2);
}

//! Days of a month.
unsigned daysInMonth(int year, unsigned month) {
	static const unsigned DAYS[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
	return DAYS[month - 1] + (month == 2 && leap ? 1 : 0);
}

//! Two digits, zero-padded.
std::wstring twoDigits(unsigned value) {
	return std::wstring(1, static_cast<wchar_t>(L'0' + value / 10)) + static_cast<wchar_t>(L'0' + value % 10);
}

//! Appends to a record, within TEXT_RECORD_MAX.
void appendBounded(TextRecord& record, const std::wstring& piece) {
	if (record.text.size() + piece.size() <= TEXT_RECORD_MAX) { record.text += piece; return; }
	record.text.append(piece, 0, TEXT_RECORD_MAX - record.text.size());
	record.truncated = true;
}

//! An XML element as JSON, its secrets left out, at most XML_DEPTH_MAX levels.
Json xmlElement(const XmlNode& node, unsigned depth, bool& hasPassword) {
	Json element = Json::obj();
	element.add(L"Name", Json::str(node.name));
	Json attributes = Json::obj();
	for (const auto& [name, value] : node.attributes) {
		if (isPasswordValue(name)) { hasPassword = true; continue; }
		attributes.add(name, Json::str(value));
	}
	element.add(L"Attributes", std::move(attributes));
	element.add(L"Text", Json::str(node.text));
	if (depth < XML_DEPTH_MAX) {
		Json children = Json::arr();
		for (const std::unique_ptr<XmlNode>& child : node.children) {
			if (isPasswordValue(child->name)) { hasPassword = true; continue; }
			children.push(xmlElement(*child, depth + 1, hasPassword));
		}
		element.add(L"Children", std::move(children));
	}
	return element;
}

//! A JSON value, its members named like a secret left out (its depth bounded by Json::parse).
Json withoutSecrets(const Json& value, bool& hasPassword) {
	if (value.kind() != Json::Kind::Obj && value.kind() != Json::Kind::Arr) return value;
	Json copy = value.kind() == Json::Kind::Obj ? Json::obj() : Json::arr();
	for (const auto& [key, member] : value.members()) {
		if (value.kind() == Json::Kind::Arr) { copy.push(withoutSecrets(member, hasPassword)); continue; }
		if (isPasswordValue(key)) { hasPassword = true; continue; }
		copy.add(key, withoutSecrets(member, hasPassword));
	}
	return copy;
}

//! The extension of a name, in lower case, with its dot; empty without one.
std::wstring extensionOf(const std::wstring& name) {
	const size_t point = name.rfind(L'.');
	return point == std::wstring::npos ? std::wstring() : toLower(name.substr(point));
}

//! Whether an extension is one of a list.
bool among(const std::wstring& extension, std::initializer_list<const wchar_t*> list) {
	for (const wchar_t* each : list) if (extension == each) return true;
	return false;
}

} // namespace

bool leadingTime(const std::wstring& line, WrittenTime& time) {
	size_t i = 0;
	while (i < line.size() && (line[i] == L' ' || line[i] == L'\t')) ++i;
	if (i < line.size() && (line[i] == L'[' || line[i] == L'<')) ++i;
	const size_t start = i;
	auto number = [&](size_t count, unsigned& value) {
		if (i + count > line.size()) return false;
		value = 0;
		for (size_t k = 0; k < count; ++k) {
			const wchar_t c = line[i + k];
			if (c < L'0' || c > L'9') return false;
			value = value * 10 + static_cast<unsigned>(c - L'0');
		}
		i += count;
		return true;
	};
	auto separator = [&](std::initializer_list<wchar_t> allowed, wchar_t& found) {
		if (i >= line.size()) return false;
		for (wchar_t c : allowed) if (line[i] == c) { found = c; ++i; return true; }
		return false;
	};
	unsigned year, month, day, hour, minute, second;
	wchar_t dateSeparator = 0, other = 0;
	if (!number(4, year) || !separator({ L'-', L'/', L'.' }, dateSeparator) || !number(2, month)
	    || !separator({ dateSeparator }, other) || !number(2, day) || !separator({ L' ', L'T' }, other)
	    || !number(2, hour) || !separator({ L':' }, other) || !number(2, minute) || !separator({ L':' }, other)
	    || !number(2, second)) return false;
	if (year < 1601 || year > 9999 || month < 1 || month > 12 || day < 1 || day > daysInMonth(static_cast<int>(year), month)
	    || hour > 23 || minute > 59 || second > 59) return false;
	std::wstring fraction;
	if (i + 1 < line.size() && (line[i] == L'.' || line[i] == L',') && line[i + 1] >= L'0' && line[i + 1] <= L'9') {
		size_t end = i + 1;
		while (end < line.size() && end - i - 1 < 9 && line[end] >= L'0' && line[end] <= L'9') ++end;
		fraction = line.substr(i + 1, end - i - 1);
		i = end;
	}
	bool hasOffset = false;
	long long offsetMinutes = 0;
	if (i < line.size() && line[i] == L'Z') { hasOffset = true; ++i; }
	else if (i < line.size() && (line[i] == L'+' || line[i] == L'-')) {
		const size_t signAt = i++;
		unsigned hours = 0, minutes = 0;
		wchar_t colon = 0;
		if (number(2, hours) && (separator({ L':' }, colon), number(2, minutes)) && hours <= 14 && minutes <= 59) {
			hasOffset = true;
			offsetMinutes = (line[signAt] == L'-' ? -1 : 1) * static_cast<long long>(hours * 60 + minutes);
		}
		else i = signAt;   // not an offset: the time ends before the sign
	}
	time.asWritten = line.substr(start, i - start);
	time.utc.clear();
	if (hasOffset) {
		const long long seconds = daysFromCivil(static_cast<int>(year), month, day) * 86400LL
		                          + hour * 3600LL + minute * 60LL + second - offsetMinutes * 60;
		long long days = seconds / 86400, rest = seconds % 86400;
		if (rest < 0) { rest += 86400; --days; }
		int y = 0;
		unsigned m = 0, d = 0;
		civilFromDays(days, y, m, d);
		time.utc = std::to_wstring(y) + L"-" + twoDigits(m) + L"-" + twoDigits(d) + L"T" + twoDigits(static_cast<unsigned>(rest / 3600))
		           + L":" + twoDigits(static_cast<unsigned>(rest % 3600 / 60)) + L":" + twoDigits(static_cast<unsigned>(rest % 60))
		           + (fraction.empty() ? L"" : L"." + fraction) + L"Z";
	}
	return true;
}

std::vector<TextRecord> textRecords(const std::wstring& text) {
	std::vector<TextRecord> records;
	size_t number = 0, position = 0;
	while (position < text.size()) {
		const size_t end = text.find(L'\n', position);
		std::wstring line = text.substr(position, end == std::wstring::npos ? std::wstring::npos : end - position);
		position = end == std::wstring::npos ? text.size() : end + 1;
		++number;
		if (!line.empty() && line.back() == L'\r') line.pop_back();
		if (line.find_first_not_of(L" \t") == std::wstring::npos) continue;
		WrittenTime time;
		const bool dated = leadingTime(line, time);
		if (!dated && !records.empty() && !records.back().time.asWritten.empty()) {
			appendBounded(records.back(), L"\n" + line);
			continue;
		}
		TextRecord record;
		record.line = number;
		record.time = time;
		appendBounded(record, line);
		records.push_back(std::move(record));
	}
	return records;
}

TraceFormat traceFormatOf(const std::wstring& name, const std::string& bytes) {
	const std::wstring extension = extensionOf(name);
	if (among(extension, { L".db", L".db-wal", L".db-shm", L".sqlite", L".sqlite3", L".sqlite-wal", L".sqlite-shm",
	                       L".sqlite3-wal", L".sqlite3-shm", L".dbx", L".edb", L".ldb", L".mdb" })) return TraceFormat::Database;
	if (among(extension, { L".dmp", L".hve", L".sdb", L".etl", L".bin", L".dat", L".xel", L".trc", L".png", L".jpg",
	                       L".evtx", L".pf", L".dpapi", L".snt", L".vhdx", L".chk", L".jfm" })) return TraceFormat::Binary;
	const bool utf16 = bytes.size() >= 2 && static_cast<unsigned char>(bytes[0]) == 0xFF && static_cast<unsigned char>(bytes[1]) == 0xFE;
	if (!utf16) {
		size_t controls = 0;
		const size_t probe = bytes.size() < TEXT_PROBE ? bytes.size() : TEXT_PROBE;
		for (size_t i = 0; i < probe; ++i) {
			const unsigned char c = static_cast<unsigned char>(bytes[i]);
			if (c == 0) return TraceFormat::Binary;
			if (c < 0x20 && c != '\t' && c != '\r' && c != '\n' && c != '\f') ++controls;
		}
		if (controls * 100 > probe) return TraceFormat::Binary;
	}
	if (among(extension, { L".xml", L".xml~", L".xml-prev", L".vbox", L".vbox-prev", L".config" })) return TraceFormat::Xml;
	if (extension == L".json") return TraceFormat::Json;
	if (among(extension, { L".ini", L".inf", L".conf", L".cfg", L".toml" })) return TraceFormat::Ini;
	return TraceFormat::Text;
}

Json structuredContent(TraceFormat format, const std::wstring& text, bool& hasPassword) {
	if (format == TraceFormat::Xml) {
		const std::unique_ptr<XmlNode> root = xmlParse(text, true);
		return root ? xmlElement(*root, 0, hasPassword) : Json::null();
	}
	if (format == TraceFormat::Json) {
		Json value = Json::null();
		std::wstring error;
		return Json::parse(text, value, error) ? withoutSecrets(value, hasPassword) : Json::null();
	}
	if (format != TraceFormat::Ini) return Json::null();
	Json sections = Json::arr();
	for (const auto& [name, values] : parseIniText(text)) {
		Json section = Json::obj(), entries = Json::arr();
		section.add(L"Name", Json::str(name));
		for (const auto& [key, value] : values) {
			if (isPasswordValue(key)) { hasPassword = true; continue; }
			Json entry = Json::obj();
			entry.add(L"Name", Json::str(key));
			entry.add(L"Value", Json::str(value));
			entries.push(std::move(entry));
		}
		section.add(L"Values", std::move(entries));
		sections.push(std::move(section));
	}
	return sections;
}

HRESULT ApplicationTraceFiles::getData() {
	for (const auto& [path, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty()) continue;
		const TraceOwner owner = traceOwnerOf(exhibit.sourcePath);
		if (owner.group != &group_
		    || !traceProductWanted(conf.traceProducts, group_.key, owner.product->key, owner.product->onByDefault)) continue;
		const std::wstring product = owner.product->name;
		auto notConverted = [&](const wchar_t* reason) {
			Json row = Json::obj();
			row.add(L"Product", Json::str(product));
			row.add(L"File", Json::str(exhibit.sourcePath));
			row.add(L"Converted", Json::boolean(false));
			row.add(L"Reason", Json::str(reason));
			rows_.push(std::move(row));
		};
		std::error_code ec;
		const uintmax_t size = std::filesystem::file_size(std::filesystem::path(exhibit.workingFile), ec);
		if (ec) { notConverted(L"unreadable copy"); continue; }
		if (size > TRACE_FILE_MAX) { notConverted(L"larger than 256 MiB: kept in the exhibit store, not converted"); continue; }
		std::string bytes;
		if (!readWholeFile(std::filesystem::path(exhibit.workingFile), TRACE_FILE_MAX, bytes)) { notConverted(L"unreadable copy"); continue; }
		const std::wstring name = std::filesystem::path(exhibit.sourcePath).filename().wstring();
		const TraceFormat format = traceFormatOf(name, bytes);
		if (format == TraceFormat::Database) { notConverted(L"database: kept in the exhibit store, not converted"); continue; }
		if (format == TraceFormat::Binary) { notConverted(L"binary or encrypted: kept in the exhibit store, not converted"); continue; }
		const std::wstring text = decodeTextFile(bytes);
		if (format != TraceFormat::Text) {
			bool hasPassword = false;
			Json content = structuredContent(format, text, hasPassword);
			if (content.kind() != Json::Kind::Null) {
				Json row = Json::obj();
				row.add(L"Product", Json::str(product));
				row.add(L"File", Json::str(exhibit.sourcePath));
				row.add(L"Format", Json::str(format == TraceFormat::Xml ? L"XML" : format == TraceFormat::Json ? L"JSON" : L"INI"));
				if (hasPassword) row.add(L"HasPassword", Json::boolean(true));
				row.add(L"Content", std::move(content));
				rows_.push(std::move(row));
				continue;
			}
			log(2, L"🔥Malformed structured file, read as text: " + exhibit.sourcePath);
		}
		for (const TextRecord& record : textRecords(text)) {
			Json row = Json::obj();
			row.add(L"Product", Json::str(product));
			row.add(L"File", Json::str(exhibit.sourcePath));
			row.add(L"Line", Json::num(static_cast<unsigned long long>(record.line)));
			row.add(L"TimeUtc", Json::str(record.time.utc));
			row.add(L"TimeAsWritten", Json::str(record.time.asWritten));
			row.add(L"Text", Json::str(record.text));
			if (record.truncated) row.add(L"Truncated", Json::boolean(true));
			rows_.push(std::move(row));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT ApplicationTraceFiles::toJson() { return writeJsonFile(group_.key + ".json", rows_); }
void ApplicationTraceFiles::clear() { rows_ = Json::arr(); }

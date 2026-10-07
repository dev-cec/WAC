/*! \file
 *  \brief Windows Error Reporting (see error_reports.h).
 */
#include "error_reports.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>
#include <map>

namespace {

//! A report is a few kilobytes; beyond this, the file is not read.
const uintmax_t REPORT_MAX = 4 * 1024 * 1024;

//! The keys given their own field, JSON name first: the most read ones.
const std::pair<const wchar_t*, const wchar_t*> NAMED_KEYS[] = {
	{ L"EventType", L"EventType" }, { L"FriendlyEventName", L"FriendlyEventName" },
	{ L"ReportType", L"ReportType" }, { L"AppName", L"AppName" }, { L"AppPath", L"AppPath" },
	{ L"NsAppName", L"NsAppName" }, { L"OriginalFilename", L"OriginalFilename" },
	{ L"ReportIdentifier", L"ReportIdentifier" },
};

//! Decodes the file: UTF-16LE with its byte-order mark, as Windows writes it; UTF-8 otherwise.
std::wstring decodeReport(const std::string& bytes) {
	if (bytes.size() >= 2 && (uint8_t)bytes[0] == 0xFF && (uint8_t)bytes[1] == 0xFE)
		return readWideZ(reinterpret_cast<const BYTE*>(bytes.data()), bytes.size(), 2);
	return decodeText(bytes, CP_UTF8);
}

} // namespace

bool parseErrorReport(const std::wstring& text, ErrorReport& report) {
	std::map<unsigned, std::pair<std::wstring, std::wstring>> signature;
	for (const std::wstring& line : splitLines(text)) {
		const size_t equal = line.find(L'=');
		if (equal == std::wstring::npos || equal == 0) continue;
		const std::wstring key = line.substr(0, equal), value = line.substr(equal + 1);
		report.values.emplace_back(key, value);
		if (key == L"EventTime") {
			// A FILETIME in decimal; anything else is not a date and is left in `values` only.
			if (!value.empty() && value.size() <= 20 && value.find_first_not_of(L"0123456789") == std::wstring::npos) {
				const unsigned long long t = std::stoull(value);
				report.eventTimeUtc = filetimeFromTicks(t);
			}
		}
		// Sig[n].Name / Sig[n].Value, n below 100.
		else if (key.compare(0, 4, L"Sig[") == 0) {
			const size_t close = key.find(L"].");
			if (close == std::wstring::npos || close <= 4 || close > 6) continue;
			const std::wstring digits = key.substr(4, close - 4);
			if (digits.find_first_not_of(L"0123456789") != std::wstring::npos) continue;
			const unsigned n = (unsigned)std::stoul(digits);
			const std::wstring part = key.substr(close + 2);
			if (part == L"Name") signature[n].first = value;
			else if (part == L"Value") signature[n].second = value;
		}
	}
	for (auto& [n, nameValue] : signature) report.signature.push_back(nameValue);
	return !report.values.empty();
}

Json ErrorReport::toJson() const {
	Json o = Json::obj();
	for (const auto& [key, name] : NAMED_KEYS)
		for (const auto& [k, v] : values)
			if (k == key) { o.add(name, Json::str(v)); break; }
	addDate(o, L"EventTime", eventTimeUtc);
	Json sig = Json::arr();
	for (const auto& [name, value] : signature) {
		Json s = Json::obj();
		s.add(L"Name", Json::str(name));
		s.add(L"Value", Json::str(value));
		sig.push(std::move(s));
	}
	o.add(L"Signature", std::move(sig));
	o.add(L"File", Json::str(file));
	/* Every value, as Name/Value pairs: the report's keys ("DynamicSig[1].Name",
	   "Response.BucketId") are not JSON key names — PascalCase, one name per
	   concept — and may repeat. */
	Json all = Json::arr();
	for (const auto& [k, v] : values) {
		Json pair = Json::obj();
		pair.add(L"Name", Json::str(k));
		pair.add(L"Value", Json::str(v));
		all.push(std::move(pair));
	}
	o.add(L"Values", std::move(all));
	return o;
}

HRESULT ErrorReports::getData() {
	log(0, L"ℹ️Error reports :");
	// Through the manifest: the machine's reports and every profile's, on whichever volume.
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty() || key.size() < 11 || key.compare(key.size() - 11, 11, L"\\report.wer") != 0
		    || key.find(L"\\microsoft\\windows\\wer\\") == std::wstring::npos) continue;
		std::error_code ec;
		const uintmax_t size = std::filesystem::file_size(exhibit.workingFile, ec);
		if (ec || size > REPORT_MAX) {
			log(2, L"🔥Error report not read (unreadable or larger than 4 MiB): " + exhibit.sourcePath);
			continue;
		}
		std::ifstream in(std::filesystem::path(exhibit.workingFile), std::ios::binary);
		const std::string bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		ErrorReport report;
		report.file = exhibit.sourcePath;
		if (!parseErrorReport(decodeReport(bytes), report)) {
			log(2, L"🔥Error report without any value: " + exhibit.sourcePath);
			continue;
		}
		reports_.push_back(std::move(report));
	}
	return ERROR_SUCCESS;
}

HRESULT ErrorReports::toJson() {
	Json list = Json::arr();
	for (const ErrorReport& r : reports_) list.push(r.toJson());
	return writeJsonFile("error_reports.json", list);
}

void ErrorReports::clear() {
	reports_.clear();
}

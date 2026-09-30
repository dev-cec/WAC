/*! \file
 *  \brief Snapshot of the live state (see live_snapshot.h).
 */
#include "live_snapshot.h"
#include "tools.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>
#include <sstream>

std::wstring liveSnapshotFolder() {
	return exhibitStoreFolder() + L"\\live";
}

HRESULT writeLiveSnapshot(const std::string& name, const Json& value, const std::wstring& what) {
	const std::wstring path = liveSnapshotFolder() + L"\\" + decodeText(name, CP_UTF8);
	// Not a path on a volume: no letter, so that it is not counted among the volumes read.
	return ExhibitStoreProduce(path, encodeText(value.dump(0)), L"live observation: " + what,
	                           L"Live observation by WAC, recorded as read (JSON, UTF-8)");
}

HRESULT readLiveSnapshot(const std::string& name, Json& value) {
	const std::wstring path = liveSnapshotFolder() + L"\\" + decodeText(name, CP_UTF8);
	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) return ERROR_FILE_NOT_FOUND;
	std::stringstream buffer;
	buffer << f.rdbuf();
	std::wstring error;
	if (!Json::parse(decodeText(buffer.str(), CP_UTF8), value, error)) {
		log(2, L"🔥Live snapshot unreadable: " + path + L" (" + error + L")");
		return ERROR_INVALID_DATA;
	}
	return ERROR_SUCCESS;
}

bool snapshotInteger(const Json& object, const wchar_t* key, long long& out) {
	const Json* v = object.find(key);
	return v && snapshotInteger(*v, out);
}

bool snapshotInteger(const Json& value, long long& out) {
	if (value.kind() != Json::Kind::Num) return false;
	const std::wstring& digits = value.text();
	// Integers only: a fraction or an exponent is not what WAC wrote.
	if (digits.empty() || digits.find_first_not_of(L"-0123456789") != std::wstring::npos) return false;
	try {
		size_t used = 0;
		const long long value = std::stoll(digits, &used);
		if (used != digits.size()) return false;
		out = value;
		return true;
	}
	catch (...) {
		return false;   // out of the range of a long long
	}
}

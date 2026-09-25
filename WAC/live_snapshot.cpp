/*! \file
 *  \brief Snapshot of the live state (see live_snapshot.h).
 */
#include "live_snapshot.h"
#include "tools.h"
#include "consigne.h"
#include "raw_hive.h"
#include "quickdigest5.h"
#include "sha.h"
#include <filesystem>
#include <fstream>
#include <sstream>

std::wstring liveSnapshotFolder() {
	return exhibitStoreFolder() + L"\\live";
}

HRESULT writeLiveSnapshot(const std::string& name, const Json& value, const std::wstring& what) {
	std::error_code ec;
	std::filesystem::create_directories(liveSnapshotFolder(), ec);
	const std::wstring path = liveSnapshotFolder() + L"\\" + decodeText(name, CP_UTF8);
	const std::string bytes = encodeText(value.dump(0));
	{
		// Binary mode: the fingerprints are those of the bytes on the medium.
		std::ofstream f(std::filesystem::path(path), std::ios::binary);
		if (!f) {
			log(2, L"🔥Live snapshot not written: " + path);
			return E_FAIL;
		}
		f.write(bytes.data(), (std::streamsize)bytes.size());
		if (!f) {
			log(2, L"🔥Live snapshot incompletely written: " + path);
			return E_FAIL;
		}
	}
	RawHiveExtraction e;
	// Not a path on a volume: no letter, so that it is not counted among the volumes read.
	e.volumePath = L"live observation: " + what;
	e.outputPath = path;
	e.result = ERROR_SUCCESS;
	Md5Stream md5;
	Sha1Stream sha1;
	Sha256Stream sha256;
	md5.update(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
	sha1.update(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
	sha256.update(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
	e.fingerprints.md5 = md5.hexDigest();
	e.fingerprints.sha1 = sha1.hexDigest();
	e.fingerprints.sha256 = sha256.hexDigest();
	e.fingerprints.bytes = bytes.size();
	e.fingerprints.declaredSize = bytes.size();
	e.fingerprints.validDataLength = bytes.size();
	e.fingerprints.resident = false;
	FILETIME now = { 0, 0 };
	GetSystemTimeAsFileTime(&now);
	e.fingerprints.extractedUtc = ((uint64_t)now.dwHighDateTime << 32) | now.dwLowDateTime;
	ExhibitStoreAdd({ e }, L"Live observation by WAC, recorded as read (JSON, UTF-8)");
	return ERROR_SUCCESS;
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
	if (!v || v->kind() != Json::Kind::Num) return false;
	const std::wstring& digits = v->text();
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

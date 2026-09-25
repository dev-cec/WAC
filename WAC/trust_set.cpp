/*! \file
 *  \brief The trust set, read and checked at the collection (see trust_set.h).
 */
#include "trust_set.h"
#include "json.h"
#include "sha.h"
#include "tools.h"
#include <filesystem>
#include <fstream>
#include <mutex>

namespace {

const size_t SET_FILE_MAX = 256u << 20;   //!< beyond: refused, the largest file of a set is ~33 MiB

/*! Reads a file of the set, bounded.
 *  @return false if absent, unreadable, or larger than allowed */
bool readSetFile(const std::filesystem::path& path, std::vector<uint8_t>& bytes) {
	std::error_code ec;
	const uintmax_t size = std::filesystem::file_size(path, ec);
	if (ec || size > SET_FILE_MAX) return false;
	std::ifstream in(path, std::ios::binary);
	bytes.resize((size_t)size);
	in.read((char*)bytes.data(), (std::streamsize)size);
	return (bool)in;
}

//! A file of the set, read as UTF-8 JSON. @return false if it is not
bool readSetJson(const std::filesystem::path& path, Json& value) {
	std::vector<uint8_t> bytes;
	std::wstring error;
	return readSetFile(path, bytes)
	    && Json::parse(decodeText(std::string(bytes.begin(), bytes.end()), CP_UTF8), value, error);
}

//! The text of a member, or "" if absent.
std::wstring textOf(const Json& object, const wchar_t* key) {
	const Json* member = object.find(key);
	return member ? member->text() : std::wstring();
}

/*! Every file the manifest lists must have its size and SHA-256.
 *  @return false with `reason` at the first that differs */
bool checkFiles(const std::filesystem::path& folder, const Json& manifest, std::string& reason) {
	const Json* files = manifest.find(L"Files");
	if (!files || files->kind() != Json::Kind::Arr || files->members().empty()) {
		reason = "manifest without its list of files";
		return false;
	}
	for (const auto& [unused, file] : files->members()) {
		const std::wstring path = textOf(file, L"Path");
		// Relative, and within the set: a manifest could name any file of the key.
		if (path.empty() || path.find(L"..") != std::wstring::npos || path.find(L':') != std::wstring::npos
		    || path[0] == L'\\' || path[0] == L'/') {
			reason = "manifest naming a file outside the set";
			return false;
		}
		std::vector<uint8_t> bytes;
		if (!readSetFile(folder / path, bytes)) { reason = "file missing: " + encodeText(path); return false; }
		uint8_t digest[32];
		sha256Bytes(bytes.data(), bytes.size(), digest);
		if (toHexadecimal(digest, sizeof(digest)) != textOf(file, L"SHA256")) {
			reason = "file altered since --update-trust: " + encodeText(path);
			return false;
		}
	}
	return true;
}

/*! The two Microsoft lists, their signatures checked, and each root
 *  certificate against the SHA-1 the signed list names.
 *  @return false with `reason` otherwise */
bool loadLists(const std::filesystem::path& folder, TrustSet& set) {
	std::vector<uint8_t> bytes;
	if (!readSetFile(folder / "authroot.stl", bytes)) { set.reason = "authroot.stl missing"; return false; }
	set.roots = ReadTrustList(bytes.data(), bytes.size());
	if (!set.roots.valid || set.roots.identifier != 3) { set.reason = "authroot.stl refused: " + set.roots.reason; return false; }
	if (!readSetFile(folder / "disallowedcert.stl", bytes)) { set.reason = "disallowedcert.stl missing"; return false; }
	set.disallowed = ReadTrustList(bytes.data(), bytes.size());
	if (!set.disallowed.valid || set.disallowed.identifier != 15) {
		set.reason = "disallowedcert.stl refused: " + set.disallowed.reason;
		return false;
	}
	for (const TrustListEntry& entry : set.roots.entries) {
		const std::wstring name = toHexadecimal((const uint8_t*)entry.identifier.data(), entry.identifier.size());
		// A root --update-trust could not obtain is absent: a chain to it cannot be cleared.
		if (!readSetFile(folder / "roots" / (name + L".crt"), bytes)) continue;
		if (FindInTrustList(set.roots, bytes.data(), bytes.size()) != &entry) {
			set.reason = "root certificate not the one authroot.stl names: " + encodeText(name);
			return false;
		}
		set.rootCertificates[entry.identifier] = bytes;
	}
	if (set.rootCertificates.empty()) { set.reason = "no root certificate"; return false; }
	return true;
}

/*! The lists that are not signed: vulnerable drivers, revocation. Absent,
 *  they are recorded as missing — the collection then cannot clear what
 *  they would have cleared.
 *  @return false with `reason` if present and unreadable */
bool loadUnsignedLists(const std::filesystem::path& folder, TrustSet& set) {
	Json drivers = Json::null();
	if (!readSetJson(folder / "vulnerable-drivers.json", drivers)) { set.reason = "vulnerable-drivers.json unreadable"; return false; }
	if (const Json* hashes = drivers.find(L"Hashes"))
		for (const auto& [unused, h] : hashes->members()) set.driverHashes.insert(textOf(h, L"Hash"));
	if (const Json* missing = drivers.find(L"ListsMissing"))
		for (const auto& [unused, m] : missing->members()) set.driverListsMissing.push_back(textOf(m, L"List"));
	Json revocation = Json::null();
	std::error_code ec;
	if (!std::filesystem::exists(folder / "revocation.json", ec)) return true;   // CCADB not obtained
	if (!readSetJson(folder / "revocation.json", revocation)) { set.reason = "revocation.json unreadable"; return false; }
	if (const Json* revoked = revocation.find(L"RevokedAuthorities"))
		for (const auto& [unused, a] : revoked->members()) set.revokedAuthorities.insert(textOf(a, L"SHA256"));
	if (const Json* crls = revocation.find(L"Crls"))
		for (const auto& [unused, crl] : crls->members())
			if (const Json* issuers = crl.find(L"IssuedBy"))
				for (const auto& [unused2, issuer] : issuers->members())
					set.crlsByAuthority[textOf(issuer, L"SHA256")].push_back(textOf(crl, L"File"));
	return true;
}

} // namespace

std::wstring DefaultTrustFolder() {
	wchar_t module[MAX_PATH];
	const DWORD size = GetModuleFileNameW(nullptr, module, MAX_PATH);
	if (size == 0 || size == MAX_PATH) return L"trust";
	return std::filesystem::path(module).parent_path().wstring() + L"\\trust";
}

const TrustSet& CollectionTrustSet() {
	static TrustSet set;
	static std::once_flag loaded;
	std::call_once(loaded, [] { set = LoadTrustSet(DefaultTrustFolder()); });
	return set;
}

TrustSet LoadTrustSet(const std::wstring& folder) {
	TrustSet set;
	set.folder = folder;
	const std::filesystem::path root(folder);
	std::vector<uint8_t> manifestBytes;
	if (!readSetFile(root / "trust-manifest.json", manifestBytes)) {
		set.reason = "absent: --update-trust was not run before the collection, or did not complete";
		return set;
	}
	uint8_t digest[32];
	sha256Bytes(manifestBytes.data(), manifestBytes.size(), digest);
	set.manifestSha256 = toHexadecimal(digest, sizeof(digest));
	Json manifest = Json::null();
	std::wstring error;
	if (!Json::parse(decodeText(std::string(manifestBytes.begin(), manifestBytes.end()), CP_UTF8), manifest, error)) {
		set.reason = "manifest unreadable";
		return set;
	}
	set.createdUtc = textOf(manifest, L"CreatedUtc");
	if (!checkFiles(root, manifest, set.reason) || !loadLists(root, set) || !loadUnsignedLists(root, set)) {
		set = TrustSet{ false, set.folder, set.reason, set.createdUtc, set.manifestSha256 };   // nothing half-loaded
		return set;
	}
	set.usable = true;
	return set;
}

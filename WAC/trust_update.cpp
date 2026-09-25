/*! \file
 *  \brief --update-trust (see trust_update.h).
 */
#include "trust_update.h"
#include "authenticode.h"
#include "cab.h"
#include "http_client.h"
#include "json.h"
#include "sha.h"
#include "tools.h"
#include <filesystem>
#include <fstream>
#include <atomic>
#include <map>
#include <thread>

namespace {

//! Microsoft's distribution point, the one Windows' own automatic update of the roots uses.
const std::wstring TRUSTED_ROOTS_URL = L"http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/";
const size_t CABINET_MAX = 16 * 1024 * 1024;   //!< a trust list cabinet is ~100 KiB
const size_t CERTIFICATE_MAX = 64 * 1024;      //!< a root certificate is ~1.5 KiB
const char MANIFEST[] = "trust-manifest.json";
const unsigned DOWNLOAD_THREADS = 8;           //!< requests at once: few enough not to burden the server

//! A file of the set, kept in memory until everything is checked.
struct SetFile {
	std::wstring path;               //!< relative to the set's folder
	std::vector<uint8_t> content;
};

//! A checked trust list, with where it came from.
struct Source {
	std::wstring name, url;
	std::vector<uint8_t> list;       //!< the .stl, as extracted
	TrustList parsed;
};

/*! Downloads a cabinet, extracts the list it carries, checks the list's
 *  signature and kind.
 *  @return false with `reason` if any step fails */
bool fetchList(const HttpClient& http, const std::wstring& cabinet, const std::string& listName,
               unsigned identifier, Source& source, std::string& reason) {
	source.url = TRUSTED_ROOTS_URL + cabinet;
	source.name = decodeText(listName, CP_UTF8);
	std::vector<uint8_t> bytes;
	if (!http.get(source.url, bytes, CABINET_MAX, reason)) return false;
	std::vector<CabFile> files;
	if (!CabExtract(bytes, files, reason)) { reason = "cabinet unreadable: " + reason; return false; }
	for (CabFile& file : files)
		if (_stricmp(file.name.c_str(), listName.c_str()) == 0) source.list = std::move(file.content);
	if (source.list.empty()) { reason = "cabinet without " + listName; return false; }
	source.parsed = ReadTrustList(source.list.data(), source.list.size());
	if (!source.parsed.valid) { reason = listName + " refused: " + source.parsed.reason; return false; }
	if (source.parsed.identifier != identifier) { reason = listName + " of an unexpected kind"; return false; }
	return true;
}

//! The identifier of an entry of authroot.stl, the SHA-1 of the root, in uppercase hexadecimal.
std::wstring thumbprint(const TrustListEntry& entry) {
	return toHexadecimal((const uint8_t*)entry.identifier.data(), entry.identifier.size());
}

/*! Downloads every root authroot.stl names; each must be the certificate
 *  the signed list names — FindInTrustList by its SHA-1. Several requests at
 *  once: one after the other, the 562 roots took 5 min 20 s, each waiting
 *  about 0.6 s on the server.
 *  @param missing receives the roots not obtained, with why
 *  @return the certificates, in the list's order */
std::vector<SetFile> fetchRoots(const HttpClient& http, const TrustList& roots,
                                std::map<std::wstring, std::string>& missing) {
	const size_t count = roots.entries.size();
	std::vector<SetFile> slots(count);
	std::vector<std::string> reasons(count);
	std::atomic<size_t> next{ 0 }, done{ 0 };
	auto worker = [&]() {
		for (size_t k = next++; k < count; k = next++) {
			const TrustListEntry& entry = roots.entries[k];
			const std::wstring name = thumbprint(entry);
			std::vector<uint8_t> certificate;
			if (http.get(TRUSTED_ROOTS_URL + name + L".crt", certificate, CERTIFICATE_MAX, reasons[k])) {
				if (FindInTrustList(roots, certificate.data(), certificate.size()) == &entry)
					slots[k] = { L"roots\\" + name + L".crt", std::move(certificate) };
				else
					reasons[k] = "not the certificate authroot.stl names: SHA-1 differs";
			}
			if (++done % 50 == 0) wprintf(L"\r - Root certificates : %zu / %zu", done.load(), count);
		}
	};
	std::vector<std::thread> threads;
	for (unsigned t = 0; t < DOWNLOAD_THREADS; ++t) threads.emplace_back(worker);
	for (std::thread& t : threads) t.join();
	std::vector<SetFile> files;
	for (size_t k = 0; k < count; ++k) {
		if (!slots[k].content.empty()) files.push_back(std::move(slots[k]));
		else missing[thumbprint(roots.entries[k])] = reasons[k];
	}
	wprintf(L"\r - Root certificates : %zu / %zu, %zu obtained\n", count, count, files.size());
	return files;
}

/*! roots.pem: the roots trusted for code signing, and not distrusted
 *  (property 104), for osslsigncode and openssl. A distrusted root may still
 *  validate a signature time-stamped before its date: only WAC's check
 *  applies that rule, openssl cannot — it is left out here. */
SetFile rootsPem(const TrustList& roots, const std::vector<SetFile>& certificates) {
	SetFile pem{ L"roots.pem", {} };
	for (const SetFile& file : certificates) {
		const TrustListEntry* entry = FindInTrustList(roots, file.content.data(), file.content.size());
		if (!entry || entry->codeSigningExcluded || entry->distrusted) continue;
		const std::string text = "# " + encodeText(thumbprint(*entry)) + "\n-----BEGIN CERTIFICATE-----\n"
		                       + EncodeBase64(file.content.data(), file.content.size(), 64)
		                       + "-----END CERTIFICATE-----\n";
		pem.content.insert(pem.content.end(), text.begin(), text.end());
	}
	return pem;
}

//! A FILETIME count to ISO 8601 UTC.
std::wstring isoUtc(uint64_t filetime) {
	FILETIME f = { (DWORD)filetime, (DWORD)(filetime >> 32) };
	return timeToIso8601Utc(f, Precision::Second);
}

//! trust-manifest.json: what the set is, and the SHA-256 of every file.
Json manifest(const std::vector<Source>& sources, const std::vector<SetFile>& files, size_t rootsListed,
              const std::map<std::wstring, std::string>& missing) {
	FILETIME now;
	GetSystemTimeAsFileTime(&now);
	Json m = Json::obj();
	m.add(L"CreatedUtc", Json::str(timeToIso8601Utc(now, Precision::Second)));
	m.add(L"CreatedBy", Json::str(L"WAC --update-trust"));
	Json lists = Json::arr();
	for (const Source& s : sources) {
		Json l = Json::obj();
		l.add(L"File", Json::str(s.name));
		l.add(L"Url", Json::str(s.url));
		l.add(L"IssuedUtc", Json::str(isoUtc(s.parsed.thisUpdate)));
		l.add(L"Entries", Json::num(s.parsed.entries.size()));
		lists.push(std::move(l));
	}
	m.add(L"Lists", std::move(lists));
	m.add(L"RootsListed", Json::num(rootsListed));
	Json absent = Json::arr();
	for (const auto& [name, reason] : missing)
		absent.push(Json::obj().add(L"Root", Json::str(name)).add(L"Reason", Json::str(decodeText(reason, CP_UTF8))));
	m.add(L"RootsMissing", std::move(absent));
	Json list = Json::arr();
	for (const SetFile& f : files) {
		uint8_t digest[32];
		sha256Bytes(f.content.data(), f.content.size(), digest);
		list.push(Json::obj().add(L"Path", Json::str(f.path)).add(L"Bytes", Json::num(f.content.size()))
		                     .add(L"SHA256", Json::str(toHexadecimal(digest, sizeof(digest)))));
	}
	m.add(L"Files", std::move(list));
	return m;
}

/*! The folder may receive the set: absent, empty, or holding a previous set
 *  (its manifest). Anything else is refused: the set would mix with foreign
 *  files, and stale roots would be removed from a folder that is not ours. */
bool folderAccepted(const std::filesystem::path& folder, std::string& reason) {
	std::error_code ec;
	if (!std::filesystem::exists(folder, ec)) return true;
	if (!std::filesystem::is_directory(folder, ec)) { reason = "not a folder"; return false; }
	if (std::filesystem::exists(folder / MANIFEST, ec)) return true;
	if (std::filesystem::directory_iterator(folder, ec) == std::filesystem::directory_iterator()) return !ec;
	reason = "not empty, and not a previous trust set";
	return false;
}

//! Writes one file of the set. @return false if it is not written entirely
bool writeFile(const std::filesystem::path& path, const std::vector<uint8_t>& content) {
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	out.write((const char*)content.data(), (std::streamsize)content.size());
	return (bool)out;
}

/*! Writes the set: manifest removed first, stale roots removed, files
 *  written, manifest last (see trust_update.h).
 *  @return false with `reason` at the first failure */
bool writeSet(const std::filesystem::path& folder, const std::vector<SetFile>& files, const Json& m,
              std::string& reason) {
	std::error_code ec;
	std::filesystem::remove(folder / MANIFEST, ec);
	if (ec) { reason = "previous manifest not removed"; return false; }
	std::filesystem::create_directories(folder / "roots", ec);
	if (ec) { reason = "folder not created"; return false; }
	for (const auto& old : std::filesystem::directory_iterator(folder / "roots", ec))
		if (old.path().extension() == ".crt") std::filesystem::remove(old.path(), ec);
	for (const SetFile& f : files)
		if (!writeFile(folder / f.path, f.content)) { reason = "not written: " + encodeText(f.path); return false; }
	const std::string text = encodeText(m.dump(0));
	if (!writeFile(folder / MANIFEST, std::vector<uint8_t>(text.begin(), text.end()))) {
		reason = "manifest not written";
		return false;
	}
	return true;
}

} // namespace

std::wstring DefaultTrustFolder() {
	wchar_t module[MAX_PATH];
	const DWORD size = GetModuleFileNameW(nullptr, module, MAX_PATH);
	if (size == 0 || size == MAX_PATH) return L"trust";
	return std::filesystem::path(module).parent_path().wstring() + L"\\trust";
}

int UpdateTrust(const std::wstring& folder) {
	std::string reason;
	printStep(L" - Trust set folder : ");
	if (!folderAccepted(folder, reason)) { printError(folder + L": " + decodeText(reason, CP_UTF8)); return 1; }
	printSuccess();
	const HttpClient http;
	if (!http.ready()) { printError(decodeText(http.reason(), CP_UTF8)); return 1; }

	std::vector<Source> sources(2);
	printStep(L" - Trusted roots list (authroot.stl) : ");
	if (!fetchList(http, L"authrootstl.cab", "authroot.stl", 3, sources[0], reason)) {
		printError(decodeText(reason, CP_UTF8));
		return 1;
	}
	printSuccess();
	printStep(L" - Disallowed certificates list (disallowedcert.stl) : ");
	if (!fetchList(http, L"disallowedcertstl.cab", "disallowedcert.stl", 15, sources[1], reason)) {
		printError(decodeText(reason, CP_UTF8));
		return 1;
	}
	printSuccess();

	std::map<std::wstring, std::string> missing;
	std::vector<SetFile> files = fetchRoots(http, sources[0].parsed, missing);
	if (files.empty()) { printError(L"no root certificate obtained"); return 1; }
	files.push_back(rootsPem(sources[0].parsed, files));
	for (const Source& s : sources) files.push_back({ s.name, s.list });

	printStep(L" - Writing the trust set : ");
	const Json m = manifest(sources, files, sources[0].parsed.entries.size(), missing);
	if (!writeSet(folder, files, m, reason)) { printError(decodeText(reason, CP_UTF8)); return 1; }
	printSuccess();
	if (!missing.empty())
		wprintf(L"   %zu root(s) not obtained: listed in %hs; a signature chaining to one is not verified.\n",
		        missing.size(), MANIFEST);
	return 0;
}

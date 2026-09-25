/*! \file
 *  \brief --update-trust (see trust_update.h).
 */
#include "trust_update.h"
#include "authenticode.h"
#include "cab.h"
#include "http_client.h"
#include "xml_light.h"
#include "zip.h"
#include "json.h"
#include "sha.h"
#include "tools.h"
#include <filesystem>
#include <fstream>
#include <atomic>
#include <cwctype>
#include <functional>
#include <set>
#include <map>
#include <thread>

namespace {

//! Microsoft's distribution point, the one Windows' own automatic update of the roots uses.
const std::wstring TRUSTED_ROOTS_URL = L"http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/";
const size_t CABINET_MAX = 16 * 1024 * 1024;   //!< a trust list cabinet is ~100 KiB
const size_t CERTIFICATE_MAX = 64 * 1024;      //!< a root certificate is ~1.5 KiB
const char MANIFEST[] = "trust-manifest.json";
/*! Microsoft's blocklist of vulnerable drivers: the XML of the policy
 *  Windows enforces (HVCI, Smart App Control), in a ZIP. */
const std::wstring DRIVER_BLOCKLIST_URL = L"https://aka.ms/VulnerableDriverBlockList";
//! LOLDrivers, the community list of vulnerable and malicious drivers.
const std::wstring LOLDRIVERS_URL = L"https://www.loldrivers.io/api/drivers.json";
const size_t DRIVER_LIST_MAX = 128 * 1024 * 1024;   //!< LOLDrivers is ~33 MiB in 2026
const char DRIVERS[] = "vulnerable-drivers.json";
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
	std::vector<ArchiveFile> files;
	if (!CabExtract(bytes, files, reason)) { reason = "cabinet unreadable: " + reason; return false; }
	for (ArchiveFile& file : files)
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

/*! A list of vulnerable drivers, as downloaded and as read.
 *  NOT SIGNED, unlike the trust lists: its authenticity is that of HTTPS —
 *  the server's certificate, checked by the workstation — and the manifest
 *  says so. */
struct DriverList {
	std::wstring name, url, file;    //!< what it is, where from, where kept in the set
	std::vector<uint8_t> raw;        //!< as downloaded
	Json hashes = Json::arr();       //!< fingerprints of drivers to distrust
	Json signers = Json::arr();      //!< signers to distrust (Microsoft's list only)
	std::string reason;              //!< why it is missing, when it is
	bool obtained = false;           //!< downloaded and read
};

//! An entry of `hashes`: a fingerprint, and of what (the file, or its Authenticode digest).
Json driverHash(const std::wstring& hash, const wchar_t* of, const std::wstring& name) {
	std::wstring upper = hash;
	for (wchar_t& c : upper) c = (wchar_t)towupper(c);
	return Json::obj().add(L"Hash", Json::str(upper)).add(L"Of", Json::str(of)).add(L"Name", Json::str(name));
}

/*! A denied signer of Microsoft's blocklist: its name, the digest of its
 *  certificate's signed part (TbsHash, by the certificate's own signature
 *  algorithm), and the file attributes that restrict it — file name,
 *  internal name, versions —, as the policy gives them. A signer without
 *  them is denied for every file. */
Json deniedSigner(const XmlNode& signer, const std::map<std::wstring, const XmlNode*>& attributes) {
	Json entry = Json::obj();
	entry.add(L"Name", Json::str(signer.attribute(L"Name")));
	if (const XmlNode* root = signer.child(L"CertRoot")) {
		if (root->attribute(L"Type") == L"TBS") entry.add(L"TbsHash", Json::str(root->attribute(L"Value")));
		else entry.add(L"CertRoot", Json::str(root->attribute(L"Type") + L" " + root->attribute(L"Value")));
	}
	Json files = Json::arr();
	for (const auto& reference : signer.children) {
		if (reference->name != L"FileAttribRef") continue;
		const auto found = attributes.find(reference->attribute(L"RuleID"));
		if (found == attributes.end()) continue;
		Json file = Json::obj();
		for (const auto& [key, value] : found->second->attributes)
			if (key != L"ID" && key != L"FriendlyName") file.add(key, Json::str(value));
		files.push(std::move(file));
	}
	entry.add(L"Files", std::move(files));
	return entry;
}

/*! Microsoft's blocklist: the flat Authenticode digests of its Deny rules
 *  (the page digests are left: WAC does not compute them), and its denied
 *  signers, each with the file attributes that restrict it, as given.
 *  @return false if the policy cannot be read */
bool readDriverBlocklist(DriverList& list) {
	std::vector<ArchiveFile> files;
	if (!ZipExtract(list.raw, files, list.reason)) return false;
	std::wstring xml;
	static const std::string POLICY = "/DriverPolicy_Enforced.xml";   // not the "_LegacyFormat" one
	for (const ArchiveFile& f : files)
		if (f.name.size() >= POLICY.size() && f.name.compare(f.name.size() - POLICY.size(), POLICY.size(), POLICY) == 0)
			xml = decodeText(std::string(f.content.begin(), f.content.end()), CP_UTF8);
	if (!xml.empty() && xml[0] == 0xFEFF) xml.erase(0, 1);                   // byte order mark
	const std::unique_ptr<XmlNode> policy = xmlParse(xml);
	if (!policy || policy->name != L"SiPolicy") { list.reason = "policy XML missing or unreadable"; return false; }
	std::map<std::wstring, const XmlNode*> attributes;
	if (const XmlNode* rules = policy->child(L"FileRules"))
		for (const auto& rule : rules->children) {
			const std::wstring friendly = rule->attribute(L"FriendlyName");
			if (rule->name == L"FileAttrib") attributes[rule->attribute(L"ID")] = rule.get();
			if (rule->name == L"Deny" && !rule->attribute(L"Hash").empty() && friendly.find(L" Page ") == std::wstring::npos)
				list.hashes.push(driverHash(rule->attribute(L"Hash"), L"Authenticode", friendly));
		}
	std::set<std::wstring> denied;
	std::function<void(const XmlNode&)> collect = [&](const XmlNode& node) {
		if (node.name == L"DeniedSigner") denied.insert(node.attribute(L"SignerId"));
		for (const auto& child : node.children) collect(*child);
	};
	if (const XmlNode* scenarios = policy->child(L"SigningScenarios")) collect(*scenarios);
	if (const XmlNode* signers = policy->child(L"Signers"))
		for (const auto& signer : signers->children)
			if (denied.count(signer->attribute(L"ID"))) list.signers.push(deniedSigner(*signer, attributes));
	if (list.hashes.members().empty()) { list.reason = "policy without a denied digest"; return false; }
	return true;
}

/*! LOLDrivers: for every sample, its SHA-256 and SHA-1, of the file and of
 *  the Authenticode digest.
 *  @return false if the JSON cannot be read */
bool readLolDrivers(DriverList& list) {
	Json drivers = Json::null();
	std::wstring error;
	if (!Json::parse(decodeText(std::string(list.raw.begin(), list.raw.end()), CP_UTF8), drivers, error)
	    || drivers.kind() != Json::Kind::Arr) {
		list.reason = "JSON unreadable: " + encodeText(error);
		return false;
	}
	for (const auto& [unused, driver] : drivers.members()) {
		const Json* samples = driver.find(L"KnownVulnerableSamples");
		const Json* category = driver.find(L"Category");
		if (!samples || samples->kind() != Json::Kind::Arr) continue;
		for (const auto& [unused2, sample] : samples->members()) {
			const Json* file = sample.find(L"Filename");
			const std::wstring name = (file ? file->text() : L"") + (category ? L" (" + category->text() + L")" : L"");
			for (const wchar_t* key : { L"SHA256", L"SHA1" }) {
				if (const Json* h = sample.find(key); h && !h->text().empty()) list.hashes.push(driverHash(h->text(), L"File", name));
				if (const Json* a = sample.find(L"Authentihash"))
					if (const Json* h = a->find(key); h && !h->text().empty())
						list.hashes.push(driverHash(h->text(), L"Authenticode", name));
			}
		}
	}
	if (list.hashes.members().empty()) { list.reason = "no fingerprint"; return false; }
	return true;
}

/*! Downloads and reads both lists of vulnerable drivers. A list that fails
 *  is recorded as missing, and the set still written: the collection then
 *  collects every signed third-party driver, which it can no longer clear. */
std::vector<DriverList> fetchDriverLists(const HttpClient& http) {
	std::vector<DriverList> lists(2);
	lists[0] = { L"Microsoft vulnerable driver blocklist", DRIVER_BLOCKLIST_URL, L"sources\\VulnerableDriverBlockList.zip" };
	lists[1] = { L"LOLDrivers", LOLDRIVERS_URL, L"sources\\loldrivers.json" };
	for (size_t k = 0; k < lists.size(); ++k) {
		DriverList& list = lists[k];
		printStep(L" - " + list.name + L" : ");
		list.obtained = http.get(list.url, list.raw, DRIVER_LIST_MAX, list.reason)
		             && (k == 0 ? readDriverBlocklist(list) : readLolDrivers(list));
		if (list.obtained) printSuccess();
		else {
			printError(decodeText(list.reason, CP_UTF8));
			list.raw.clear();
		}
	}
	return lists;
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

/*! vulnerable-drivers.json: the fingerprints and signers of both lists,
 *  each with its source, and which lists are missing — what the collection
 *  reads. */
SetFile driversFile(const std::vector<DriverList>& lists) {
	Json hashes = Json::arr(), signers = Json::arr(), missing = Json::arr();
	for (const DriverList& list : lists) {
		if (!list.obtained) {
			missing.push(Json::obj().add(L"List", Json::str(list.name)).add(L"Reason", Json::str(decodeText(list.reason, CP_UTF8))));
			continue;
		}
		for (const auto& [unused, hash] : list.hashes.members()) {
			Json entry = hash;
			hashes.push(std::move(entry.add(L"Source", Json::str(list.name))));
		}
		for (const auto& [unused, signer] : list.signers.members()) {
			Json entry = signer;
			signers.push(std::move(entry.add(L"Source", Json::str(list.name))));
		}
	}
	Json file = Json::obj();
	file.add(L"ListsMissing", std::move(missing));
	file.add(L"Hashes", std::move(hashes));
	file.add(L"Signers", std::move(signers));
	const std::string text = encodeText(file.dump(0));
	return { decodeText(DRIVERS, CP_UTF8), std::vector<uint8_t>(text.begin(), text.end()) };
}

//! A FILETIME count to ISO 8601 UTC.
std::wstring isoUtc(uint64_t filetime) {
	FILETIME f = { (DWORD)filetime, (DWORD)(filetime >> 32) };
	return timeToIso8601Utc(f, Precision::Second);
}

//! trust-manifest.json: what the set is, and the SHA-256 of every file.
Json manifest(const std::vector<Source>& sources, const std::vector<DriverList>& drivers,
              const std::vector<SetFile>& files, size_t rootsListed,
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
	Json driverLists = Json::arr();
	for (const DriverList& d : drivers) {
		Json l = Json::obj();
		l.add(L"Name", Json::str(d.name));
		l.add(L"Url", Json::str(d.url));
		l.add(L"Authenticity", Json::str(L"HTTPS only: the list is not signed"));
		l.add(L"Obtained", Json::boolean(d.obtained));
		if (!d.obtained) l.add(L"Reason", Json::str(decodeText(d.reason, CP_UTF8)));
		else l.add(L"Hashes", Json::num(d.hashes.members().size())).add(L"Signers", Json::num(d.signers.members().size()));
		driverLists.push(std::move(l));
	}
	m.add(L"DriverLists", std::move(driverLists));
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
	if (!ec) std::filesystem::create_directories(folder / "sources", ec);
	if (ec) { reason = "folder not created"; return false; }
	std::filesystem::remove(folder / "sources" / "VulnerableDriverBlockList.zip", ec);
	std::filesystem::remove(folder / "sources" / "loldrivers.json", ec);
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
	std::vector<DriverList> drivers = fetchDriverLists(http);
	files.push_back(driversFile(drivers));
	for (DriverList& d : drivers)
		if (d.obtained) files.push_back({ d.file, std::move(d.raw) });

	printStep(L" - Writing the trust set : ");
	const Json m = manifest(sources, drivers, files, sources[0].parsed.entries.size(), missing);
	if (!writeSet(folder, files, m, reason)) { printError(decodeText(reason, CP_UTF8)); return 1; }
	printSuccess();
	if (!missing.empty())
		wprintf(L"   %zu root(s) not obtained: listed in %hs; a signature chaining to one is not verified.\n",
		        missing.size(), MANIFEST);
	return 0;
}

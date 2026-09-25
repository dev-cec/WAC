/*! \file
 *  \brief --update-trust (see trust_update.h).
 */
#include "trust_update.h"
#include "authenticode.h"
#include "cab.h"
#include "http_client.h"
#include "xml_light.h"
#include "zip.h"
#include "csv_reader.h"
#include "json.h"
#include "sha.h"
#include "tools.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
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
/*! The Common CA Database's report of every authority of the root programs:
 *  capabilities, status, and the revocation lists each issues. */
const std::wstring CCADB_URL = L"https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4";
const size_t CCADB_MAX = 256 * 1024 * 1024;         //!< ~10 MiB in 2026
const size_t CRL_MAX = 64 * 1024 * 1024;            //!< the largest code signing CRL is ~6 MiB in 2026
const char REVOCATION[] = "revocation.json";
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

//! One download of a batch: its address, then its content or why it failed.
struct Download {
	std::wstring url;
	std::vector<uint8_t> content;
	std::string reason;
	bool obtained = false;
};

/*! Downloads a batch, several requests at once: one after the other, the
 *  562 roots took 5 min 20 s, each waiting about 0.6 s on the server.
 *  @param batch the downloads, filled in place
 *  @param maxSize limit of each content
 *  @param label what is downloaded, for the progress line */
void downloadAll(const HttpClient& http, std::vector<Download>& batch, size_t maxSize, const std::wstring& label) {
	std::atomic<size_t> next{ 0 }, done{ 0 };
	auto worker = [&]() {
		for (size_t k = next++; k < batch.size(); k = next++) {
			batch[k].obtained = http.get(batch[k].url, batch[k].content, maxSize, batch[k].reason);
			if (++done % 50 == 0) wprintf(L"\r - %ls : %zu / %zu", label.c_str(), done.load(), batch.size());
		}
	};
	std::vector<std::thread> threads;
	for (unsigned t = 0; t < DOWNLOAD_THREADS; ++t) threads.emplace_back(worker);
	for (std::thread& t : threads) t.join();
	size_t obtained = 0;
	for (const Download& d : batch) obtained += d.obtained;
	wprintf(L"\r - %ls : %zu / %zu, %zu obtained\n", label.c_str(), batch.size(), batch.size(), obtained);
}

/*! Downloads every root authroot.stl names; each must be the certificate
 *  the signed list names — FindInTrustList by its SHA-1.
 *  @param missing receives the roots not obtained, with why
 *  @return the certificates, in the list's order */
std::vector<SetFile> fetchRoots(const HttpClient& http, const TrustList& roots,
                                std::map<std::wstring, std::string>& missing) {
	std::vector<Download> batch(roots.entries.size());
	for (size_t k = 0; k < batch.size(); ++k) batch[k].url = TRUSTED_ROOTS_URL + thumbprint(roots.entries[k]) + L".crt";
	downloadAll(http, batch, CERTIFICATE_MAX, L"Root certificates");
	std::vector<SetFile> files;
	for (size_t k = 0; k < batch.size(); ++k) {
		const TrustListEntry& entry = roots.entries[k];
		Download& d = batch[k];
		if (d.obtained && FindInTrustList(roots, d.content.data(), d.content.size()) != &entry)
			d = { d.url, {}, "not the certificate authroot.stl names: SHA-1 differs", false };
		if (d.obtained) files.push_back({ L"roots\\" + thumbprint(entry) + L".crt", std::move(d.content) });
		else missing[thumbprint(entry)] = d.reason;
	}
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

/*! What the CCADB report gives, and the revocation lists downloaded from it.
 *  The report is not signed — HTTPS only —; each CRL is signed by its
 *  authority, a signature checked where the CRL is used, against the
 *  authority's certificate in the chain of the binary. */
struct Revocation {
	bool obtained = false;
	std::string reason;
	std::vector<uint8_t> report;                     //!< the CSV, as downloaded
	//! Each CRL address, and the authorities that name it (name, SHA-256 of the certificate).
	std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>> crls;
	Json revokedAuthorities = Json::arr();           //!< authorities the CCADB says revoked
	std::vector<Download> downloads;
};

//! The columns of the report read here; the report is refused if one is missing.
struct CcadbColumns {
	size_t name, sha256, codeSigning, status, fullCrl, partitionedCrls;
};

/*! Locates the columns by their header names, not by position: the report
 *  gains columns over time.
 *  @return false if one is missing */
bool locateColumns(const std::vector<std::string>& header, CcadbColumns& c) {
	const char* NAMES[] = { "Certificate Name", "SHA-256 Fingerprint", "Code Signing Capable", "Revocation Status",
	                        "Full CRL Issued By This CA", "JSON Array of Partitioned CRLs" };
	size_t* targets[] = { &c.name, &c.sha256, &c.codeSigning, &c.status, &c.fullCrl, &c.partitionedCrls };
	for (size_t k = 0; k < 6; ++k) {
		const auto found = std::find(header.begin(), header.end(), NAMES[k]);
		if (found == header.end()) return false;
		*targets[k] = (size_t)(found - header.begin());
	}
	return true;
}

/*! Reads the report: the CRLs of every authority capable of code signing
 *  and not revoked, full and partitioned; and every revoked authority,
 *  whatever its capabilities — one in a chain invalidates the signature.
 *  @return false if the report cannot be read */
bool readCcadb(Revocation& r) {
	std::vector<std::vector<std::string>> records;
	CcadbColumns c{};
	if (!CsvRead(std::string(r.report.begin(), r.report.end()), records, r.reason)) return false;
	if (records.size() < 2 || !locateColumns(records[0], c)) { r.reason = "CCADB report without its expected columns"; return false; }
	for (size_t k = 1; k < records.size(); ++k) {
		const std::vector<std::string>& row = records[k];
		const std::wstring name = decodeText(row[c.name], CP_UTF8), sha256 = decodeText(row[c.sha256], CP_UTF8);
		if (row[c.status] == "Revoked" || row[c.status] == "Parent Cert Revoked") {
			r.revokedAuthorities.push(Json::obj().add(L"SHA256", Json::str(sha256)).add(L"Name", Json::str(name))
			                                     .add(L"Status", Json::str(decodeText(row[c.status], CP_UTF8))));
			continue;
		}
		if (row[c.codeSigning] != "True" || (!row[c.status].empty() && row[c.status] != "Not Revoked")) continue;
		std::vector<std::wstring> urls;
		if (!row[c.fullCrl].empty()) urls.push_back(decodeText(row[c.fullCrl], CP_UTF8));
		Json partitioned = Json::null();
		std::wstring error;
		if (!row[c.partitionedCrls].empty() && Json::parse(decodeText(row[c.partitionedCrls], CP_UTF8), partitioned, error))
			for (const auto& [unused, url] : partitioned.members()) urls.push_back(url.text());
		for (std::wstring& url : urls) {
			url.erase(url.find_last_not_of(L" \t\r\n") + 1);
			if (!url.empty()) r.crls[url].push_back({ name, sha256 });
		}
	}
	return true;
}

/*! Downloads the report, then every CRL it names. A report not obtained
 *  leaves the set without revocation: the collection then cannot clear a
 *  signature, and collects the binary. */
Revocation fetchRevocation(const HttpClient& http) {
	Revocation r;
	printStep(L" - Certificate authorities (CCADB) : ");
	r.obtained = http.get(CCADB_URL, r.report, CCADB_MAX, r.reason) && readCcadb(r);
	if (!r.obtained) { printError(decodeText(r.reason, CP_UTF8)); return r; }
	printSuccess();
	for (const auto& [url, unused] : r.crls) r.downloads.push_back({ url, {}, {}, false });
	downloadAll(http, r.downloads, CRL_MAX, L"Revocation lists (CRL)");
	return r;
}

//! The file of a CRL in the set: named by the SHA-256 of its address, which may hold anything.
std::wstring crlFile(const std::wstring& url) {
	const std::string bytes = encodeText(url);
	uint8_t digest[32];
	sha256Bytes((const uint8_t*)bytes.data(), bytes.size(), digest);
	return L"crl\\" + toHexadecimal(digest, 16) + L".crl";
}

/*! revocation.json: each CRL with the authorities that issue it, the CRLs
 *  not obtained, and the revoked authorities — what the collection reads. */
SetFile revocationFile(const Revocation& r) {
	Json crls = Json::arr(), missing = Json::arr();
	for (const Download& d : r.downloads) {
		Json issuers = Json::arr();
		for (const auto& [name, sha256] : r.crls.at(d.url))
			issuers.push(Json::obj().add(L"Name", Json::str(name)).add(L"SHA256", Json::str(sha256)));
		if (d.obtained)
			crls.push(Json::obj().add(L"Url", Json::str(d.url)).add(L"File", Json::str(crlFile(d.url)))
			                     .add(L"Bytes", Json::num(d.content.size())).add(L"IssuedBy", std::move(issuers)));
		else
			missing.push(Json::obj().add(L"Url", Json::str(d.url)).add(L"Reason", Json::str(decodeText(d.reason, CP_UTF8)))
			                        .add(L"IssuedBy", std::move(issuers)));
	}
	Json file = Json::obj();
	file.add(L"Crls", std::move(crls));
	file.add(L"CrlsMissing", std::move(missing));
	file.add(L"RevokedAuthorities", r.revokedAuthorities);
	const std::string text = encodeText(file.dump(0));
	return { decodeText(REVOCATION, CP_UTF8), std::vector<uint8_t>(text.begin(), text.end()) };
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
Json manifest(const std::vector<Source>& sources, const std::vector<DriverList>& drivers, const Revocation& revocation,
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
	Json crl = Json::obj();
	crl.add(L"Url", Json::str(CCADB_URL));
	crl.add(L"Authenticity", Json::str(L"HTTPS only for the CCADB report; each CRL is signed by its authority, checked where it is used"));
	crl.add(L"Obtained", Json::boolean(revocation.obtained));
	if (!revocation.obtained) crl.add(L"Reason", Json::str(decodeText(revocation.reason, CP_UTF8)));
	size_t crls = 0;
	for (const Download& d : revocation.downloads) crls += d.obtained;
	if (revocation.obtained)
		crl.add(L"Crls", Json::num(crls)).add(L"CrlsMissing", Json::num(revocation.downloads.size() - crls))
		   .add(L"RevokedAuthorities", Json::num(revocation.revokedAuthorities.members().size()));
	m.add(L"Revocation", std::move(crl));
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
	if (!ec) std::filesystem::create_directories(folder / "crl", ec);
	if (ec) { reason = "folder not created"; return false; }
	std::filesystem::remove(folder / "sources" / "VulnerableDriverBlockList.zip", ec);
	std::filesystem::remove(folder / "sources" / "loldrivers.json", ec);
	for (const auto& old : std::filesystem::directory_iterator(folder / "roots", ec))
		if (old.path().extension() == ".crt") std::filesystem::remove(old.path(), ec);
	for (const auto& old : std::filesystem::directory_iterator(folder / "crl", ec))
		if (old.path().extension() == ".crl") std::filesystem::remove(old.path(), ec);
	std::filesystem::remove(folder / REVOCATION, ec);
	std::filesystem::remove(folder / "sources" / "ccadb.csv", ec);
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
	Revocation revocation = fetchRevocation(http);
	if (revocation.obtained) {
		files.push_back(revocationFile(revocation));
		files.push_back({ L"sources\\ccadb.csv", std::move(revocation.report) });
		for (Download& d : revocation.downloads)
			if (d.obtained) files.push_back({ crlFile(d.url), std::move(d.content) });
	}

	printStep(L" - Writing the trust set : ");
	const Json m = manifest(sources, drivers, revocation, files, sources[0].parsed.entries.size(), missing);
	if (!writeSet(folder, files, m, reason)) { printError(decodeText(reason, CP_UTF8)); return 1; }
	printSuccess();
	if (!missing.empty())
		wprintf(L"   %zu root(s) not obtained: listed in %hs; a signature chaining to one is not verified.\n",
		        missing.size(), MANIFEST);
	return 0;
}

/*! \file
 *  \brief Implementation of the exhibit store and of its sealed manifest (see consigne.h for the procedure and the manifest's content).
 */
#include "consigne.h"
#include "tools.h"
#include "audit.h"
#include "json.h"
#include "sha.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <map>
#include <set>

/*  exhibitStore.cpp — see exhibitStore.h for the procedure and the manifest's content.
 *  Here, the implementation.
 */

namespace {

//! An exhibit in the manifest.
struct Exhibit {
	RawHiveExtraction extracted;
	std::wstring   method;
	bool           shared = false;   //!< content already stored under another exhibit
	/*! false: fingerprinted and authenticated, content NOT copied (an
	 *  authentic Microsoft binary, see ExhibitStoreAddFingerprint). */
	bool           contentStored = true;
	std::wstring   signature;        //!< verdict of the Microsoft authenticity check, if made
};

std::vector<Exhibit> g_exhibits;
//! Volumes actually read, by letter: recorded once each.
std::map<std::wstring, std::wstring> g_volumes;   // letter -> "serial | file system"

//! FILETIME from a 64-bit integer, the form raw_hive returns them in.
FILETIME toFiletime(uint64_t v) {
	FILETIME f = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
	return f;
}

/*! Adds a timestamp in both forms, UTC and the SUSPECT's local time.
 *  Nothing is written if the date is zero: an empty field would read as a date
 *  the format did not carry — which it indeed did not — but a "1601-01-01"
 *  would read as a real date.
 */
void addDate(Json& o, const std::wstring& key, uint64_t filetimeUtc) {
	if (filetimeUtc == 0) return;
	const FILETIME f = toFiletime(filetimeUtc);
	o.add(key + L"Utc", Json::str(timeToIso8601Utc(f)));
	o.add(key,          Json::str(utcTimeToIso8601Local(f)));
}

//! Records a volume's serial number and file system.
std::wstring signatureVolume(const std::wstring& letter) {
	const std::wstring root = letter + L":\\";
	DWORD serial = 0;
	wchar_t fs[64] = { 0 };
	if (!GetVolumeInformationW(root.c_str(), nullptr, 0, &serial, nullptr, nullptr,
	                           fs, (DWORD)(sizeof(fs) / sizeof(fs[0]))))
		return L"";
	wchar_t hex[16] = { 0 };
	swprintf(hex, 16, L"%08X", (unsigned)serial);
	return std::wstring(hex) + L" | " + fs;
}

//! Volume letter of a source path "X:\...".
std::wstring letterOf(const std::wstring& volumePath) {
	if (volumePath.size() >= 2 && volumePath[1] == L':')
		return volumePath.substr(0, 1);
	return L"";
}

/*! Path of an exhibit RELATIVE to the output directory.
 *
 *  The manifest must not carry the collecting machine's absolute path: it
 *  identifies nothing about the exhibit, it exposes the examiner's directory
 *  tree, and it becomes wrong as soon as the medium is mounted elsewhere —
 *  that is, the first time someone else reads it.
 */
std::wstring outputRelative(const std::wstring& absolute) {
	std::error_code ec;
	const std::filesystem::path rel = std::filesystem::relative(
		std::filesystem::path(absolute), std::filesystem::path(conf._outputDir), ec);
	if (ec || rel.empty()) return absolute;      // outside the output folder: as is
	return rel.wstring();
}

} // namespace

std::wstring exhibitStoreFolder() {
	return conf._outputDir + L"\\exhibits";
}

std::wstring workingFolder() {
	return conf._outputDir + L"\\working";
}

unsigned long long ExhibitStoreFreeSpace() {
	ULARGE_INTEGER free = { 0 };
	const std::wstring output = conf._outputDir;
	std::error_code ec;
	std::filesystem::create_directories(output, ec);
	if (!GetDiskFreeSpaceExW(output.c_str(), &free, nullptr, nullptr)) return 0;
	return free.QuadPart;
}

HRESULT ExhibitStoreCheckLocation(unsigned long long estimatedNeed) {
	std::error_code ec;

	// 1. A working directory already populated would analyse an earlier collection.
	const std::filesystem::path working = workingFolder();
	if (std::filesystem::exists(working, ec)) {
		bool populated = false;
		for (const std::filesystem::directory_entry& e :
		     std::filesystem::recursive_directory_iterator(working, ec)) {
			if (ec) break;
			if (e.is_regular_file(ec)) { populated = true; break; }
		}
		if (populated) {
			log(2, L"🔥The working directory already holds files: "
			       + working.wstring()
			       + L" — a previous collection would be analysed instead of "
			       L"this one. Use --output towards a fresh folder.",
			    ERROR_DIR_NOT_EMPTY);
			return HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
		}
	}

	// 2. Available space. The need is doubled: exhibit store + working copy.
	const unsigned long long free = ExhibitStoreFreeSpace();
	if (free == 0) {
		// Information unavailable: do not block on a failed measurement.
		log(2, L"🔥Free space undetermined on the collection medium: "
		       L"check skipped");
		return ERROR_SUCCESS;
	}
	const unsigned long long need = estimatedNeed * 2;
	log(2, L"❇️Collection medium: " + std::to_wstring(free / 1024 / 1024)
	     + L" MiB free, " + std::to_wstring(need / 1024 / 1024)
	     + L" MiB estimated as needed (exhibit store + working copy)");
	if (free < need) {
		log(2, L"🔥Not enough space on the collection medium: "
		       + std::to_wstring(free / 1024 / 1024) + L" MiB free for "
		       + std::to_wstring(need / 1024 / 1024) + L" MiB needed",
		    ERROR_DISK_FULL);
		return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
	}
	return ERROR_SUCCESS;
}

void ExhibitStoreAdd(const std::vector<RawHiveExtraction>& reading,
                     const std::wstring& method) {
	for (const RawHiveExtraction& e : reading) {
		g_exhibits.push_back(Exhibit{ e, method });
		const std::wstring letter = letterOf(e.volumePath);
		if (!letter.empty() && g_volumes.find(letter) == g_volumes.end())
			g_volumes.emplace(letter, signatureVolume(letter));
	}
}

void ExhibitStoreAddDuplicate(const RawHiveExtraction& e, const std::wstring& method) {
	g_exhibits.push_back(Exhibit{ e, method, true });
}

void ExhibitStoreAddFingerprint(const RawHiveExtraction& e, const std::wstring& method,
                                const std::wstring& signature) {
	Exhibit p{ e, method, false, false, signature };
	p.extracted.outputPath.clear();
	g_exhibits.push_back(std::move(p));
}

bool ExhibitSourceTimes(const std::wstring& workingCopy, FILETIME& created, FILETIME& modified, FILETIME& accessed) {
	// Exhibit files by path, rebuilt when exhibits were added since.
	static std::map<std::wstring, size_t> byFile;
	static size_t builtFor = 0;
	if (builtFor != g_exhibits.size()) {
		byFile.clear();
		for (size_t i = 0; i < g_exhibits.size(); ++i)
			if (SUCCEEDED(g_exhibits[i].extracted.result) && g_exhibits[i].contentStored && !g_exhibits[i].shared)
				byFile.emplace(toLower(g_exhibits[i].extracted.outputPath), i);
		builtFor = g_exhibits.size();
	}
	const std::wstring working = workingFolder();
	if (toLower(workingCopy).compare(0, working.size(), toLower(working)) != 0) return false;
	const auto found = byFile.find(toLower(exhibitStoreFolder() + workingCopy.substr(working.size())));
	if (found == byFile.end()) return false;
	const RawHiveFingerprints& m = g_exhibits[found->second].extracted.fingerprints;
	if (!m.creeUtc && !m.modifiedUtc && !m.accedeUtc) return false;
	created = toFiletime(m.creeUtc);
	modified = toFiletime(m.modifiedUtc);
	accessed = toFiletime(m.accedeUtc);
	return true;
}

const std::map<std::wstring, StoredExhibit>& ExhibitStoreIndex() {
	static const std::map<std::wstring, StoredExhibit> index = [] {
		std::map<std::wstring, StoredExhibit> built;
		for (const Exhibit& p : g_exhibits)
			if (SUCCEEDED(p.extracted.result) && !p.extracted.volumePath.empty())
				built.emplace(toLower(p.extracted.volumePath),
				              StoredExhibit{ p.extracted.volumePath, p.extracted.outputPath, p.contentStored,
				                             p.extracted.fingerprints.md5, p.extracted.fingerprints.sha1,
				                             p.extracted.fingerprints.sha256, p.extracted.fingerprints.authenticodeSha256,
				                             p.signature });
		return built;
	}();
	return index;
}

void ExhibitStoreSummary(size_t* exhibits, size_t* failures, unsigned long long* bytes) {
	size_t count = 0, failed = 0;
	unsigned long long total = 0;
	for (const Exhibit& p : g_exhibits) {
		++count;
		if (FAILED(p.extracted.result)) ++failed;
		// Shared content takes room in the exhibit store only once; a fingerprint alone, none.
		else if (!p.shared && p.contentStored) total += p.extracted.fingerprints.bytes;
	}
	if (exhibits) *exhibits = count;
	if (failures) *failures = failed;
	if (bytes) *bytes = total;
}

const wchar_t READ_IN_PLACE[] = L" [read in place by the conversion]";

HRESULT ExhibitStoreToWorking(size_t* copies, unsigned long long* bytes, bool skipReadInPlace) {
	if (copies) *copies = 0;
	if (bytes) *bytes = 0;

	const std::filesystem::path exhibitStore = exhibitStoreFolder();
	const std::filesystem::path working  = workingFolder();
	std::error_code ec;
	if (!std::filesystem::exists(exhibitStore, ec)) {
		log(2, L"🔥Exhibit store absent: " + exhibitStore.wstring(), ERROR_PATH_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	}
	std::filesystem::create_directories(working, ec);

	/*  The manifest's fingerprints, indexed by exhibit store path: the working
	 *  copy is compared with what was READ FROM THE VOLUME, not with a re-read of
	 *  the exhibit store. An already altered exhibit store would thus be caught
	 *  too. */
	std::map<std::wstring, std::wstring> expected;   // path -> SHA-256
	for (const Exhibit& p : g_exhibits)
		if (SUCCEEDED(p.extracted.result) && p.contentStored && !p.extracted.fingerprints.sha256.empty())
			expected.emplace(p.extracted.outputPath, p.extracted.fingerprints.sha256);
	std::set<std::wstring> inPlace;                  // exhibit files the conversion reads from the store
	if (skipReadInPlace)
		for (const Exhibit& p : g_exhibits)
			if (p.method.find(READ_IN_PLACE) != std::wstring::npos) inPlace.insert(p.extracted.outputPath);

	size_t count = 0, failed = 0, verified = 0, existing = 0;
	unsigned long long volume = 0;
	HRESULT global = ERROR_SUCCESS;

	for (const std::filesystem::directory_entry& e :
	     std::filesystem::recursive_directory_iterator(exhibitStore, ec)) {
		if (ec) break;
		if (!e.is_regular_file(ec)) continue;

		const std::filesystem::path relative =
			std::filesystem::relative(e.path(), exhibitStore, ec);
		if (ec) continue;
		// The manifest and its seal belong to the exhibit store alone: copying
		// them to the working directory would invite changing them.
		const std::wstring name = relative.filename().wstring();
		if (name == L"MANIFEST.json" || name == L"MANIFEST.sha256") continue;
		if (inPlace.count(e.path().wstring())) continue;

		const std::filesystem::path target = working / relative;
		/*  AN EXISTING WORKING COPY IS NOT OVERWRITTEN. The function is called
		 *  after each extraction phase; overwriting would undo the work already
		 *  done on the previous phase's files — in particular the replay of the
		 *  hives' transaction logs, which happens right after they are copied. */
		if (std::filesystem::exists(target, ec)) { ++existing; continue; }
		std::filesystem::create_directories(target.parent_path(), ec);
		std::filesystem::copy_file(e.path(), target,
		                           std::filesystem::copy_options::overwrite_existing, ec);
		if (ec) {
			log(2, L"🔥Cannot copy into the working directory: " + relative.wstring());
			++failed;
			global = S_FALSE;
			continue;
		}
		++count;
		volume += (unsigned long long)std::filesystem::file_size(target, ec);

		/*  VERIFYING THE COPY. Without it, a silently truncated copy — full
		 *  medium, write error — would give a working directory that does not
		 *  match the exhibit, and the whole analysis would bear on something
		 *  else. */
		const auto att = expected.find(e.path().wstring());
		if (att != expected.end()) {
			const std::wstring obtained = sha256OfFile(target.wstring());
			if (obtained != att->second) {
				log(2, L"🔥Working copy does not match the exhibit store: "
				       + relative.wstring() + L" (expected " + att->second
				       + L", got " + obtained + L")");
				++failed;
				global = S_FALSE;
			}
			else ++verified;
		}
	}

	log(2, L"❇️Working directory: " + std::to_wstring(count) + L" file(s) copied, "
	     + std::to_wstring(verified) + L" verified by fingerprint, "
	     + std::to_wstring(existing) + L" already present, "
	     + std::to_wstring(failed) + L" divergence(s)");
	if (copies) *copies = count;
	if (bytes) *bytes = volume;
	return global;
}

HRESULT ExhibitStoreWriteManifest() {
	std::error_code ec;
	const std::filesystem::path exhibitStore = exhibitStoreFolder();
	std::filesystem::create_directories(exhibitStore, ec);

	// The context comes from the audit: built once for both documents of
	// the collection (see auditContext).
	Json root = auditContext();

	size_t count = 0, failed = 0;
	unsigned long long total = 0;
	ExhibitStoreSummary(&count, &failed, &total);

	Json guard = Json::obj();
	guard.add(L"ExhibitDirectory",  Json::str(L"exhibits"));
	guard.add(L"WorkingDirectory",  Json::str(L"working"));
	guard.add(L"Statement", Json::str(
		L"The files of 'exhibits' are the raw copies as read from the volume: "
		L"they are never reopened for writing. Any analysis, and any "
		L"modification (replay of the transaction logs, alignment of a hive's "
		L"base block), bear on 'working', copied from the exhibit store and "
		L"verified by fingerprint. Nothing was written to the examined "
		L"system."));
	guard.add(L"ExtractionStartUtc",   Json::str(auditStartUtc()));
	guard.add(L"ExtractionStart",      Json::str(auditStartLocal()));
	std::wstring finUtc, finLocal;
	{
		FILETIME f = { 0, 0 };
		GetSystemTimeAsFileTime(&f);
		finUtc   = timeToIso8601Utc(f);
		finLocal = utcTimeToIso8601Local(f);
	}
	guard.add(L"ManifestWrittenUtc",   Json::str(finUtc));
	guard.add(L"ManifestWritten",      Json::str(finLocal));
	guard.add(L"ItemCount",            Json::num((unsigned long long)count));
	guard.add(L"FailedCount",          Json::num((unsigned long long)failed));
	guard.add(L"TotalBytes",           Json::num(total));
	guard.add(L"HashAlgorithms",       Json::str(L"MD5, SHA-1, SHA-256"));
	guard.add(L"NoWriteToExaminedSystem", Json::boolean(true));

	Json volumes = Json::arr();
	for (const auto& v : g_volumes) {
		Json o = Json::obj();
		o.add(L"Letter", Json::str(v.first));
		// The serial number and file system tie the exhibit to the physical
		// medium, independently of the letter, which can change.
		const size_t sep = v.second.find(L" | ");
		if (sep != std::wstring::npos) {
			o.add(L"SerialNumber", Json::str(v.second.substr(0, sep)));
			o.add(L"FileSystem",   Json::str(v.second.substr(sep + 3)));
		}
		o.add(L"RawDevice", Json::str(L"\\\\.\\" + v.first + L":"));
		volumes.push(std::move(o));
	}
	guard.add(L"VolumesRead", std::move(volumes));
	root.add(L"Custody", std::move(guard));

	Json exhibits = Json::arr();
	for (const Exhibit& p : g_exhibits) {
		const RawHiveExtraction& e = p.extracted;
		const RawHiveFingerprints& m = e.fingerprints;
		Json o = Json::obj();
		o.add(L"SourcePath",  Json::str(e.volumePath));
		/* An authentic Microsoft binary is fingerprinted, not copied: no exhibit
		   file, and the manifest says so rather than point to nothing. */
		if (p.contentStored) o.add(L"ExhibitPath", Json::str(outputRelative(e.outputPath)));
		else                 o.add(L"ContentStored", Json::boolean(false));
		o.add(L"Method",      Json::str(p.method));
		if (FAILED(e.result)) {
			// An exhibit missing from the manifest would read as never looked for.
			o.add(L"Result", Json::str(L"0x" + to_hex(e.result) + L" "
			                           + getErrorMessage(e.result)));
			exhibits.push(std::move(o));
			continue;
		}
		o.add(L"Result",        Json::str(L"OK"));
		/* An authentic Microsoft binary fingerprinted without a copy carries its
		   Authenticode digests only (see readAndAuthenticate in binaires.cpp). */
		if (!m.md5.empty())    o.add(L"MD5",    Json::str(m.md5));
		if (!m.sha1.empty())   o.add(L"SHA1",   Json::str(m.sha1));
		if (!m.sha256.empty()) o.add(L"SHA256", Json::str(m.sha256));
		if (!m.authenticodeSha1.empty())   o.add(L"AuthenticodeSHA1",   Json::str(m.authenticodeSha1));
		if (!m.authenticodeSha256.empty()) o.add(L"AuthenticodeSHA256", Json::str(m.authenticodeSha256));
		o.add(L"Bytes",         Json::num(m.bytes));
		/* Content identical, byte for byte (SHA-256), to an exhibit already
		   stored: ExhibitPath points to it, and it was not copied again. The source
		   remains an exhibit in its own right — its path, $MFT entry and timestamps
		   are its own. */
		if (p.shared) o.add(L"SharedExhibit", Json::boolean(true));
		if (!p.signature.empty()) o.add(L"Signature", Json::str(p.signature));
		// The two sizes diverging = truncated extraction, which a fingerprint
		// alone would not reveal (it would just be... the truncated file's).
		if (m.declaredSize != m.bytes)
			o.add(L"DeclaredBytes", Json::num(m.declaredSize));
		/* Preallocated file: what follows was never written and is zero in the
		   exhibit, whatever the clusters hold on the disk. To be declared, otherwise
		   a 1 MiB exhibit of which only 135 KiB carry data simply looks "full of
		   zeros". */
		if (!m.resident && m.validDataLength < m.declaredSize)
			o.add(L"ValidDataBytes", Json::num(m.validDataLength));
		o.add(L"MftEntry",      Json::num(m.mftEntry));
		if (m.resident) o.add(L"ResidentData", Json::boolean(true));
		addDate(o, L"Extracted",         m.extractedUtc);
		addDate(o, L"SourceCreated",     m.creeUtc);
		addDate(o, L"SourceModified",    m.modifiedUtc);
		addDate(o, L"SourceMftModified", m.mftModifiedUtc);
		addDate(o, L"SourceAccessed",    m.accedeUtc);
		exhibits.push(std::move(o));
	}
	root.add(L"Items", std::move(exhibits));

	// Writing the manifest. Absolute path: writeJsonFile writes under
	// _outputDir, which is not the exhibit store.
	const std::filesystem::path path = exhibitStore / L"MANIFEST.json";
	{
		std::ofstream f;
		f.open(path);
		if (!f) {
			log(2, L"🔥Exhibit manifest not written: " + path.wstring());
			return E_FAIL;
		}
		f << encodeText(root.dump(0));
		f.close();
	}

	/*  SEAL. A manifest cannot carry its own fingerprint: it is written beside
	 *  it, after it. Without that second file, a retouched manifest would go
	 *  undetected — and the manifest is precisely what attests to the
	 *  exhibits. */
	const std::wstring fingerprint = sha256OfFile(path.wstring());
	const std::filesystem::path seal = exhibitStore / L"MANIFEST.sha256";
	{
		std::ofstream f;
		f.open(seal);
		if (!f || fingerprint.empty()) {
			log(2, L"🔥Manifest seal not written: " + seal.wstring());
			return E_FAIL;
		}
		// sha256sum format: "<fingerprint>  <name>", readable by common tools
		// without knowing anything about WAC.
		f << encodeText(fingerprint + L"  MANIFEST.json\n");
		f.close();
	}

	log(2, L"❇️Exhibit manifest: " + std::to_wstring(count) + L" exhibit(s), "
	     + std::to_wstring(failed) + L" failure(s), "
	     + std::to_wstring(total / 1024 / 1024) + L" MiB");
	log(2, L"❇️Manifest seal (SHA-256): " + fingerprint);
	return ERROR_SUCCESS;
}

bool exhibitPathContained(const std::wstring& relative) {
	if (relative.rfind(L"exhibits\\", 0) != 0) return false;
	/* By COMPONENT: WinSxS shortens its names with ".." inside them
	   ("amd64_microsoft-onecore-i..sermode-kernel…"), and refusing the
	   substring refused every conversion of a --binary collection. */
	size_t start = 0;
	while (start <= relative.size()) {
		const size_t end = relative.find_first_of(L"\\/", start);
		const std::wstring component = relative.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
		if (component == L".." || component == L"." || component.find(L':') != std::wstring::npos) return false;
		if (end == std::wstring::npos) break;
		start = end + 1;
	}
	return true;
}

HRESULT ExhibitStoreLoad(ExhibitStoreCheck& check) {
	check = ExhibitStoreCheck{};
	g_exhibits.clear();
	const std::filesystem::path exhibitStore = exhibitStoreFolder();
	const std::filesystem::path manifestPath = exhibitStore / L"MANIFEST.json";
	const std::filesystem::path sealPath = exhibitStore / L"MANIFEST.sha256";

	// 1. The seal: the manifest's real fingerprint must be the one recorded.
	std::ifstream sealFile(sealPath);
	std::string sealLine;
	if (!sealFile || !std::getline(sealFile, sealLine)) {
		check.reason = L"seal MANIFEST.sha256 absent or unreadable";
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}
	const std::wstring recorded = toLower(decodeText(sealLine.substr(0, sealLine.find(' ')), CP_UTF8));
	check.manifestSha256 = sha256OfFile(manifestPath.wstring());
	if (check.manifestSha256.empty() || toLower(check.manifestSha256) != recorded) {
		check.reason = L"the manifest does not match its seal (recorded " + recorded
		             + L", actual " + check.manifestSha256 + L")";
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}

	// 2. The manifest, read back: every item as it was recorded.
	std::ifstream manifestFile(manifestPath, std::ios::binary);
	std::stringstream buffer;
	buffer << manifestFile.rdbuf();
	Json manifest = Json::null();
	std::wstring error;
	if (!Json::parse(decodeText(buffer.str(), CP_UTF8), manifest, error)) {
		check.reason = L"manifest unreadable: " + error;
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	const Json* items = manifest.find(L"Items");
	if (!items || items->kind() != Json::Kind::Arr) {
		check.reason = L"manifest without Items";
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	for (const auto& member : items->members()) {
		const Json& item = member.second;
		auto text = [&](const wchar_t* key) { const Json* v = item.find(key); return v ? v->text() : std::wstring(); };
		Exhibit p;
		p.method = text(L"Method");
		p.shared = item.find(L"SharedExhibit") != nullptr;
		p.extracted.volumePath = text(L"SourcePath");
		p.signature = text(L"Signature");
		p.contentStored = text(L"ContentStored") != L"false";
		if (p.contentStored) {
			const std::wstring relative = text(L"ExhibitPath");
			/* The exhibit must stay INSIDE the exhibit store: a path climbing out of
			   it ("..") in a forged manifest would have files elsewhere read. */
			if (!exhibitPathContained(relative)) {
				check.reason = L"exhibit path outside the exhibit store: " + relative;
				return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
			}
			p.extracted.outputPath = (std::filesystem::path(conf._outputDir) / relative).wstring();
		}
		if (text(L"Result") != L"OK") {
			p.extracted.result = E_FAIL;
			++check.failedAtCollection;
		}
		else {
			p.extracted.result = ERROR_SUCCESS;
			p.extracted.fingerprints.md5 = text(L"MD5");
			p.extracted.fingerprints.sha1 = text(L"SHA1");
			p.extracted.fingerprints.sha256 = text(L"SHA256");
			p.extracted.fingerprints.authenticodeSha1 = text(L"AuthenticodeSHA1");
			p.extracted.fingerprints.authenticodeSha256 = text(L"AuthenticodeSHA256");
			// The source's timestamps, for the dates of the file artefacts (ExhibitSourceTimes).
			auto date = [&](const wchar_t* key, uint64_t& out) {
				FILETIME f = {};
				if (iso8601UtcToFiletime(text(key), f)) out = ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime;
			};
			date(L"SourceCreatedUtc", p.extracted.fingerprints.creeUtc);
			date(L"SourceModifiedUtc", p.extracted.fingerprints.modifiedUtc);
			date(L"SourceMftModifiedUtc", p.extracted.fingerprints.mftModifiedUtc);
			date(L"SourceAccessedUtc", p.extracted.fingerprints.accedeUtc);
		}
		g_exhibits.push_back(std::move(p));
	}

	// 3. Every exhibit: its content must still be the one the manifest attests.
	std::map<std::wstring, std::wstring> checked;   // exhibit file -> SHA-256 (shared contents once)
	for (const Exhibit& p : g_exhibits) {
		if (FAILED(p.extracted.result) || !p.contentStored) continue;   // a fingerprint alone: no content to check
		std::wstring actual;
		const auto found = checked.find(p.extracted.outputPath);
		if (found != checked.end()) actual = found->second;
		else {
			actual = sha256OfFile(p.extracted.outputPath);
			checked.emplace(p.extracted.outputPath, actual);
		}
		if (toLower(actual) == toLower(p.extracted.fingerprints.sha256)) ++check.verified;
		else {
			++check.altered;
			if (check.firstAltered.empty()) check.firstAltered = p.extracted.outputPath;
		}
	}
	if (check.altered) {
		check.reason = std::to_wstring(check.altered) + L" exhibit(s) no longer match the manifest, e.g. "
		             + check.firstAltered;
		return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	}
	return ERROR_SUCCESS;
}

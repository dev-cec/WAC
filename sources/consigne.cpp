/*! \file
 *  \brief Implementation of the exhibit store and of its sealed manifest (see consigne.h for the procedure and the manifest's content).
 */
#include "consigne.h"
#include "tools.h"
#include "audit.h"
#include "json.h"
#include "sha.h"
#include "quickdigest5.h"
#include "long_path.h"
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
	SignatureVerdict verdict;        //!< signature check of an executable, if made
};

std::vector<Exhibit> g_exhibits;
//! Volumes actually read, by letter: recorded once each.
std::map<std::wstring, std::wstring> g_volumes;   // letter -> "serial | file system"

//! addDate (tools.h) for a date kept as a 64-bit integer, as raw_hive returns them.
void addDate(Json& o, const std::wstring& key, uint64_t filetimeUtc) {
	addDate(o, key, filetimeFromTicks(filetimeUtc));
}

//! Records a volume's serial number and file system.
std::wstring signatureVolume(const std::wstring& letter) {
	const std::wstring root = letter + L":\\";
	DWORD serial = 0;
	wchar_t fs[64] = { 0 };
	if (!GetVolumeInformationW(root.c_str(), nullptr, 0, &serial, nullptr, nullptr,
	                           fs, (DWORD)(sizeof(fs) / sizeof(fs[0]))))
		return L"";
	return to_hex((unsigned)serial, 8, HexLetters::Upper) + L" | " + fs;
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
	const std::wstring relative = pathBelow(absolute, conf._outputDir);
	return relative.empty() ? absolute : relative;   // outside the output folder: as is
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
	// 1. A working directory already populated would analyse an earlier collection.
	const std::wstring working = workingFolder();
	if (pathExists(working)) {
		bool populated = false;
		forEachFileBelow(working, [&](const std::wstring&) { populated = true; });
		if (populated) {
			log(2, L"🔥The working directory already holds files: "
			       + working
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

HRESULT ExhibitStoreCheckWorkingSpace(unsigned long long freeBytes) {
	if (freeBytes == 0) return ERROR_SUCCESS;   // measurement failed: do not block on it
	unsigned long long need = 0;
	ExhibitStoreSummary(nullptr, nullptr, &need);
	if (freeBytes >= need) return ERROR_SUCCESS;
	log(2, L"🔥Not enough space for the working copy: " + std::to_wstring(freeBytes / 1024 / 1024)
	       + L" MiB free for " + std::to_wstring(need / 1024 / 1024) + L" MiB of exhibits", ERROR_DISK_FULL);
	return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
}

void ExhibitStoreAdd(const std::vector<RawHiveExtraction>& reading,
                     const std::wstring& method, const SignatureVerdict& verdict) {
	for (const RawHiveExtraction& e : reading) {
		g_exhibits.push_back(Exhibit{ e, method, false, true, verdict });
		const std::wstring letter = letterOf(e.volumePath);
		if (!letter.empty() && g_volumes.find(letter) == g_volumes.end())
			g_volumes.emplace(letter, signatureVolume(letter));
	}
}

void ExhibitStoreAddDuplicate(const RawHiveExtraction& e, const std::wstring& method,
                              const SignatureVerdict& verdict) {
	g_exhibits.push_back(Exhibit{ e, method, true, true, verdict });
}

void ExhibitStoreAddFingerprint(const RawHiveExtraction& e, const std::wstring& method,
                                const SignatureVerdict& verdict) {
	Exhibit p{ e, method, false, false, verdict };
	p.extracted.outputPath.clear();
	g_exhibits.push_back(std::move(p));
}

bool ExhibitStoreHolds(const std::wstring& storedPath) {
	// The files written to the store so far, completed with the exhibits added since.
	static std::set<std::wstring> held;
	static size_t builtFor = 0;
	if (builtFor > g_exhibits.size()) { held.clear(); builtFor = 0; }   // the store was reset
	for (; builtFor < g_exhibits.size(); ++builtFor)
		if (SUCCEEDED(g_exhibits[builtFor].extracted.result) && g_exhibits[builtFor].contentStored)
			held.insert(toLower(g_exhibits[builtFor].extracted.outputPath));
	return held.count(toLower(storedPath)) != 0;
}

bool ExhibitStoreCurrent(const std::wstring& sourcePath, RawHiveExtraction& stored) {
	const std::wstring wanted = toLower(sourcePath);
	for (const Exhibit& p : g_exhibits)
		if (SUCCEEDED(p.extracted.result) && p.contentStored && p.extracted.shadowCopy.empty()
		    && toLower(p.extracted.volumePath) == wanted) {
			stored = p.extracted;
			return true;
		}
	return false;
}

std::wstring workingCopyOf(const std::wstring& stored);

void ExhibitStoreSharedOfShadowCopy(const std::wstring& copyId,
                                    const std::function<void(const std::wstring& source, const std::wstring& workingCopy)>& visit) {
	const std::wstring wanted = toLower(copyId);
	for (const Exhibit& p : g_exhibits)
		if (p.shared && SUCCEEDED(p.extracted.result) && toLower(p.extracted.shadowCopy) == wanted)
			visit(p.extracted.volumePath, workingCopyOf(p.extracted.outputPath));
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
	created = filetimeFromTicks(m.creeUtc);
	modified = filetimeFromTicks(m.modifiedUtc);
	accessed = filetimeFromTicks(m.accedeUtc);
	return true;
}

/*! The working copy of a file of the exhibit store: the same path under the
 *  working directory, where ExhibitStoreToWorking copied it.
 *  @param stored the file in the exhibit store
 *  @return its working copy; empty for an empty path */
std::wstring workingCopyOf(const std::wstring& stored) {
	const std::wstring relative = pathBelow(stored, exhibitStoreFolder());
	return relative.empty() ? std::wstring() : workingFolder() + L"\\" + relative;
}

const std::map<std::wstring, StoredExhibit>& ExhibitStoreIndex() {
	static const std::map<std::wstring, StoredExhibit> index = [] {
		std::map<std::wstring, StoredExhibit> built;
		/* The volume as it is now only: a file of a shadow copy has the same
		   source path, and is not the one the artefacts cite. */
		for (const Exhibit& p : g_exhibits)
			if (SUCCEEDED(p.extracted.result) && !p.extracted.volumePath.empty() && p.extracted.shadowCopy.empty())
				built.emplace(toLower(p.extracted.volumePath),
				              StoredExhibit{ p.extracted.volumePath, workingCopyOf(p.extracted.outputPath), p.contentStored,
				                             p.extracted.fingerprints.md5, p.extracted.fingerprints.sha1,
				                             p.extracted.fingerprints.sha256, p.extracted.fingerprints.authenticodeSha256,
				                             p.verdict.label, p.extracted.fingerprints.leadingSparseBytes, p.verdict.checked });
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

HRESULT ExhibitStoreToWorking(size_t* copies, unsigned long long* bytes) {
	if (copies) *copies = 0;
	if (bytes) *bytes = 0;

	const std::wstring exhibitStore = exhibitStoreFolder();
	const std::wstring working = workingFolder();
	if (!pathExists(exhibitStore)) {
		log(2, L"🔥Exhibit store absent: " + exhibitStore, ERROR_PATH_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	}
	createFolders(working);

	/*  The manifest's fingerprints, indexed by exhibit store path: the working
	 *  copy is compared with what was READ FROM THE VOLUME, not with a re-read of
	 *  the exhibit store. An already altered exhibit store would thus be caught
	 *  too. */
	std::map<std::wstring, std::wstring> expected;   // path -> SHA-256
	for (const Exhibit& p : g_exhibits)
		if (SUCCEEDED(p.extracted.result) && p.contentStored && !p.extracted.fingerprints.sha256.empty())
			expected.emplace(p.extracted.outputPath, p.extracted.fingerprints.sha256);

	size_t count = 0, failed = 0, verified = 0, existing = 0;
	unsigned long long volume = 0;
	HRESULT global = ERROR_SUCCESS;

	// The walk, the copy and the check go through Win32: an exhibit's path can
	// pass MAX_PATH, where std::filesystem fails (long_path.h, B-049).
	const bool listed = forEachFileBelow(exhibitStore, [&](const std::wstring& relative) {
		// The manifest and its seal belong to the exhibit store alone: copying
		// them to the working directory would invite changing them.
		const std::wstring name = relative.substr(relative.find_last_of(L'\\') + 1);
		if (name == L"MANIFEST.json" || name == L"MANIFEST.sha256") return;

		const std::wstring source = exhibitStore + L"\\" + relative;
		const std::wstring target = working + L"\\" + relative;
		/*  AN EXISTING WORKING COPY IS NOT OVERWRITTEN. The function is called
		 *  after each extraction phase; overwriting would undo the work already
		 *  done on the previous phase's files — in particular the replay of the
		 *  hives' transaction logs, which happens right after they are copied. */
		if (pathExists(target)) { ++existing; return; }
		if (!copyFileLong(source, target, true)) {
			log(2, L"🔥Cannot copy into the working directory: " + relative, GetLastError());
			++failed;
			global = S_FALSE;
			return;
		}
		++count;
		uint64_t size = 0;
		if (fileSizeOf(target, size)) volume += size;

		/*  VERIFYING THE COPY. Without it, a silently truncated copy — full
		 *  medium, write error — would give a working directory that does not
		 *  match the exhibit, and the whole analysis would bear on something
		 *  else. */
		const auto att = expected.find(source);
		if (att != expected.end()) {
			const std::wstring obtained = sha256OfFile(target);
			if (obtained != att->second) {
				log(2, L"🔥Working copy does not match the exhibit store: "
				       + relative + L" (expected " + att->second
				       + L", got " + obtained + L")");
				++failed;
				global = S_FALSE;
			}
			else ++verified;
		}
	});
	/* The store exists (checked above) and yet could not be listed: nothing
	   was copied, and everything that follows would read an empty working
	   copy. Said, and returned — it used to pass for "0 file copied". */
	if (!listed) {
		log(2, L"🔥Exhibit store not listed: no working copy made of " + exhibitStore, ERROR_ACCESS_DENIED);
		return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
	}

	log(2, L"❇️Working directory: " + std::to_wstring(count) + L" file(s) copied, "
	     + std::to_wstring(verified) + L" verified by fingerprint, "
	     + std::to_wstring(existing) + L" already present, "
	     + std::to_wstring(failed) + L" divergence(s)");
	if (copies) *copies = count;
	if (bytes) *bytes = volume;
	return global;
}

HRESULT ExhibitStoreWriteManifest(std::wstring* sealValue) {
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
		/* Read through a shadow copy: the source is the file as the copy
		   kept it, not as it is on the volume now. */
		if (!e.shadowCopy.empty()) o.add(L"ShadowCopyId", Json::str(e.shadowCopy));
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
		/* The signature check of an executable, valid or not: under
		   --binary-all every executable is copied, and the verdict tells which
		   are authentic. */
		if (p.verdict.checked) {
			o.add(L"SignatureVerified", Json::boolean(p.verdict.valid));
			if (p.verdict.valid && !p.verdict.label.empty()) o.add(L"Signature", Json::str(p.verdict.label));
			if (!p.verdict.valid && !p.verdict.reason.empty()) o.add(L"SignatureReason", Json::str(p.verdict.reason));
			/* Who signed, and whether the file is as signed — for a third
			   party too. For the analyst: the chain is not verified up to a
			   trusted root, anyone can sign with a certificate of their own. */
			if (!p.verdict.embeddedSigner.empty()) {
				o.add(L"EmbeddedSigner", Json::str(p.verdict.embeddedSigner));
				o.add(L"EmbeddedSignatureIntact", Json::boolean(p.verdict.embeddedIntact));
			}
			// Its chain, against the trust set of the key: tied to a trusted root, or why not.
			if (p.verdict.chainChecked) {
				o.add(L"EmbeddedChainTrusted", Json::boolean(p.verdict.chainTrusted));
				o.add(L"EmbeddedChainRoot", Json::str(p.verdict.chainRoot));
				o.add(L"EmbeddedChainReason", Json::str(p.verdict.chainReason));
				// When it was signed, by a time stamp that holds: the time the chain was judged at.
				o.add(L"EmbeddedTimeStampUtc", Json::str(p.verdict.chainSignedUtc));
				o.add(L"EmbeddedTimeStampAuthority", Json::str(p.verdict.chainTimeStampAuthority));
				// The revocation lists are those of --update-trust: known up to their issue.
				o.add(L"EmbeddedRevocationListsUtc", Json::str(p.verdict.chainRevocationListsUtc));
			}
		}
		/* A PE's build: TimeDateStamp and SizeOfImage, the key of Microsoft's
		   symbol server. An authentic Microsoft binary that was not copied can
		   thus be fetched again, identical, and its fingerprint checked. */
		if (m.peTimeDateStamp && m.peSizeOfImage) {
			const std::wstring stamp = to_hex(m.peTimeDateStamp, 8, HexLetters::Upper);
			const std::wstring size = to_hex(m.peSizeOfImage, 1);      // lower case, as the symbol server writes it
			const std::wstring name = e.volumePath.substr(e.volumePath.find_last_of(L'\\') + 1);
			o.add(L"PeTimeDateStamp", Json::str(stamp));
			o.add(L"PeSizeOfImage", Json::str(size));
			o.add(L"SymbolServerKey", Json::str(name + L"/" + stamp + size + L"/" + name));
		}
		// The two sizes diverging = truncated extraction, which a fingerprint
		// alone would not reveal (it would just be... the truncated file's).
		if (m.declaredSize != m.bytes)
			o.add(L"DeclaredBytes", Json::num(m.declaredSize));
		/* The change journal copied from its first allocated byte: the offset of
		   the copy in the stream, which the journal's record numbers count from. */
		if (m.leadingSparseBytes)
			o.add(L"LeadingSparseBytes", Json::num(m.leadingSparseBytes));
		/* Preallocated file: what follows was never written and is zero in the
		   exhibit, whatever the clusters hold on the disk. To be declared, otherwise
		   a 1 MiB exhibit of which only 135 KiB carry data simply looks "full of
		   zeros". */
		if (!m.resident && m.validDataLength < m.declaredSize)
			o.add(L"ValidDataBytes", Json::num(m.validDataLength));
		if (m.mftEntry) o.add(L"MftEntry", Json::num(*m.mftEntry));
		if (m.resident) o.add(L"ResidentData", Json::boolean(true));
		addDate(o, L"Extracted",         m.extractedUtc);
		addDate(o, L"SourceCreated",     m.creeUtc);
		addDate(o, L"SourceModified",    m.modifiedUtc);
		addDate(o, L"SourceMftModified", m.mftModifiedUtc);
		addDate(o, L"SourceAccessed",    m.accedeUtc);
		/* The same four dates from $FILE_NAME, which NTFS keeps on its own
		   terms: set side by side with the above, they reveal timestamps forged
		   after the fact (a $STANDARD_INFORMATION earlier than $FILE_NAME). */
		addDate(o, L"SourceFileNameCreated",     m.fnCreatedUtc);
		addDate(o, L"SourceFileNameModified",    m.fnModifiedUtc);
		addDate(o, L"SourceFileNameMftModified", m.fnMftModifiedUtc);
		addDate(o, L"SourceFileNameAccessed",    m.fnAccessedUtc);
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
		/* Checked once written too: a key filled during the write left a
		   truncated manifest, sealed as it was and reported written. */
		if (!f) {
			log(2, L"🔥Exhibit manifest not written whole: " + path.wstring());
			return E_FAIL;
		}
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
		if (!f) {
			log(2, L"🔥Manifest seal not written whole: " + seal.wstring());
			return E_FAIL;
		}
	}

	log(2, L"❇️Exhibit manifest: " + std::to_wstring(count) + L" exhibit(s), "
	     + std::to_wstring(failed) + L" failure(s), "
	     + std::to_wstring(total / 1024 / 1024) + L" MiB");
	log(2, L"❇️Manifest seal (SHA-256): " + fingerprint);
	if (sealValue) *sealValue = fingerprint;
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
		p.extracted.shadowCopy = text(L"ShadowCopyId");
		p.verdict.checked = item.find(L"SignatureVerified") != nullptr;
		p.verdict.valid = text(L"SignatureVerified") == L"true";
		p.verdict.label = text(L"Signature");
		p.verdict.reason = text(L"SignatureReason");
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
				if (iso8601UtcToFiletime(text(key), f)) out = ticksFromFiletime(f);
			};
			date(L"SourceCreatedUtc", p.extracted.fingerprints.creeUtc);
			date(L"SourceModifiedUtc", p.extracted.fingerprints.modifiedUtc);
			date(L"SourceMftModifiedUtc", p.extracted.fingerprints.mftModifiedUtc);
			date(L"SourceAccessedUtc", p.extracted.fingerprints.accedeUtc);
			auto count = [&](const wchar_t* key, uint64_t& out) {
				const std::wstring digits = text(key);
				wchar_t* end = nullptr;
				const unsigned long long value = digits.empty() ? 0 : wcstoull(digits.c_str(), &end, 10);
				if (end && *end == L'\0') out = value;
			};
			// Its size: what its working copy takes (ExhibitStoreCheckWorkingSpace).
			count(L"Bytes", p.extracted.fingerprints.bytes);
			// Where the copy of the change journal starts in its stream (see ExtractStreamRaw).
			count(L"LeadingSparseBytes", p.extracted.fingerprints.leadingSparseBytes);
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

HRESULT ExhibitStoreProduce(const std::wstring& path, const std::string& bytes, const std::wstring& source,
                            const std::wstring& method) {
	createFolders(parentFolder(path));
	{
		// Binary mode: the fingerprints are those of the bytes on the medium.
		std::ofstream f(std::filesystem::path(extendedPath(path)), std::ios::binary);
		f.write(bytes.data(), (std::streamsize)bytes.size());
		if (!f) {
			log(2, L"🔥Exhibit not written: " + path);
			return E_FAIL;
		}
	}
	/* Its working copy, written from the same bytes at once: what WAC
	   produces is read back right away (the live state, by the detection of
	   the volumes), and the exhibit store is not read again (backlog B-040). */
	{
		const std::wstring working = workingCopyOf(path);
		createFolders(parentFolder(working));
		std::ofstream w(std::filesystem::path(extendedPath(working)), std::ios::binary);
		w.write(bytes.data(), (std::streamsize)bytes.size());
		if (!w) {
			log(2, L"🔥Working copy not written: " + working);
			return E_FAIL;
		}
	}
	RawHiveExtraction e;
	e.volumePath = source;
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
	FILETIME now = { 0, 0 };
	GetSystemTimeAsFileTime(&now);
	e.fingerprints.extractedUtc = ticksFromFiletime(now);
	ExhibitStoreAdd({ e }, method);
	return ERROR_SUCCESS;
}

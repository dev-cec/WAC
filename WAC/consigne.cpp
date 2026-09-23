#include "consigne.h"
#include "tools.h"
#include "audit.h"
#include "json.h"
#include "sha.h"
#include <fstream>
#include <filesystem>
#include <map>

/*  exhibitStore.cpp — see exhibitStore.h for the procedure and the manifest's content.
 *  Here, the implementation.
 */

namespace {

//! An exhibit in the manifest.
struct Exhibit {
	RawHiveExtraction extracted;
	std::wstring   method;
	bool           shared = false;   //!< content already stored under another exhibit
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
		std::filesystem::path(absolute), std::filesystem::path(string_to_wstring(conf._outputDir)), ec);
	if (ec || rel.empty()) return absolute;      // outside the output folder: as is
	return rel.wstring();
}

} // namespace

std::wstring exhibitStoreFolder() {
	return string_to_wstring(conf._outputDir) + L"\\consigne";
}

std::wstring workingFolder() {
	return string_to_wstring(conf._outputDir) + L"\\travail";
}

unsigned long long ExhibitStoreFreeSpace() {
	ULARGE_INTEGER free = { 0 };
	const std::wstring output = string_to_wstring(conf._outputDir);
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
			log(2, L"🔥Le répertoire de travail contient déjà des fichiers : "
			       + working.wstring()
			       + L" — une collecte antérieure serait analysée à la place de "
			       L"celle-ci. Utilisez --output vers un dossier neuf.",
			    ERROR_DIR_NOT_EMPTY);
			return HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
		}
	}

	// 2. Available space. The need is doubled: exhibit store + working copy.
	const unsigned long long free = ExhibitStoreFreeSpace();
	if (free == 0) {
		// Information unavailable: do not block on a failed measurement.
		log(2, L"🔥Espace libre indéterminé sur le support de collecte : "
		       L"vérification ignorée");
		return ERROR_SUCCESS;
	}
	const unsigned long long need = estimatedNeed * 2;
	log(2, L"❇️Support de collecte : " + std::to_wstring(free / 1024 / 1024)
	     + L" Mio libres, " + std::to_wstring(need / 1024 / 1024)
	     + L" Mio estimés nécessaires (consigne + travail)");
	if (free < need) {
		log(2, L"🔥Place insuffisante sur le support de collecte : "
		       + std::to_wstring(free / 1024 / 1024) + L" Mio libres pour "
		       + std::to_wstring(need / 1024 / 1024) + L" Mio nécessaires",
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

void ExhibitStoreSummary(size_t* exhibits, size_t* failures, unsigned long long* bytes) {
	size_t nb = 0, ko = 0;
	unsigned long long total = 0;
	for (const Exhibit& p : g_exhibits) {
		++nb;
		if (FAILED(p.extracted.result)) ++ko;
		// Shared content takes room in the exhibit store only once.
		else if (!p.shared) total += p.extracted.fingerprints.bytes;
	}
	if (exhibits) *exhibits = nb;
	if (failures) *failures = ko;
	if (bytes) *bytes = total;
}

HRESULT ExhibitStoreToWorking(size_t* copies, unsigned long long* bytes) {
	if (copies) *copies = 0;
	if (bytes) *bytes = 0;

	const std::filesystem::path exhibitStore = exhibitStoreFolder();
	const std::filesystem::path working  = workingFolder();
	std::error_code ec;
	if (!std::filesystem::exists(exhibitStore, ec)) {
		log(2, L"🔥Consigne absente : " + exhibitStore.wstring(), ERROR_PATH_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	}
	std::filesystem::create_directories(working, ec);

	/*  The manifest's fingerprints, indexed by exhibit store path: the working
	 *  copy is compared with what was READ FROM THE VOLUME, not with a re-read of
	 *  the exhibit store. An already altered exhibit store would thus be caught
	 *  too. */
	std::map<std::wstring, std::wstring> expected;   // path -> SHA-256
	for (const Exhibit& p : g_exhibits)
		if (SUCCEEDED(p.extracted.result) && !p.extracted.fingerprints.sha256.empty())
			expected.emplace(p.extracted.outputPath, p.extracted.fingerprints.sha256);

	size_t nb = 0, ko = 0, verifies = 0, existing = 0;
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
		if (name == L"MANIFESTE.json" || name == L"MANIFESTE.sha256") continue;

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
			log(2, L"🔥Copie vers le travail impossible : " + relative.wstring());
			++ko;
			global = S_FALSE;
			continue;
		}
		++nb;
		volume += (unsigned long long)std::filesystem::file_size(target, ec);

		/*  VERIFYING THE COPY. Without it, a silently truncated copy — full
		 *  medium, write error — would give a working directory that does not
		 *  match the exhibit, and the whole analysis would bear on something
		 *  else. */
		const auto att = expected.find(e.path().wstring());
		if (att != expected.end()) {
			const std::wstring obtained = sha256OfFile(target.wstring());
			if (obtained != att->second) {
				log(2, L"🔥Copie de travail non conforme à la consigne : "
				       + relative.wstring() + L" (attendu " + att->second
				       + L", obtenu " + obtained + L")");
				++ko;
				global = S_FALSE;
			}
			else ++verifies;
		}
	}

	log(2, L"❇️Travail : " + std::to_wstring(nb) + L" fichier(s) recopié(s), "
	     + std::to_wstring(verifies) + L" vérifié(s) par empreinte, "
	     + std::to_wstring(existing) + L" déjà présent(s), "
	     + std::to_wstring(ko) + L" écart(s)");
	if (copies) *copies = nb;
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

	size_t nb = 0, ko = 0;
	unsigned long long total = 0;
	ExhibitStoreSummary(&nb, &ko, &total);

	Json guard = Json::obj();
	guard.add(L"ExhibitDirectory",  Json::str(L"consigne"));
	guard.add(L"WorkingDirectory",  Json::str(L"travail"));
	guard.add(L"Statement", Json::str(
		L"Les fichiers de « consigne » sont les copies brutes telles que lues du "
		L"volume : elles ne sont jamais réouvertes en écriture. Toute analyse, et "
		L"toute modification (rejeu des journaux de transaction, alignement du bloc "
		L"de base d'une ruche), portent sur « travail », recopié depuis la consigne "
		L"et vérifié par empreinte. Aucune écriture n'a été faite sur le système "
		L"examiné."));
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
	guard.add(L"ItemCount",            Json::num((unsigned long long)nb));
	guard.add(L"FailedCount",          Json::num((unsigned long long)ko));
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
		o.add(L"ExhibitPath", Json::str(outputRelative(e.outputPath)));
		o.add(L"Method",      Json::str(p.method));
		if (FAILED(e.result)) {
			// An exhibit missing from the manifest would read as never looked for.
			o.add(L"Result", Json::str(L"0x" + to_hex(e.result) + L" "
			                           + getErrorMessage(e.result)));
			exhibits.push(std::move(o));
			continue;
		}
		o.add(L"Result",        Json::str(L"OK"));
		o.add(L"MD5",           Json::str(m.md5));
		o.add(L"SHA1",          Json::str(m.sha1));
		o.add(L"SHA256",        Json::str(m.sha256));
		o.add(L"Bytes",         Json::num(m.bytes));
		/* Content identical, byte for byte (SHA-256), to an exhibit already
		   stored: ExhibitPath points to it, and it was not copied again. The source
		   remains an exhibit in its own right — its path, $MFT entry and timestamps
		   are its own. */
		if (p.shared) o.add(L"SharedExhibit", Json::boolean(true));
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
	const std::filesystem::path path = exhibitStore / L"MANIFESTE.json";
	{
		std::wofstream f;
		f.open(path);
		if (!f) {
			log(2, L"🔥Manifeste de consigne non écrit : " + path.wstring());
			return E_FAIL;
		}
		f << ansi_to_utf8(root.dump(0));
		f.close();
	}

	/*  SEAL. A manifest cannot carry its own fingerprint: it is written beside
	 *  it, after it. Without that second file, a retouched manifest would go
	 *  undetected — and the manifest is precisely what attests to the
	 *  exhibits. */
	const std::wstring fingerprint = sha256OfFile(path.wstring());
	const std::filesystem::path seal = exhibitStore / L"MANIFESTE.sha256";
	{
		std::wofstream f;
		f.open(seal);
		if (!f || fingerprint.empty()) {
			log(2, L"🔥Sceau du manifeste non écrit : " + seal.wstring());
			return E_FAIL;
		}
		// sha256sum format: "<fingerprint>  <name>", readable by common tools
		// without knowing anything about WAC.
		f << ansi_to_utf8(fingerprint + L"  MANIFESTE.json\n");
		f.close();
	}

	log(2, L"❇️Manifeste de consigne : " + std::to_wstring(nb) + L" pièce(s), "
	     + std::to_wstring(ko) + L" échec(s), "
	     + std::to_wstring(total / 1024 / 1024) + L" Mio");
	log(2, L"❇️Sceau du manifeste (SHA-256) : " + fingerprint);
	return ERROR_SUCCESS;
}

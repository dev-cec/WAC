/*! \file
 *  \brief Implementation of the fingerprinting and collection of the files cited by artefacts (see binaires.h).
 */
#include "binaires.h"
#include <map>
#include <fstream>
#include <chrono>
#include <deque>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <memory>
#include <filesystem>
#include "tools.h"
#include "raw_hive.h"
#include "exhibit_reader.h"
#include "consigne.h"
#include "running_machine.h"
#include "authenticode.h"
#include "trust_set.h"
#include "audit.h"
#include "sha.h"
#include "quickdigest5.h"
#include "xml_light.h"
#include <set>
#include <vector>

namespace {

/*! Where the cited files are read: the examined volume, or under --convert the
 *  exhibit store of the collection (exhibit_reader.h) — never the disk of the
 *  analysis workstation. */
std::unique_ptr<FileSource> g_reader;
std::map<std::wstring, BinaryFingerprint> g_cache;      // key: lowercase path
std::map<std::wstring, std::wstring> g_byContent;    // SHA-256 -> exhibit in the store
size_t g_read = 0, g_collected = 0, g_sansPlace = 0, g_duplicates = 0;
unsigned long long g_bytes = 0, g_avoidedBytes = 0;
size_t g_authenticated = 0, g_catalogsRead = 0;
size_t g_deltas = 0;                                    // Windows differential files met (--collect)

/*! Time spent per phase of the reading of the executables, in milliseconds:
 *  where a whole-volume reading spends its time is measured, not guessed. */
struct PhaseTimes { unsigned long long catalogs = 0, packages = 0, reading = 0, copying = 0; };
PhaseTimes g_times;

/*! Adds the time of its scope to a counter of g_times. */
class PhaseTimer {
public:
	explicit PhaseTimer(unsigned long long& counter) : counter_(counter), start_(GetTickCount64()) {}
	~PhaseTimer() { counter_ += GetTickCount64() - start_; }
	PhaseTimer(const PhaseTimer&) = delete;
	PhaseTimer& operator=(const PhaseTimer&) = delete;
private:
	unsigned long long& counter_;
	const unsigned long long start_;
};
unsigned long long g_authenticatedBytes = 0;
std::set<std::wstring> g_catalogsUsed;
/*! Catalogs read but not signed by Microsoft — third-party drivers and
 *  software (oemNN.cat): they are what signs a third-party binary WAC
 *  collects, and the analysis needs them to check that signature. */
std::set<std::wstring> g_thirdPartyCatalogs;
const size_t CATALOGUE_MAX = 64 * 1024 * 1024;       // a catalog beyond that: ignored
unsigned long long g_incoming = 0;                      // counter of incoming files

/*! INCOMING directory, on the collection medium but outside the exhibit store.
 *
 *  DEDUPLICATION. A file's content is only known once it has been read. It is
 *  therefore written here first, hashed on the way, then RENAMED into the
 *  exhibit store if new, or deleted if it is already there under another path.
 *  The exhibit store thus only receives final exhibits: nothing is written then
 *  erased in it, and an interrupted collection leaves no temporary file there.
 *  A single read of the volume per file. */
std::wstring stagingFolder() {
	return exhibitStoreFolder() + L".staging";
}

/*! Space kept free on the collection medium: below it, files are hashed
 *  without being copied. Each exhibit is written twice (exhibit store then
 *  working copy), and the event logs, processed last, must still find room. */
const unsigned long long RESERVE = 1ULL << 30;

/*! What is collected: executables, libraries, drivers, the scripts a task or a
 *  Run key can launch, and Office documents ABLE TO CARRY MACROS.
 *
 *  MACRO DOCUMENTS. A booby-trapped document is an intrusion vector as common as
 *  an executable, and it shows in the traces: target of a shortcut or a jump
 *  list, file loaded by WINWORD.EXE or EXCEL.EXE in their Prefetch. Only the
 *  formats where VBA can live are kept: legacy binary formats (.doc, .xls,
 *  .ppt…), "m" formats (.docm, .xlsm…), .xlsb, templates and add-ins,
 *  Publisher, Visio and Access. .docx/.xlsx/.pptx cannot hold VBA: they are
 *  only hashed, like any document — copying them would turn the collection
 *  into a copy of the user's files. */
bool worthCollecting(const std::wstring& path) {
	const size_t point = path.find_last_of(L'.');
	if (point == std::wstring::npos || path.find(L'\\', point) != std::wstring::npos) return false;
	static const wchar_t* const extensions[] = {
		// executables, libraries, drivers
		L"exe", L"dll", L"sys", L"ocx", L"cpl", L"scr", L"drv", L"efi", L"com", L"msi",
		// scripts
		L"ps1", L"psm1", L"bat", L"cmd", L"vbs", L"vbe", L"js", L"jse", L"wsf", L"wsh", L"hta",
		// Word
		L"doc", L"docm", L"dot", L"dotm",
		// Excel (xll and wll are DLLs loaded by Excel and Word)
		L"xls", L"xlsm", L"xlsb", L"xlt", L"xltm", L"xla", L"xlam", L"xll", L"wll",
		// PowerPoint
		L"ppt", L"pptm", L"pot", L"potm", L"pps", L"ppsm", L"ppa", L"ppam",
		// Publisher, Visio, Access
		L"pub", L"vsd", L"vsdm", L"vstm", L"vssm", L"mdb", L"accdb", L"accde",
	};
	const std::wstring ext = toLower(path.substr(point + 1));
	for (const wchar_t* e : extensions) if (ext == e) return true;
	return false;
}

} // namespace

namespace {

/*! Buffer that keeps what is written to it: reading a catalog into memory. */
class Collector : public std::streambuf {
public:
	std::vector<uint8_t> bytes;
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) bytes.push_back((uint8_t)c);
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		if (bytes.size() + (size_t)n <= CATALOGUE_MAX) bytes.insert(bytes.end(), s, s + n);
		return n;
	}
};

/*! Forwards what it receives to several buffers, as the content is read
 *  once: the PE analysis, the in-memory text of a PowerShell script, the
 *  block digests of a package file. Null buffers are skipped. */
class Fanout : public std::streambuf {
public:
	explicit Fanout(std::initializer_list<std::streambuf*> targets) {
		for (std::streambuf* t : targets) if (t) targets_.push_back(t);
	}
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) for (std::streambuf* t : targets_) t->sputc((char)c);
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		for (std::streambuf* t : targets_) t->sputn(s, n);
		return n;
	}
private:
	std::vector<std::streambuf*> targets_;
};

/*! SHA-256 of each 64 KiB block of a content, as an AppX block map lists
 *  them (see PackageFile). */
class BlockDigests : public std::streambuf {
public:
	static const size_t BLOCK = 65536;
	//! Ends the last block. @return the digests, 32 bytes each, in order.
	const std::vector<std::string>& finish() {
		if (inBlock_) close();
		return digests_;
	}
	//! @return the bytes received
	uint64_t size() const { return size_; }
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) { const char b = (char)c; xsputn(&b, 1); }
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		const uint8_t* p = reinterpret_cast<const uint8_t*>(s);
		size_t left = (size_t)n;
		while (left) {
			const size_t take = std::min(left, BLOCK - inBlock_);
			current_.update(p, take);
			inBlock_ += take; size_ += take; p += take; left -= take;
			if (inBlock_ == BLOCK) close();
		}
		return n;
	}
private:
	void close() {
		uint8_t d[32];
		current_.digest(d);
		digests_.emplace_back((const char*)d, 32);
		current_ = Sha256Stream();
		inBlock_ = 0;
	}
	Sha256Stream current_;
	size_t inBlock_ = 0;
	uint64_t size_ = 0;
	std::vector<std::string> digests_;
};

/*! Keeps the first bytes of a content, and forwards everything to the next
 *  buffer: the signature of a format is known without a second read. */
class Head : public std::streambuf {
public:
	explicit Head(std::streambuf* next) : next_(next) {}
	//! @return the first bytes read (up to 8)
	const std::vector<uint8_t>& bytes() const { return bytes_; }
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) {
			if (bytes_.size() < 8) bytes_.push_back((uint8_t)c);
			next_->sputc((char)c);
		}
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		for (std::streamsize i = 0; i < n && bytes_.size() < 8; ++i) bytes_.push_back((uint8_t)s[i]);
		next_->sputn(s, n);
		return n;
	}
private:
	std::streambuf* next_;
	std::vector<uint8_t> bytes_;
};

/*! A Windows differential file (MSDELTA "PA30"/"PA31", possibly after a
 *  4-byte CRC): what WinSxS keeps in the r\ and f\ folders of its components
 *  to rebuild other versions of a file. It carries the name and extension of
 *  the binary (.dll, .exe) but is NOT an executable: 12,700 of them, 1.3 GB,
 *  were collected from a plain Windows 11 as "unauthenticated binaries".
 *  Recognised by its content, never by its folder — an intruder can name a
 *  folder "r". */
bool isWindowsDelta(const std::vector<uint8_t>& head) {
	auto magicAt = [&](size_t at) {
		return head.size() >= at + 4 && head[at] == 'P' && head[at + 1] == 'A' && head[at + 2] == '3'
		       && (head[at + 3] == '0' || head[at + 3] == '1');
	};
	return magicAt(0) || magicAt(4);
}

//! Scripts whose embedded signature is verified (see EvaluatePowerShellScript).
bool isPowerShellScript(const std::wstring& path) {
	const size_t point = path.find_last_of(L'.');
	if (point == std::wstring::npos) return false;
	const std::wstring ext = toLower(path.substr(point + 1));
	return ext == L"ps1" || ext == L"psm1" || ext == L"psd1" || ext == L"ps1xml"
	    || ext == L"psc1" || ext == L"cdxml";
}

//! Hexadecimal digest (64 characters) -> 32 bytes.
bool bytesFromHex(const std::wstring& hexa, uint8_t output[32]) {
	if (hexa.size() != 64) return false;
	for (size_t i = 0; i < 32; ++i) {
		unsigned v = 0;
		for (size_t k = 0; k < 2; ++k) {
			const wchar_t c = hexa[2 * i + k];
			v <<= 4;
			if (c >= L'0' && c <= L'9') v |= c - L'0';
			else if (c >= L'A' && c <= L'F') v |= c - L'A' + 10;
			else if (c >= L'a' && c <= L'f') v |= c - L'a' + 10;
			else return false;
		}
		output[i] = (uint8_t)v;
	}
	return true;
}

/*! Where Windows keeps its signature catalogs. CatRoot holds those of the
 *  installed system; the catalogs of the COMPONENTS (WinSxS) and of the
 *  servicing packages are elsewhere. Reading CatRoot alone left 14,023 WinSxS
 *  files of a plain Windows 11 unauthenticated, hence collected. */
std::vector<std::wstring> catalogFolders() {
	return { conf.systemDrive + L"\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}",
	         conf.systemDrive + L"\\Windows\\WinSxS\\Catalogs",
	         conf.systemDrive + L"\\Windows\\servicing\\Packages" };
}

/*! Index of the machine's Microsoft catalogs, built on first request — hence
 *  only if a binary to collect is met. Catalogs are read raw, IN MEMORY:
 *  nothing is written, and no service is solicited (see authenticode.h). */
/*! The roots third-party signatures are tied to: those of the trust set of
 *  the key, when it is usable; nullptr otherwise — third-party signatures are
 *  then not checked. Built on first use, before the analysis threads start
 *  (BinariesCollectAll), which only read it. */
const ThirdPartyRoots* thirdPartyRoots() {
	static std::unique_ptr<ThirdPartyRoots> roots;
	static bool done = false;
	if (done) return roots.get();
	done = true;
	const TrustSet& set = CollectionTrustSet();
	FILETIME now;
	GetSystemTimeAsFileTime(&now);
	if (set.usable)
		roots.reset(new ThirdPartyRoots(set.roots, set.rootCertificates, set.disallowed, set.revokedAuthorities,
		                                set.revocationLists, ((uint64_t)now.dwHighDateTime << 32) | now.dwLowDateTime));
	return roots.get();
}

IndexCatalogues& catalogues() {
	static IndexCatalogues index;
	static bool done = false;
	if (done) return index;
	done = true;
	PhaseTimer timer(g_times.catalogs);
	size_t read = 0;
	for (const std::wstring& folder : catalogFolders()) {
		std::vector<RawDirEntry> entries;
		const HRESULT hr = g_reader->list(folder, entries);
		if (FAILED(hr)) {
			log(2, L"🔥Signature catalogs unreadable: " + folder, hr);
			continue;
		}
		std::set<uint64_t> seen;                  // a file can also appear under its short name
		for (const RawDirEntry& e : entries) {
			if (e.isDirectory || !seen.insert(e.mftIndex).second) continue;
			if (e.name.size() < 4 || toLower(e.name.substr(e.name.size() - 4)) != L".cat") continue;
			const std::wstring path = folder + L"\\" + e.name;
			Collector c;
			RawHiveExtraction line;
			if (FAILED(g_reader->read(path, std::wstring(), line, &c))) continue;
			++read;
			// Named by its path: two folders may share a name.
			if (!index.add(path, c.bytes.data(), c.bytes.size())) g_thirdPartyCatalogs.insert(path);
		}
	}
	g_catalogsRead = read;
	log(2, L"❇️Signature catalogs: " + std::to_wstring(read) + L" read, "
	     + std::to_wstring(index.catalogues()) + L" kept (Microsoft signature verified), "
	     + std::to_wstring(index.rejected()) + L" refused, "
	     + std::to_wstring(index.fingerprints()) + L" fingerprints");
	return index;
}

/*! A file of a signed AppX / MSIX package, as its block map describes it. */
struct PackageFile {
	uint64_t size = 0;                  //!< declared size
	std::vector<std::string> blocks;    //!< SHA-256 of each 64 KiB block (32 bytes each)
	std::wstring package;               //!< the package's folder ("X:\\…\\")
	std::wstring signer;                //!< who signed the package
};
std::map<std::wstring, PackageFile> g_packageFiles;   // by path in lower case
std::set<std::wstring> g_packagesProbed;               // folders already looked at (lower case)
std::set<std::wstring> g_packagesUsed;                 // package folders that authenticated a file

/*! Loads the block map of the package whose folder this is, if its signature
 *  holds (see VerifyPackageSignature): signed by the Store or Microsoft, and
 *  the block map's SHA-256 the one the signature carries. Read raw, in memory.
 *  @param folder the package's folder, with its trailing backslash
 *  @return true if the folder is a package whose block map was loaded */
bool loadPackage(const std::wstring& folder) {
	PhaseTimer timer(g_times.packages);
	Collector signature, blockMap;
	RawHiveExtraction l1, l2;
	if (FAILED(g_reader->read(folder + L"AppxSignature.p7x", std::wstring(), l1, &signature))) return false;
	if (FAILED(g_reader->read(folder + L"AppxBlockMap.xml", std::wstring(), l2, &blockMap))) return false;
	const PackageSignature s = VerifyPackageSignature(signature.bytes.data(), signature.bytes.size());
	if (!s.valid) {
		log(2, L"🔥Package not authenticated (" + decodeText(s.reason) + L"): " + folder);
		return false;
	}
	uint8_t actual[32];
	sha256Bytes(blockMap.bytes.data(), blockMap.bytes.size(), actual);
	if (s.blockMapSha256.compare(0, 32, (const char*)actual, 32) != 0) {
		log(2, L"🔥Package block map does not match its signature: " + folder);
		return false;
	}
	const std::unique_ptr<XmlNode> root = xmlParse(decodeText(
		std::string(blockMap.bytes.begin(), blockMap.bytes.end()), CP_UTF8));
	if (!root) return false;
	size_t files = 0;
	for (const XmlNode* f : root->descendants(L"File")) {
		PackageFile entry;
		entry.package = folder;
		entry.signer = s.signer;
		try { entry.size = std::stoull(f->attribute(L"Size")); } catch (...) { continue; }
		for (const auto& block : f->children)
			if (block->name == L"Block") {
				const std::wstring hash = block->attribute(L"Hash");
				const std::vector<uint8_t> raw = DecodeBase64(std::string(hash.begin(), hash.end()));
				entry.blocks.emplace_back(raw.begin(), raw.end());
			}
		g_packageFiles[toLower(folder + f->attribute(L"Name"))] = std::move(entry);
		++files;
	}
	log(3, L"🔈Package authenticated (" + s.signer + L"), " + std::to_wstring(files) + L" file(s): " + folder);
	return true;
}

/*! The block map entry of a file, if it lies in a signed package. The package
 *  is found by its folder, going up from the file's (at most 8 levels), each
 *  folder looked at once.
 *  @param path the file ("X:\\…")
 *  @return the entry, or nullptr */
const PackageFile* packageFileOf(const std::wstring& path) {
	const std::wstring key = toLower(path);
	std::wstring folder = path;
	for (int level = 0; level < 8; ++level) {
		const size_t cut = folder.find_last_of(L'\\', folder.size() - 2);
		if (cut == std::wstring::npos || cut < 2) break;
		folder = folder.substr(0, cut + 1);
		if (!g_packagesProbed.insert(toLower(folder)).second) continue;
		if (loadPackage(folder)) break;
	}
	const auto found = g_packageFiles.find(key);
	return found == g_packageFiles.end() ? nullptr : &found->second;
}

/*! Copies into the exhibit store the files that justified not collecting
 *  others (catalogs, package signatures and block maps), once each.
 *  @param sources the files ("X:\\…")
 *  @param method the collection method, as recorded */
void recordJustifications(const std::vector<std::wstring>& sources, const std::wstring& method) {
	std::vector<RawHiveExtraction> reading;
	for (const std::wstring& source : sources) {
		const std::wstring target = pathUnder(exhibitStoreFolder(), source);
		std::error_code ec;
		if (std::filesystem::exists(target, ec)) continue;
		std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);
		RawHiveExtraction line;
		g_reader->read(source, target, line);    // a failure is recorded as such
		reading.push_back(std::move(line));
	}
	if (!reading.empty()) ExhibitStoreAdd(reading, method);
}

/*! The file source of this run (see g_reader). */
std::unique_ptr<FileSource> openReader() {
	if (conf.mode == RunMode::Convert) return std::make_unique<ExhibitReader>();
	return std::make_unique<RawReader>();
}

/*! True while the collection medium keeps its reserve. In a full run, each
 *  collected exhibit will also be copied to the working directory at the end:
 *  that room is already owed. A --collect run makes no working copy of the
 *  binaries (the conversion rebuilds it elsewhere), so nothing is owed. */
bool roomLeft() {
	const unsigned long long free = ExhibitStoreFreeSpace();
	const unsigned long long owed = conf.mode == RunMode::Collect ? 0 : g_bytes;
	return free == 0 || free >= RESERVE + owed;
}

/*! A new file of the incoming directory (see stagingFolder).
 *  @return its path; the directory is created if needed */
std::wstring newStagingFile() {
	std::error_code ec;
	std::filesystem::create_directories(stagingFolder(), ec);
	return stagingFolder() + L"\\" + std::to_wstring(++g_incoming) + L".bin";
}

/*! Moves a file read into the incoming directory to the exhibit store —
 *  renamed there if its content is new, declared as sharing an exhibit
 *  already stored otherwise (deduplication) — and records it in the manifest,
 *  failure included. The incoming file is gone afterwards.
 *  @param path the file on the volume ("X:\\…")
 *  @param staged its copy in the incoming directory
 *  @param result the result of the read
 *  @param line the record of the read, fingerprints included
 *  @param method collection method, as recorded
 *  @param verdict the signature check, for an executable
 *  @return the result, or ERROR_WRITE_FAULT if it could not be stored */
HRESULT recordStaged(const std::wstring& path, const std::wstring& staged, HRESULT result,
                     RawHiveExtraction& line, const std::wstring& method, const SignatureVerdict& verdict) {
	std::error_code ec;
	const std::wstring target = pathUnder(exhibitStoreFolder(), path);
	if (FAILED(result)) {
		line.outputPath = target;
		ExhibitStoreAdd({ line }, method, verdict);
	}
	else {
		const auto already = g_byContent.find(line.fingerprints.sha256);
		if (already != g_byContent.end()) {
			line.outputPath = already->second;
			ExhibitStoreAddDuplicate(line, method + L" ; content identical (SHA-256) "
			                                        L"to an exhibit already recorded, not copied again", verdict);
			++g_duplicates;
			g_avoidedBytes += line.fingerprints.bytes;
		}
		else {
			std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);
			std::filesystem::rename(staged, target, ec);
			line.outputPath = target;
			if (ec) {
				log(2, L"🔥Cannot record as an exhibit: " + target);
				line.result = result = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
			}
			else {
				g_byContent.emplace(line.fingerprints.sha256, target);
				++g_collected;
				g_bytes += line.fingerprints.bytes;
			}
			ExhibitStoreAdd({ line }, method, verdict);
		}
	}
	std::filesystem::remove(staged, ec);    // whatever is left in the incoming directory: nothing
	return result;
}

/*! Copies a file of the volume into the exhibit store, through the incoming
 *  directory: written there first, hashed on the way, then renamed into the
 *  store if its content is new, or declared as sharing an exhibit already
 *  stored (deduplication). Recorded in the manifest in every case, failure
 *  included.
 *  @param path the file ("X:\…")
 *  @param purpose why it is collected, for the manifest's method
 *  @param line receives the record, fingerprints included
 *  @param verdict the signature check of an executable, for the manifest
 *  @return the result of the read, or ERROR_WRITE_FAULT if it could not be stored */
HRESULT storeExhibit(const std::wstring& path, const std::wstring& purpose, RawHiveExtraction& line,
                     const SignatureVerdict& verdict = {}) {
	const std::wstring staged = newStagingFile();
	const HRESULT result = g_reader->read(path, staged, line);
	const std::wstring method = L"Raw NTFS reading (\\\\.\\" + path.substr(0, 2)
	                          + L" — $MFT, directory indexes, $DATA attribute); " + purpose
	                          + (conf.mode == RunMode::Collect ? READ_IN_PLACE : L"");
	return recordStaged(path, staged, result, line, method, verdict);
}

/*! The analysis of an executable's content, fed as the content passes —
 *  read from the volume, or held in memory: the PE (Authenticode), the first
 *  bytes (a Windows differential file), a PowerShell script's text, a package
 *  file's blocks. It touches no shared state (the catalogs are only read), so
 *  it runs on any thread; what the verdict changes in the counters is left to
 *  noteVerdict, on the main thread. */
class ContentAnalysis {
public:
	ContentAnalysis(const std::wstring& path, const PackageFile* package)
		: powershell_(isPowerShellScript(path)), package_(package),
		  fanout_{ &pe_, powershell_ ? &text_ : nullptr, package ? &blocks_ : nullptr }, head_(&fanout_) {}
	ContentAnalysis(const ContentAnalysis&) = delete;
	ContentAnalysis& operator=(const ContentAnalysis&) = delete;

	//! @return where to feed the content
	std::streambuf* input() { return &head_; }
	//! To be called once the whole content is fed.
	void finishContent() { pe_.finish(); }
	//! @return whether the content is a PE (after finishContent)
	bool isPe() const { return pe_.isPe(); }

	/*! The PE fields of the record, whether the file is a Windows differential
	 *  file, and the verdict. A non-PE is looked up in the catalogs by its
	 *  SHA-256: the record must carry it.
	 *  @param line the record of the read
	 *  @param verdict receives the verdict
	 *  @param windowsDelta receives whether it is a differential file */
	void conclude(RawHiveExtraction& line, VerdictMicrosoft& verdict, bool& windowsDelta) {
		windowsDelta = !pe_.isPe() && isWindowsDelta(head_.bytes());
		if (pe_.isPe()) {
			line.fingerprints.authenticodeSha1 = toHexadecimal(pe_.sha1(), 20);
			line.fingerprints.authenticodeSha256 = toHexadecimal(pe_.sha256(), 32);
			line.fingerprints.peTimeDateStamp = pe_.timeDateStamp();
			line.fingerprints.peSizeOfImage = pe_.sizeOfImage();
		}
		/* PE: Authenticode digest. Script or document: SHA-256 of the raw bytes in
		   the catalogs, then embedded PowerShell signature. */
		if (pe_.isPe()) verdict = EvaluatePe(pe_, catalogues(), thirdPartyRoots());
		else {
			uint8_t h[32];
			if (bytesFromHex(line.fingerprints.sha256, h)) verdict = EvaluateByCatalog(h, catalogues());
			if (!verdict.microsoft && powershell_) {
				const VerdictMicrosoft ps = EvaluatePowerShellScript(text_.bytes.data(), text_.bytes.size());
				if (ps.microsoft || ps.reason != "no embedded signature") verdict = ps;
			}
		}
		/* A file of a signed package — a Store application: its size and every
		   block match what the package's signed block map says. A file added to
		   the folder after installation is in no block map; a modified one fails
		   on its first altered block. Either is collected. */
		if (verdict.microsoft || !package_) return;
		if (blocks_.size() == package_->size && blocks_.finish() == package_->blocks) {
			verdict.microsoft = true;
			verdict.source = L"package " + package_->package + L", signed by " + package_->signer
			               + L" (AppxSignature.p7x, AppxBlockMap.xml)";
			verdict.reason.clear();
		}
		// Listed in a signed block map, yet different: say so, it is the finding.
		else verdict.reason += "; content differs from its package's signed block map";
	}

private:
	const bool powershell_;
	const PackageFile* package_;
	PeAnalyser pe_;
	Collector text_;                  // PowerShell scripts: text in memory
	BlockDigests blocks_;             // a file of a signed package: its blocks
	Fanout fanout_;
	Head head_;
};

/*! Counts an authenticated file, and keeps what justified its authentication
 *  for the exhibit store (catalog, package). Main thread only.
 *  @param verdict the verdict
 *  @param line the file's record
 *  @param package its package entry, if any */
void noteVerdict(const VerdictMicrosoft& verdict, const RawHiveExtraction& line, const PackageFile* package) {
	if (!verdict.microsoft) return;
	++g_authenticated;
	g_authenticatedBytes += line.fingerprints.bytes;
	/* By the verdict's own field: the prefix of its label used to be looked
	   for as "catalogue " while the label says "catalog " — no catalog that
	   justified an authentication ever reached the exhibit store. */
	if (!verdict.catalog.empty()) g_catalogsUsed.insert(verdict.catalog);
	if (package && verdict.source.compare(0, 8, L"package ") == 0) g_packagesUsed.insert(package->package);
}

/*! FIRST READ, WRITING NOTHING: fingerprints and, for a PE or a script, the
 *  Microsoft authenticity, verified in memory (see authenticode.h). The
 *  content goes through the analysis (ContentAnalysis) as it is read.
 *
 *  THE STRICT NECESSARY. Authenticating a PE needs its Authenticode digests
 *  only; MD5, SHA-1 and SHA-256 of the file identify it, and are computed
 *  again anyway when it is copied. Skipping them (`fileHashes` false) takes
 *  three of the five digests off a whole-volume reading. A file that turns
 *  out not to be a PE is read again with them: its catalog lookup needs its
 *  SHA-256.
 *  @param path the file ("X:\\…")
 *  @param line receives the record, fingerprints included
 *  @param verdict receives the verdict
 *  @param fileHashes false to skip MD5, SHA-1 and SHA-256 of a PE
 *  @param windowsDelta receives whether the file is a Windows differential file
 *  @param output file to write the content to, in the same read (--binary-all)
 *  @return the result of the read */
HRESULT readAndAuthenticate(const std::wstring& path, RawHiveExtraction& line, VerdictMicrosoft& verdict,
                            bool fileHashes = true, bool* windowsDelta = nullptr,
                            const std::wstring& output = std::wstring()) {
	const PackageFile* package = packageFileOf(path);
	ContentAnalysis analysis(path, package);
	line.fingerprints.computeHashes = fileHashes;
	const HRESULT hr = g_reader->read(path, output, line, analysis.input());
	analysis.finishContent();
	if (FAILED(hr)) return hr;
	if (!analysis.isPe() && !fileHashes) {
		line = RawHiveExtraction{};
		return readAndAuthenticate(path, line, verdict, true, windowsDelta, output);
	}
	bool delta = false;
	analysis.conclude(line, verdict, delta);
	if (windowsDelta) *windowsDelta = delta;
	noteVerdict(verdict, line, package);
	return hr;
}

/*! The verdict of a check, as the manifest records it.
 *  @param verdict the check's outcome
 *  @return the recorded verdict */
SignatureVerdict recordedVerdict(const VerdictMicrosoft& verdict);

//! The verdict as recorded: "Microsoft (<source>)", or "Package (<source>)"
//! for a file whose package the Store signed for its publisher.
std::wstring signatureLabel(const VerdictMicrosoft& verdict) {
	if (verdict.source.compare(0, 8, L"package ") == 0) return L"Package (" + verdict.source + L")";
	return L"Microsoft (" + verdict.source + L")";
}

/*! CRL addresses the chains named and the trust set lacked: what the next
 *  --update-trust must also fetch (see recordMissingCrls). Main thread only,
 *  like recordedVerdict. */
std::set<std::string> g_missingCrls;

SignatureVerdict recordedVerdict(const VerdictMicrosoft& verdict) {
	g_missingCrls.insert(verdict.chainMissingCrls.begin(), verdict.chainMissingCrls.end());
	SignatureVerdict v;
	v.checked = true;
	v.valid = verdict.microsoft;
	if (v.valid) v.label = signatureLabel(verdict);
	else v.reason = decodeText(verdict.reason);
	if (!verdict.signer.empty()) {
		v.embeddedSigner = verdict.signer
		                 + (verdict.signerOrganization.empty() ? L"" : L", " + verdict.signerOrganization);
		v.embeddedIntact = verdict.signatureIntact;
	}
	v.chainChecked = verdict.chainChecked;
	v.chainTrusted = verdict.chainTrusted;
	v.chainRoot = verdict.chainRoot;
	v.chainReason = decodeText(verdict.chainReason);
	if (verdict.chainSignedAt) {
		const FILETIME at = { (DWORD)verdict.chainSignedAt, (DWORD)(verdict.chainSignedAt >> 32) };
		v.chainSignedUtc = timeToIso8601Utc(at, Precision::Second);
		v.chainTimeStampAuthority = verdict.chainTimeStampAuthority;
	}
	if (verdict.chainRevocationListsIssued) {
		const FILETIME at = { (DWORD)verdict.chainRevocationListsIssued, (DWORD)(verdict.chainRevocationListsIssued >> 32) };
		v.chainRevocationListsUtc = timeToIso8601Utc(at, Precision::Second);
	}
	return v;
}

} // namespace

const BinaryFingerprint& FingerprintFile(const std::wstring& rawPath) {
	static const BinaryFingerprint empty;
	if (!conf.binary) return empty;
	const std::wstring path = normalizeFilePath(rawPath);
	if (path.empty()) return empty;

	const std::wstring key = toLower(path);       // NTFS is case-insensitive
	const auto found = g_cache.find(key);
	if (found != g_cache.end()) return found->second;

	if (!g_reader) g_reader = openReader();
	BinaryFingerprint e;
	e.path = path;
	/* --convert: an executable the collection authenticated as Microsoft was
	   fingerprinted, not copied — its fingerprints and verdict are the
	   manifest's (ExhibitStoreAddFingerprint). */
	if (conf.mode == RunMode::Convert) {
		const std::map<std::wstring, StoredExhibit>& index = ExhibitStoreIndex();
		const auto stored = index.find(key);
		if (stored != index.end() && !stored->second.contentStored) {
			e.md5 = stored->second.md5;
			e.sha1 = stored->second.sha1;
			e.sha256 = stored->second.sha256;
			e.signature = stored->second.signature;
			e.authenticodeSha256 = stored->second.authenticodeSha256;
			e.result = ERROR_SUCCESS;
			++g_read;
			if (!e.signature.empty()) ++g_authenticated;
			return g_cache.emplace(key, std::move(e)).first->second;
		}
	}
	auto keep = [&](RawHiveExtraction& l) {
		e.md5    = l.fingerprints.md5;
		e.sha1   = l.fingerprints.sha1;
		e.sha256 = l.fingerprints.sha256;
		e.authenticodeSha256 = l.fingerprints.authenticodeSha256;
	};

	if (!worthCollecting(path)) {
		// Document or data: fingerprints only, nothing is written.
		RawHiveExtraction line;
		e.result = g_reader->read(path, std::wstring(), line);
		if (SUCCEEDED(e.result)) { ++g_read; keep(line); }
		else log(3, L"🔈Cannot fingerprint: " + path, e.result);
		return g_cache.emplace(key, std::move(e)).first->second;
	}

	const std::wstring target = pathUnder(exhibitStoreFolder(), path);
	std::error_code ec;

	/* FIRST READ, WRITING NOTHING. An authentic Microsoft binary — the vast
	   majority — is thus never written to the collection medium; only the
	   others are read again to be collected. Re-reading the examined disk costs
	   less than writing then erasing on a USB stick. */
	RawHiveExtraction first;
	VerdictMicrosoft v;
	{
		RawHiveExtraction& line = first;
		e.result = readAndAuthenticate(path, line, v);
		if (FAILED(e.result)) {
			log(3, L"🔈Cannot fingerprint: " + path, e.result);
			// Missing: the artefact already says so, and it is not an exhibit. Any
			// other error is an exhibit that could not be read: it is recorded.
			if (conf.mode != RunMode::Convert && e.result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
				line.outputPath = target;
				ExhibitStoreAdd({ line }, L"Raw NTFS reading; binary cited by an artefact (--binary)");
			}
			return g_cache.emplace(key, std::move(e)).first->second;
		}
		++g_read;
		keep(line);
		if (v.microsoft) {
			e.signature = signatureLabel(v);
			// --binary-all: collected all the same, the verdict recorded with it.
			if (!conf.binaryAll) return g_cache.emplace(key, std::move(e)).first->second;
		}
		else log(3, L"🔈Collected (" + decodeText(v.reason) + L") : " + path);
	}

	/* Already in the exhibit store (extracted by another phase), or read from
	   it (--convert: the store is sealed, nothing is written to it). */
	if (conf.mode == RunMode::Convert || std::filesystem::exists(target, ec))
		return g_cache.emplace(key, std::move(e)).first->second;

	if (!roomLeft()) {
		++g_sansPlace;
		log(2, L"🔥Not enough space: " + path + L" hashed without being collected");
		return g_cache.emplace(key, std::move(e)).first->second;
	}

	// SECOND READ: collection, through the incoming directory (deduplication).
	RawHiveExtraction line;
	line.fingerprints.authenticodeSha1 = first.fingerprints.authenticodeSha1;
	line.fingerprints.authenticodeSha256 = first.fingerprints.authenticodeSha256;
	line.fingerprints.peTimeDateStamp = first.fingerprints.peTimeDateStamp;
	line.fingerprints.peSizeOfImage = first.fingerprints.peSizeOfImage;
	e.result = storeExhibit(path, conf.binaryAll ? L"binary cited by an artefact (--binary-all)"
	                                             : L"binary cited by an artefact (--binary)",
	                        line, recordedVerdict(v));
	if (SUCCEEDED(e.result)) {
		if (line.fingerprints.sha256 != e.sha256)
			log(2, L"🔥Content changed between two reads: " + path);
		keep(line);                     // the exhibit is authoritative
	}
	return g_cache.emplace(key, std::move(e)).first->second;
}

void addFingerprints(Json& o, const BinaryFingerprint& e,
                       const std::wstring& prefix, const std::wstring& suffix) {
	if (!e.md5.empty())    o.add(prefix + L"Md5"    + suffix, Json::str(e.md5));
	if (!e.sha1.empty())   o.add(prefix + L"Sha1"   + suffix, Json::str(e.sha1));
	if (!e.sha256.empty()) o.add(prefix + L"Sha256" + suffix, Json::str(e.sha256));
	if (!e.authenticodeSha256.empty()) o.add(prefix + L"AuthenticodeSha256" + suffix, Json::str(e.authenticodeSha256));
	if (!e.signature.empty()) o.add(prefix + L"Signature" + suffix, Json::str(e.signature));
}

BinarySummary BinariesSummary() {
	BinarySummary b;
	b.files = g_cache.size();
	b.read = g_read;
	b.collectedCount = g_collected;
	b.collectedBytes = g_bytes;
	b.sansPlace = g_sansPlace;
	b.duplicates = g_duplicates;
	b.avoidedBytes = g_avoidedBytes;
	b.authenticated = g_authenticated;
	b.authenticatedBytes = g_authenticatedBytes;
	b.catalogsRead = g_catalogsRead;
	b.catalogsUsed = g_catalogsUsed.size();
	return b;
}

namespace {

/*! One file of the whole-volume walk, from its reading to its record. */
struct WalkItem {
	size_t order = 0;                 //!< its rank in the walk: results are recorded in that order
	std::wstring path;
	std::wstring method;              //!< collection method, as the manifest records it
	std::pair<size_t, uint64_t> record;   //!< (volume, $MFT record): identifies hard links
	bool link = false;                //!< another name of a record already read
	bool inMemory = false;            //!< content held here, analysed by a worker
	HRESULT result = S_OK;            //!< the read's result
	RawHiveExtraction line;           //!< the read's record
	std::vector<uint8_t> content;     //!< the content (inMemory)
	std::wstring staged;              //!< the content already written to the incoming directory (--binary-all, streamed)
	const PackageFile* package = nullptr;
	VerdictMicrosoft verdict;
	bool windowsDelta = false;
};

//! Largest file held in memory for a worker; a larger one is read in stream.
const size_t IN_MEMORY_MAX = 64 * 1024 * 1024;
//! Content read and not yet recorded, at most: the reading waits beyond it.
const size_t IN_FLIGHT_MAX = 256 * 1024 * 1024;

//! Time the workers spent analysing, in milliseconds (all threads added).
std::atomic<unsigned long long> g_analysisMs{ 0 };

//! MD5, SHA-1 and SHA-256 of a content held in memory, into its record.
void setFileHashes(RawHiveExtraction& line, const std::vector<uint8_t>& content) {
	Md5Stream md5;
	Sha1Stream sha1;
	Sha256Stream sha256;
	md5.update(content.data(), content.size());
	sha1.update(content.data(), content.size());
	sha256.update(content.data(), content.size());
	line.fingerprints.md5 = md5.hexDigest();
	line.fingerprints.sha1 = sha1.hexDigest();
	line.fingerprints.sha256 = sha256.hexDigest();
}

/*! A worker's job: the analysis of a content held in memory — what
 *  readAndAuthenticate does during a read. Its three fingerprints are
 *  computed when they are needed: a non-PE (catalog lookup), a file not
 *  authenticated (copied), --binary-all (everything copied). */
void analyseInMemory(WalkItem& item) {
	const auto start = std::chrono::steady_clock::now();
	ContentAnalysis analysis(item.path, item.package);
	analysis.input()->sputn(reinterpret_cast<const char*>(item.content.data()), (std::streamsize)item.content.size());
	analysis.finishContent();
	if (!analysis.isPe() || conf.binaryAll) setFileHashes(item.line, item.content);
	analysis.conclude(item.line, item.verdict, item.windowsDelta);
	if (!item.verdict.microsoft && item.line.fingerprints.sha256.empty()) setFileHashes(item.line, item.content);
	g_analysisMs += (unsigned long long)std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - start).count();
}

/*! The workers: they analyse the contents the reading hands them, and hold
 *  the results until the main thread records them, in the walk's order. */
class AnalysisPool {
public:
	explicit AnalysisPool(unsigned threads) {
		for (unsigned k = 0; k < threads; ++k) threads_.emplace_back([this] { run(); });
	}
	~AnalysisPool() {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			stop_ = true;
		}
		work_.notify_all();
		for (std::thread& t : threads_) t.join();
	}
	AnalysisPool(const AnalysisPool&) = delete;
	AnalysisPool& operator=(const AnalysisPool&) = delete;

	//! Hands a content to the workers.
	void submit(std::unique_ptr<WalkItem> item) {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			inFlight_ += item->content.size();
			todo_.push_back(std::move(item));
		}
		work_.notify_one();
	}
	/*! The result of a rank, if analysed.
	 *  @param order the rank
	 *  @param wait true to wait for it (it must have been submitted)
	 *  @return the item, or nullptr if not analysed yet */
	std::unique_ptr<WalkItem> take(size_t order, bool wait) {
		std::unique_lock<std::mutex> lock(mutex_);
		if (wait) finished_.wait(lock, [&] { return done_.count(order) != 0; });
		const auto found = done_.find(order);
		if (found == done_.end()) return nullptr;
		std::unique_ptr<WalkItem> item = std::move(found->second);
		done_.erase(found);
		inFlight_ -= item->content.size();
		return item;
	}
	//! @return the bytes of content read and not taken back yet
	size_t inFlight() {
		std::lock_guard<std::mutex> lock(mutex_);
		return inFlight_;
	}

private:
	void run() {
		for (;;) {
			std::unique_ptr<WalkItem> item;
			{
				std::unique_lock<std::mutex> lock(mutex_);
				work_.wait(lock, [&] { return stop_ || !todo_.empty(); });
				if (todo_.empty()) return;              // stopping, nothing left
				item = std::move(todo_.front());
				todo_.pop_front();
			}
			analyseInMemory(*item);
			{
				std::lock_guard<std::mutex> lock(mutex_);
				const size_t order = item->order;
				done_[order] = std::move(item);
			}
			finished_.notify_all();
		}
	}
	std::vector<std::thread> threads_;
	std::deque<std::unique_ptr<WalkItem>> todo_;
	std::map<size_t, std::unique_ptr<WalkItem>> done_;
	std::mutex mutex_;
	std::condition_variable work_, finished_;
	size_t inFlight_ = 0;
	bool stop_ = false;
};

/*! What was recorded for a $MFT record, for its other names (hard links). */
struct Recorded { RawHiveExtraction line; SignatureVerdict verdict; bool stored = false; std::wstring method; };

/*! Writes a content held in memory to the incoming directory.
 *  @return the file, or an empty string if it could not be written */
std::wstring stageFromMemory(const std::vector<uint8_t>& content) {
	const std::wstring staged = newStagingFile();
	std::ofstream out(std::filesystem::path(staged), std::ios::binary | std::ios::trunc);
	out.write(reinterpret_cast<const char*>(content.data()), (std::streamsize)content.size());
	if (out) return staged;
	std::error_code ec;
	std::filesystem::remove(staged, ec);
	return std::wstring();
}

/*! Records one file of the walk, analysed: fingerprinted only, or copied —
 *  from memory, without reading the volume again — and what its hard links
 *  will repeat. Main thread only: it alone touches the manifest, the incoming
 *  directory and the counters. */
class WalkRecorder {
public:
	void record(WalkItem& item) {
		std::error_code ec;
		if (item.link) {
			const auto first = byRecord_.find(item.record);
			if (first != byRecord_.end()) {
				RawHiveExtraction other = first->second.line;   // same record: same content, same timestamps
				other.volumePath = item.path;
				// What the first name was found to be (authentic, differential, collected), and why.
				const std::wstring linkMethod = first->second.method + L"; another name (hard link) of $MFT record "
				                              + std::to_wstring(item.record.second) + L", read once";
				if (first->second.stored) ExhibitStoreAddDuplicate(other, linkMethod + READ_IN_PLACE, first->second.verdict);
				else ExhibitStoreAddFingerprint(other, linkMethod, first->second.verdict);
				++links;
				return;
			}
			// The first name could not be recorded: this one is read on its own.
			item.link = false;
			item.result = readAndAuthenticate(item.path, item.line, item.verdict, conf.binaryAll, &item.windowsDelta);
		}
		if (FAILED(item.result)) {
			if (!item.staged.empty()) std::filesystem::remove(item.staged, ec);
			item.line.outputPath = pathUnder(exhibitStoreFolder(), item.path);
			ExhibitStoreAdd({ item.line }, item.method);   // a failure is recorded too
			return;
		}
		++g_read;
		if (item.inMemory) noteVerdict(item.verdict, item.line, item.package);
		// A differential file is no executable: no signature to check.
		const SignatureVerdict recorded = item.windowsDelta ? SignatureVerdict{} : recordedVerdict(item.verdict);
		const std::wstring nature = item.windowsDelta
		        ? L"Windows differential file (MSDELTA), not an executable"
		        : item.verdict.microsoft ? L"authenticated in memory"
		                                 : L"not authenticated: " + decodeText(item.verdict.reason);
		if (item.windowsDelta) ++g_deltas;

		if (conf.binaryAll && roomLeft()) {
			const std::wstring allMethod = item.method + L"; " + nature + L"; copied (--binary-all)";
			const std::wstring staged = item.inMemory ? stageFromMemory(item.content) : item.staged;
			if (SUCCEEDED(recordStaged(item.path, staged, staged.empty() ? HRESULT_FROM_WIN32(ERROR_WRITE_FAULT) : S_OK,
			                           item.line, allMethod + READ_IN_PLACE, recorded)))
				byRecord_.emplace(item.record, Recorded{ item.line, recorded, true, allMethod });
			return;
		}
		if (!item.staged.empty()) std::filesystem::remove(item.staged, ec);

		// Authentic, differential, or no room left: fingerprinted, not copied.
		if (item.verdict.microsoft || item.windowsDelta || full || (full = !roomLeft())) {
			if (!item.verdict.microsoft && !item.windowsDelta) ++g_sansPlace;
			// Not authenticated and not copied: at least its three fingerprints.
			if (!item.verdict.microsoft && item.line.fingerprints.sha256.empty()) {
				RawHiveExtraction reread;   // keeping what the first read found
				reread.fingerprints.authenticodeSha1 = item.line.fingerprints.authenticodeSha1;
				reread.fingerprints.authenticodeSha256 = item.line.fingerprints.authenticodeSha256;
				reread.fingerprints.peTimeDateStamp = item.line.fingerprints.peTimeDateStamp;
				reread.fingerprints.peSizeOfImage = item.line.fingerprints.peSizeOfImage;
				if (FAILED(g_reader->read(item.path, std::wstring(), reread))) return;
				item.line = std::move(reread);
			}
			const std::wstring fingerprintMethod = item.method + L"; " + nature
			        + (item.verdict.microsoft || item.windowsDelta ? L"; fingerprinted, not copied"
			                                                       : L"; fingerprinted without a copy: collection medium full");
			ExhibitStoreAddFingerprint(item.line, fingerprintMethod, recorded);
			byRecord_.emplace(item.record, Recorded{ item.line, recorded, false, fingerprintMethod });
			return;
		}
		// Why it was not authenticated: a fact for the investigation, and the way to spot a gap.
		const std::wstring purpose = L"executable, library, driver, script or macro document of the volume, "
		                             + nature + L" (" + std::wstring(conf.binaryAll ? L"--collect --binary-all" : L"--collect --binary") + L")";
		PhaseTimer timer(g_times.copying);
		HRESULT stored;
		if (item.inMemory) {
			// Copied from memory: the content already read, not the volume again.
			const std::wstring staged = stageFromMemory(item.content);
			const std::wstring method = L"Raw NTFS reading (\\\\.\\" + item.path.substr(0, 2)
			                          + L" — $MFT, directory indexes, $DATA attribute); " + purpose + READ_IN_PLACE;
			stored = recordStaged(item.path, staged, staged.empty() ? HRESULT_FROM_WIN32(ERROR_WRITE_FAULT) : S_OK,
			                      item.line, method, recorded);
			if (SUCCEEDED(stored)) byRecord_.emplace(item.record, Recorded{ item.line, recorded, true, item.method + L"; " + purpose });
			return;
		}
		// Read in stream (a large file): the copy, and its three fingerprints, read it again.
		RawHiveExtraction copy;
		copy.fingerprints.authenticodeSha1 = item.line.fingerprints.authenticodeSha1;
		copy.fingerprints.authenticodeSha256 = item.line.fingerprints.authenticodeSha256;
		copy.fingerprints.peTimeDateStamp = item.line.fingerprints.peTimeDateStamp;
		copy.fingerprints.peSizeOfImage = item.line.fingerprints.peSizeOfImage;
		stored = storeExhibit(item.path, purpose, copy, recorded);
		if (SUCCEEDED(stored)) byRecord_.emplace(item.record, Recorded{ copy, recorded, true, item.method + L"; " + purpose });
	}

	size_t links = 0;
	bool full = false;

private:
	std::map<std::pair<size_t, uint64_t>, Recorded> byRecord_;
};

} // namespace

HRESULT BinariesCollectAll() {
	g_reader = openReader();
	std::error_code ec;
	/* Every fixed NTFS volume: a profile on D: holds what an intruder drops
	   there, and so do programs installed off the system volume. Removable
	   volumes — the collection medium among them — are left out, and so is
	   the output folder when it lies on a fixed volume. */
	std::vector<std::wstring> roots;
	for (const RunningMachine::Volume& v : runningMachine().volumes)
		if (v.driveType == DRIVE_FIXED && v.fileSystem == L"NTFS" && v.mountPoint.size() == 2)
			roots.push_back(v.mountPoint + L"\\");
	if (roots.empty()) roots.push_back(conf.systemDrive + L"\\");
	const std::wstring output = toLower(std::filesystem::absolute(conf._outputDir, ec).wstring());
	const std::wstring option = conf.binaryAll ? L"--collect --binary-all" : L"--collect --binary";

	/* THE WALK IN THREE PARTS. This thread alone reads the volume — the raw
	   reader and its $MFT cache are not shared between threads — and holds
	   each executable in memory; the workers analyse it (PE, Authenticode,
	   catalogs, packages, fingerprints); this thread records the results IN
	   THE WALK'S ORDER, so that the manifest does not depend on the threads.
	   The catalogs and the trust set are loaded before the workers start:
	   they only read them. */
	catalogues();
	thirdPartyRoots();
	const unsigned threads = conf.threads ? conf.threads
	                       : std::max(1u, std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency() - 1 : 1u);
	AnalysisPool pool(threads);
	WalkRecorder recorder;
	std::map<size_t, std::unique_ptr<WalkItem>> ready;   // not analysed by a worker: failures, links, large files
	size_t nextOrder = 0, nextRecord = 0;
	/* HARD LINKS. System32 and WinSxS name the same $MFT records: the content
	   is read once, and every other name is recorded like the first — the
	   conversion looks a file up by the path an artefact cites. */
	std::set<std::pair<size_t, uint64_t>> readOnce;
	auto recordAvailable = [&](bool waitForMemory) {
		while (nextRecord < nextOrder) {
			std::unique_ptr<WalkItem> item;
			const auto found = ready.find(nextRecord);
			if (found != ready.end()) { item = std::move(found->second); ready.erase(found); }
			else item = pool.take(nextRecord, waitForMemory && pool.inFlight() > IN_FLIGHT_MAX);
			if (!item) return;
			recorder.record(*item);
			++nextRecord;
		}
	};

	size_t listed = 0, unreadable = 0;
	const auto walkStart = std::chrono::steady_clock::now();
	for (size_t volume = 0; volume < roots.size(); ++volume) {
		const std::wstring& root = roots[volume];
		std::vector<std::wstring> folders{ root };
		std::set<uint64_t> directories;       // a directory met twice (a cycle) is walked once
		while (!folders.empty()) {
			const std::wstring folder = folders.back();
			folders.pop_back();
			std::vector<RawDirEntry> entries;
			if (FAILED(g_reader->list(folder, entries))) {
				++unreadable;
				log(2, L"🔥Directory unreadable, its executables not collected: " + folder);
				continue;
			}
			++listed;
			for (const RawDirEntry& e : entries) {
				// The NTFS metadata files ($MFT, $Extend…).
				// "." and "..": the root's index names the root itself — walked
				// again as "C:\\.\\", its files were recorded twice.
				if (e.name.empty() || e.name[0] == L'$' || e.name == L"." || e.name == L"..") continue;
				const std::wstring path = folder + e.name;
				if (e.isDirectory) {
					if (directories.insert(e.mftIndex).second && toLower(path) != output)
						folders.push_back(path + L"\\");
					continue;
				}
				if (!worthCollecting(path)) continue;
				/* The memory files at the root of a volume carry the ".sys"
				   extension but are no drivers: paged memory, gigabytes of it. */
				if (folder == root && (toLower(e.name) == L"pagefile.sys" || toLower(e.name) == L"swapfile.sys"
				                       || toLower(e.name) == L"hiberfil.sys")) continue;
				// Already an exhibit (resource file of an event provider): recorded once.
				if (std::filesystem::exists(pathUnder(exhibitStoreFolder(), path), ec)) continue;

				std::unique_ptr<WalkItem> item(new WalkItem);
				item->order = nextOrder++;
				item->path = path;
				item->record = { volume, e.mftIndex };
				item->method = L"Raw NTFS reading (\\\\.\\" + path.substr(0, 2)
				             + L" — $MFT, directory indexes, $DATA attribute); executable, library, "
				               L"driver, script or macro document of the volume (" + option + L")";
				if (readOnce.count(item->record)) {
					item->link = true;
					ready.emplace(item->order, std::move(item));
				}
				else if (e.size <= IN_MEMORY_MAX) {
					// Read into memory, analysed by a worker.
					PhaseTimer timer(g_times.reading);
					item->package = packageFileOf(path);
					Collector content;
					content.bytes.reserve((size_t)e.size);
					item->line.fingerprints.computeHashes = false;
					item->result = g_reader->read(path, std::wstring(), item->line, &content);
					item->content = std::move(content.bytes);
					if (SUCCEEDED(item->result)) {
						readOnce.insert(item->record);
						item->inMemory = true;
						pool.submit(std::move(item));
					}
					else ready.emplace(item->order, std::move(item));
				}
				else {
					// A large file: read and analysed in stream, by this thread.
					PhaseTimer timer(g_times.reading);
					if (conf.binaryAll) item->staged = newStagingFile();
					item->result = readAndAuthenticate(path, item->line, item->verdict, conf.binaryAll,
					                                   &item->windowsDelta, item->staged);
					if (SUCCEEDED(item->result)) readOnce.insert(item->record);
					ready.emplace(item->order, std::move(item));
				}
				recordAvailable(true);
			}
		}
	}
	// The last results, waited for.
	while (nextRecord < nextOrder) {
		const size_t before = nextRecord;
		recordAvailable(true);
		if (nextRecord == before) {
			std::unique_ptr<WalkItem> item = pool.take(nextRecord, true);
			recorder.record(*item);
			++nextRecord;
		}
	}
	const auto walkSeconds = std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::steady_clock::now() - walkStart).count();

	log(2, L"❇️Executables of " + std::to_wstring(roots.size()) + L" volume(s): " + std::to_wstring(listed)
	     + L" directorie(s) walked, " + std::to_wstring(unreadable) + L" unreadable, " + std::to_wstring(g_read)
	     + L" read, " + std::to_wstring(g_authenticated) + L" authenticated"
	     + (conf.binaryAll ? L" (copied all the same, --binary-all), " : L" (not copied), ")
	     + std::to_wstring(g_collected) + L" collected (" + std::to_wstring(g_bytes / 1024 / 1024) + L" MiB), "
	     + std::to_wstring(g_duplicates) + L" identical content(s) not copied again, " + std::to_wstring(recorder.links)
	     + L" other name(s) of hard links, " + std::to_wstring(g_deltas) + L" Windows differential file(s) not copied, "
	     + std::to_wstring(g_sansPlace) + L" not copied for lack of room");
	const RawReadTimes activity = RawHiveTimes();
	log(2, L"❇️Raw reading, time per activity since the start: disk " + std::to_wstring((long long)activity.diskRead)
	     + L" s, decompression " + std::to_wstring((long long)activity.decompression) + L" s, file hashes "
	     + std::to_wstring((long long)activity.fileHashes) + L" s, PE analysis and Authenticode in stream "
	     + std::to_wstring((long long)activity.observers) + L" s");
	log(2, L"❇️Executables, " + std::to_wstring(threads) + L" analysis thread(s): walk " + std::to_wstring((long long)walkSeconds)
	     + L" s; reading " + std::to_wstring(g_times.reading / 1000) + L" s (of which catalogs "
	     + std::to_wstring(g_times.catalogs / 1000) + L" s, packages " + std::to_wstring(g_times.packages / 1000)
	     + L" s); analysis " + std::to_wstring(g_analysisMs.load() / 1000) + L" s of thread time; copies "
	     + std::to_wstring(g_times.copying / 1000) + L" s");
	if (recorder.full) return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
	return unreadable ? S_FALSE : ERROR_SUCCESS;
}

/*! The CRL addresses this collection lacked, added to wanted-crls.txt in the
 *  trust set's folder, on the key: the next --update-trust fetches them too,
 *  so that the CRLs of authorities the CCADB does not list — Microsoft's own
 *  code signing authorities, first — fill in by themselves. Written to the
 *  collection medium only; the manifest of the set does not list the file,
 *  whose content is only addresses, each CRL checked by its signature where
 *  it is used. */
void recordMissingCrls() {
	if (g_missingCrls.empty() || !CollectionTrustSet().usable) return;
	const std::filesystem::path file = std::filesystem::path(CollectionTrustSet().folder) / "wanted-crls.txt";
	std::set<std::string> all = g_missingCrls;
	{
		std::ifstream in(file);
		for (std::string line; std::getline(in, line);)
			if (!line.empty()) all.insert(line.back() == '\r' ? line.substr(0, line.size() - 1) : line);
	}
	std::ofstream out(file, std::ios::trunc);
	for (const std::string& url : all) out << url << "\n";
	const HRESULT result = out ? S_OK : E_FAIL;
	auditRecord(L"Revocation lists missing from the trust set (" + std::to_wstring(g_missingCrls.size())
	            + L" address(es)): added to wanted-crls.txt for the next --update-trust", file.wstring(), result,
	            Footprint::USB_WRITE);
}

void BinariesFinish() {
	if (conf.mode != RunMode::Convert) recordMissingCrls();
	/* The catalogs and package signatures that JUSTIFIED not collecting a
	   binary go into the exhibit store: without them, the decision could not
	   be checked by a third party. Only those — not the machine's 13,000
	   catalogs. Under --convert, they were read FROM the store. */
	if (g_reader && conf.mode != RunMode::Convert) {
		const std::wstring inPlace = conf.mode == RunMode::Collect ? READ_IN_PLACE : L"";
		const std::wstring method = L"Raw NTFS reading (\\\\.\\" + conf.systemDrive
		                          + L" — $MFT, directory indexes, $DATA attribute); ";
		std::vector<std::wstring> packageFiles;
		for (const std::wstring& folder : g_packagesUsed) {
			packageFiles.push_back(folder + L"AppxSignature.p7x");
			packageFiles.push_back(folder + L"AppxBlockMap.xml");
		}
		recordJustifications(std::vector<std::wstring>(g_catalogsUsed.begin(), g_catalogsUsed.end()),
		                     method + L"signature catalog that justified not collecting binaries "
		                              L"authenticated as Microsoft (--binary)" + inPlace);
		recordJustifications(packageFiles,
		                     method + L"signature and block map of a package that justified not "
		                              L"collecting its files (--binary)" + inPlace);
		recordJustifications(std::vector<std::wstring>(g_thirdPartyCatalogs.begin(), g_thirdPartyCatalogs.end()),
		                     method + L"signature catalog NOT signed by Microsoft (third-party drivers and "
		                              L"software), for the verification of their signatures at analysis (--binary)"
		                              + inPlace);
	}
	g_reader.reset();
	std::error_code ec;
	std::filesystem::remove_all(stagingFolder(), ec);
}

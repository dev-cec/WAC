/*  binaires.cpp — voir binaires.h. */
#include "binaires.h"
#include <map>
#include <memory>
#include <filesystem>
#include "tools.h"
#include "raw_hive.h"
#include "consigne.h"
#include "authenticode.h"
#include <set>
#include <vector>

namespace {

std::unique_ptr<RawReader> g_reader;
std::map<std::wstring, BinaryFingerprint> g_cache;      // key: lowercase path
std::map<std::wstring, std::wstring> g_byContent;    // SHA-256 -> exhibit in the store
size_t g_read = 0, g_collected = 0, g_sansPlace = 0, g_duplicates = 0;
unsigned long long g_bytes = 0, g_avoidedBytes = 0;
size_t g_authenticated = 0, g_catalogsRead = 0;
unsigned long long g_authenticatedBytes = 0;
std::set<std::wstring> g_catalogsUsed;
const size_t CATALOGUE_MAX = 64 * 1024 * 1024;       // a catalog beyond that: ignored
unsigned long long g_entrant = 0;                      // counter of incoming files

/*! INCOMING directory, on the collection medium but outside the exhibit store.
 *
 *  DEDUPLICATION. A file's content is only known once it has been read. It is
 *  therefore written here first, hashed on the way, then RENAMED into the
 *  exhibit store if new, or deleted if it is already there under another path.
 *  The exhibit store thus only receives final exhibits: nothing is written then
 *  erased in it, and an interrupted collection leaves no temporary file there.
 *  A single read of the volume per file. */
std::wstring stagingFolder() {
	return exhibitStoreFolder() + L".arrivee";
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

/*! Forwards what it receives to two buffers: the PE analysis and, for a
 *  PowerShell script, the in-memory copy of its text. */
class Duplicator : public std::streambuf {
public:
	Duplicator(std::streambuf* a, std::streambuf* b) : a_(a), b_(b) {}
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) { a_->sputc((char)c); if (b_) b_->sputc((char)c); }
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		a_->sputn(s, n);
		if (b_) b_->sputn(s, n);
		return n;
	}
private:
	std::streambuf* a_;
	std::streambuf* b_;
};

//! Scripts whose embedded signature is verified (see EvaluatePowerShellScript).
bool estScriptPowerShell(const std::wstring& path) {
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

std::wstring catalogFolder() {
	return conf.systemDrive + L"\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";
}

/*! Index of the machine's Microsoft catalogs, built on first request — hence
 *  only if a binary to collect is met. Catalogs are read raw, IN MEMORY:
 *  nothing is written, and no service is solicited (see authenticode.h). */
IndexCatalogues& catalogues() {
	static IndexCatalogues index;
	static bool done = false;
	if (done) return index;
	done = true;
	std::vector<RawDirEntry> entries;
	const HRESULT hr = g_reader->list(catalogFolder(), entries);
	if (FAILED(hr)) {
		log(2, L"🔥Signature catalogs unreadable: every binary will be collected", hr);
		return index;
	}
	std::set<uint64_t> seen;                  // a file can also appear under its short name
	size_t read = 0;
	for (const RawDirEntry& e : entries) {
		if (e.isDirectory || !seen.insert(e.mftIndex).second) continue;
		if (e.name.size() < 4 || toLower(e.name.substr(e.name.size() - 4)) != L".cat") continue;
		Collector c;
		RawHiveExtraction line;
		if (FAILED(g_reader->read(catalogFolder() + L"\\" + e.name, std::wstring(), line, &c))) continue;
		++read;
		index.add(e.name, c.bytes.data(), c.bytes.size());
	}
	g_catalogsRead = read;
	log(2, L"❇️Catalogues de signatures : " + std::to_wstring(read) + L" read, "
	     + std::to_wstring(index.catalogues()) + L" kept (Microsoft signature verified), "
	     + std::to_wstring(index.rejected()) + L" refuses, "
	     + std::to_wstring(index.fingerprints()) + L" fingerprints");
	return index;
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

	if (!g_reader) g_reader.reset(new RawReader);
	BinaryFingerprint e;
	e.path = path;
	auto keep = [&](RawHiveExtraction& l) {
		e.md5    = l.fingerprints.md5;
		e.sha1   = l.fingerprints.sha1;
		e.sha256 = l.fingerprints.sha256;
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

	/* FIRST READ, WRITING NOTHING: fingerprints and, for a PE, Microsoft
	   authenticity. An authentic Microsoft binary — the vast majority — is thus
	   never written to the collection medium; only the others are read again to be
	   collected. Re-reading the examined disk costs less than writing then erasing
	   on a USB stick. */
	{
		PeAnalyser pe;
		Collector text;                       // PowerShell scripts: text in memory
		const bool powershell = estScriptPowerShell(path);
		Duplicator tee(&pe, powershell ? &text : nullptr);
		RawHiveExtraction line;
		e.result = g_reader->read(path, std::wstring(), line, &tee);
		pe.finish();
		if (FAILED(e.result)) {
			log(3, L"🔈Cannot fingerprint: " + path, e.result);
			// Missing: the artefact already says so, and it is not an exhibit. Any
			// other error is an exhibit that could not be read: it is recorded.
			if (e.result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
				line.outputPath = target;
				ExhibitStoreAdd({ line }, L"Raw NTFS reading; binary cited by an artefact (--binary)");
			}
			return g_cache.emplace(key, std::move(e)).first->second;
		}
		++g_read;
		keep(line);
		/* PE: Authenticode digest. Script or document: SHA-256 of the raw bytes in
		   the catalogs, then embedded PowerShell signature. */
		VerdictMicrosoft v;
		if (pe.estPe()) v = EvaluatePe(pe, catalogues());
		else {
			uint8_t h[32];
			if (bytesFromHex(e.sha256, h)) v = EvaluateByCatalog(h, catalogues());
			if (!v.microsoft && powershell) {
				const VerdictMicrosoft ps = EvaluatePowerShellScript(text.bytes.data(), text.bytes.size());
				if (ps.microsoft || ps.reason != "no embedded signature") v = ps;
			}
		}
		{
			if (v.microsoft) {
				e.signature = L"Microsoft (" + v.source + L")";
				++g_authenticated;
				g_authenticatedBytes += line.fingerprints.bytes;
				if (v.source.compare(0, 10, L"catalogue ") == 0)
					g_catalogsUsed.insert(v.source.substr(10));
				return g_cache.emplace(key, std::move(e)).first->second;
			}
			log(3, L"🔈Collected (" + string_to_wstring(v.reason) + L") : " + path);
		}
	}

	// Already in the exhibit store (extracted by another phase): nothing to rewrite.
	if (std::filesystem::exists(target, ec)) return g_cache.emplace(key, std::move(e)).first->second;

	/* Each collected exhibit will be copied to the working directory at the end
	   of the collection: the room it will take there is already owed. Without this
	   term, an exhibit store filled up to the reserve left no room for its own
	   working copy. */
	const unsigned long long free = ExhibitStoreFreeSpace();
	if (free != 0 && free < RESERVE + g_bytes) {
		++g_sansPlace;
		log(2, L"🔥Not enough space: " + path + L" hashed without being collected");
		return g_cache.emplace(key, std::move(e)).first->second;
	}

	// SECOND READ: collection, through the incoming directory (deduplication).
	std::filesystem::create_directories(stagingFolder(), ec);
	const std::wstring output = stagingFolder() + L"\\" + std::to_wstring(++g_entrant) + L".bin";
	RawHiveExtraction line;
	e.result = g_reader->read(path, output, line);
	const std::wstring method = L"Lecture brute NTFS (\\\\.\\" + path.substr(0, 2)
	                           + L" — $MFT, directory indexes, $DATA attribute); "
	                           L"binary cited by an artefact (--binary)";
	if (FAILED(e.result)) {
		line.outputPath = target;
		ExhibitStoreAdd({ line }, method);
	}
	else {
		if (line.fingerprints.sha256 != e.sha256)
			log(2, L"🔥Content changed between two reads: " + path);
		keep(line);                     // the exhibit is authoritative
		const auto already = g_byContent.find(e.sha256);
		if (already != g_byContent.end()) {
			line.outputPath = already->second;
			ExhibitStoreAddDuplicate(line, method + L" ; content identical (SHA-256) "
			                                        L"to an exhibit already recorded, not copied again");
			++g_duplicates;
			g_avoidedBytes += line.fingerprints.bytes;
			e.collected = true;
		}
		else {
			std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);
			std::filesystem::rename(output, target, ec);
			line.outputPath = target;
			if (ec) {
				log(2, L"🔥Cannot record as an exhibit: " + target);
				line.result = e.result = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
			}
			else {
				g_byContent.emplace(e.sha256, target);
				e.collected = true;
				++g_collected;
				g_bytes += line.fingerprints.bytes;
			}
			ExhibitStoreAdd({ line }, method);
		}
	}
	std::filesystem::remove(output, ec);    // whatever is left in the incoming directory: nothing
	return g_cache.emplace(key, std::move(e)).first->second;
}

void addFingerprints(Json& o, const BinaryFingerprint& e,
                       const std::wstring& prefix, const std::wstring& suffix) {
	if (!e.md5.empty())    o.add(prefix + L"Md5"    + suffix, Json::str(e.md5));
	if (!e.sha1.empty())   o.add(prefix + L"Sha1"   + suffix, Json::str(e.sha1));
	if (!e.sha256.empty()) o.add(prefix + L"Sha256" + suffix, Json::str(e.sha256));
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

void BinariesFinish() {
	/* The catalogs that JUSTIFIED not collecting a binary go into the exhibit
	   store: without them, the decision could not be checked by a third party.
	   Only those — not the machine's 5,000. */
	if (g_reader && !g_catalogsUsed.empty()) {
		std::vector<RawHiveExtraction> reading;
		for (const std::wstring& name : g_catalogsUsed) {
			const std::wstring source = catalogFolder() + L"\\" + name;
			const std::wstring target = pathUnder(exhibitStoreFolder(), source);
			std::error_code ec;
			if (std::filesystem::exists(target, ec)) continue;
			std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);
			RawHiveExtraction line;
			g_reader->read(source, target, line);
			reading.push_back(std::move(line));
		}
		ExhibitStoreAdd(reading, L"Lecture brute NTFS (\\\\.\\" + conf.systemDrive
		                        + L" — $MFT, directory indexes, $DATA attribute); catalogue de "
		                        L"catalog that justified not collecting binaries "
		                        L"authenticated as Microsoft (--binary)");
	}
	g_reader.reset();
	std::error_code ec;
	std::filesystem::remove_all(stagingFolder(), ec);
}

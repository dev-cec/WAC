#include "event_messages.h"
#include "tools.h"
#include "consigne.h"
#include "raw_hive.h"
#include "pe_resource.h"
#include "wevt.h"
#include "audit.h"
#include <filesystem>
#include <map>
#include <memory>
#include <fstream>
#include <vector>

/*! \file
 *  \brief See event_messages.h for the chain to bring together.
 *  Here, the mechanics: finding the file, extracting it on demand, caching.
 */

namespace {

//! What is known of a provider, once its resources have been read (or not).
struct Provider {
	bool usable = false;         //!< both resources were loaded
	WevtMetadata metadata;     //!< event -> message identifier
	TableMessages   messages;        //!< message identifier -> template
	/*! Table of the parameter file (ParameterFileName): labels of the "%%nnnn"
	 *  values. For Security-Auditing, that is msobjs.dll, and not the provider's
	 *  binary. */
	TableMessages   parameters;
	std::wstring    file;         //!< original path of the resource binary
	std::wstring    reason;           //!< why it is unusable
};

std::map<std::wstring, std::unique_ptr<Provider>> g_cache;   // guid -> fournisseur
bool g_ready = false;
size_t g_failures = 0;
unsigned long long g_resolved = 0, g_bytes = 0;

//! GUID in lower case, braces included: that is how the registry key writes it.
std::wstring normalizeGuid(const std::wstring& g) {
	std::wstring r;
	for (wchar_t c : g) r += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
	if (!r.empty() && r.front() != L'{') r = L"{" + r + L"}";
	return r;
}

//! True if the file starts with the signature of a PE binary.
bool isValidPe(const std::wstring& path) {
	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) return false;
	char head[2] = { 0, 0 };
	f.read(head, 2);
	return f.gcount() == 2 && head[0] == 'M' && head[1] == 'Z';
}

/*! Extracts a file from the volume into the exhibit store, then copies it into
 *  the working directory, and returns the working path.
 *
 *  The discipline of the exhibit store applies to those binaries as to the
 *  rest: the raw copy is identified by its fingerprints and is never reopened
 *  for writing; it is the working copy that is opened.
 *
 *  Windows 10 and 11 compress their system binaries with WOF — "Compact OS":
 *  the `$DATA` attribute is sparse and the payload lives in the named stream
 *  `WofCompressedData`. The raw reading decompresses it (see xpress.h); nothing
 *  is opened through the API on the examined system.
 *
 *  ABSENT CANDIDATES. The `.mui` satellites are looked for language by
 *  language: most of the candidates do not exist, and that is not a collection
 *  failure. They are therefore not recorded in the exhibit store — 136 "failed
 *  exhibits" appeared there for languages that were simply not installed,
 *  drowning the real failures. Only a file that is present but unreadable is
 *  recorded.
 *
 *  @return the readable path, or an empty string on failure
 */
std::wstring extractResource(const std::wstring& absolutePath) {
	const std::wstring working = extractedPath(absolutePath);
	std::error_code ec;
	if (std::filesystem::exists(working, ec)) return working;   // already extracted

	const std::wstring volume  = volumeOfPath(absolutePath);
	const std::wstring relative = pathRelativeToVolume(absolutePath);
	const std::wstring target   = pathUnder(exhibitStoreFolder(), absolutePath);
	/* Already in the exhibit store — collected as a binary cited by an artefact
	   (--binary), and not yet copied into the working directory: it is not
	   extracted again, which would rewrite a sealed exhibit and declare it
	   twice. */
	if (std::filesystem::exists(target, ec)) {
		if (!isValidPe(target)) return std::wstring();
		std::filesystem::create_directories(std::filesystem::path(working).parent_path(), ec);
		std::filesystem::copy_file(target, working, std::filesystem::copy_options::skip_existing, ec);
		return ec ? std::wstring() : working;
	}
	std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);

	std::vector<HRESULT> res;
	std::vector<RawHiveExtraction> reading;
	const HRESULT hr = ExtractFilesRaw(volume, { { relative, target } }, &res, &reading);
	const bool absent = !res.empty()
	                 && (res[0] == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
	                  || res[0] == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND));
	if (absent) {
		// A candidate that does not exist: neither an exhibit, nor an empty directory
// in the exhibit store.
		std::filesystem::remove(std::filesystem::path(target).parent_path(), ec);
		return std::wstring();
	}
	ExhibitStoreAdd(reading, L"Lecture brute NTFS (\\\\.\\" + volume
	                        + L": — resource file of an event provider)");
	const bool brutOk = SUCCEEDED(hr) && !res.empty() && SUCCEEDED(res[0]);
	if (!brutOk)
		log(3, L"🔈Raw reading unsuccessful, fallback expected: " + absolutePath);
	else
		for (const RawHiveExtraction& e : reading) g_bytes += e.fingerprints.bytes;

	/*  NO FALLBACK THROUGH THE API. Those binaries are compressed by WOF
	    ("Compact OS"): their $DATA attribute is sparse and the content lives in a
	    named stream. The raw reading now handles them entirely (see xpress.h),
	    and nothing is therefore opened on the examined system.
	    A file that stays unreadable is so for another reason — absent, or
	    compressed with LZX, which WAC does not decompress — and it is reported as
	    such rather than read by a route that would leave a trace. */
	if (!brutOk || !isValidPe(target)) {
		log(2, L"🔥Resource binary unreadable by raw reading: " + absolutePath);
		return std::wstring();
	}

	// Copy into the working directory: that is where the reading will happen.
	std::filesystem::create_directories(std::filesystem::path(working).parent_path(), ec);
	std::filesystem::copy_file(target, working,
	                           std::filesystem::copy_options::overwrite_existing, ec);
	if (ec) {
		log(2, L"🔥Cannot make the working copy: " + working);
		return std::wstring();
	}
	return working;
}

/*! Interface languages to try to find a satellite, in order.
 *
 *  Read ONCE: `PreferredUILanguages` is a MULTI_SZ value — reading it as a
 *  plain string returned only the first language, or nothing. The usual
 *  candidates serve only as a last resort, and trying five languages for each of
 *  the hundred or so providers of a collection costs five hundred path
 *  resolutions for nothing.
 */
const std::vector<std::wstring>& interfaceLanguages() {
	static std::vector<std::wstring> languages;
	static bool done = false;
	if (done) return languages;
	done = true;

	std::vector<std::wstring> declared;
	if (conf.Software && getRegMultiSzValue(conf.Software,
	        L"Microsoft\\Windows\\CurrentVersion\\MUI\\Settings",
	        L"PreferredUILanguages", &declared) == ERROR_SUCCESS)
		for (const std::wstring& l : declared)
			if (!l.empty()) languages.push_back(l);

	for (PCWSTR l : { L"en-US", L"fr-FR", L"de-DE", L"es-ES", L"it-IT" }) {
		bool already = false;
		for (const std::wstring& d : languages) if (d == l) { already = true; break; }
		if (!already) languages.push_back(l);
	}
	log(2, L"❇️Interface languages tried for the .mui satellites: "
	     + std::to_wstring(languages.size()) + L" (" + (languages.empty() ? L"-" : languages[0]) + L"…)");
	return languages;
}

/*! Looks for the localised satellite of a resource binary.
 *
 *  On a localised system, the message table is NOT in the DLL: it is in
 *  `<directory>\<language>\<name>.mui`. The language not being known in
 *  advance, the most common candidates are tried, then the language read in the
 *  hive if it appears there.
 *
 *  @return the working path of the .mui, or an empty string if there is none
 */
std::wstring findMui(const std::wstring& absolutePath) {
	const std::filesystem::path p = absolutePath;
	const std::wstring directory = p.parent_path().wstring();
	const std::wstring name = p.filename().wstring();

	const std::vector<std::wstring>& languages = interfaceLanguages();

	for (const std::wstring& l : languages) {
		if (l.empty()) continue;
		const std::wstring candidate = directory + L"\\" + l + L"\\" + name + L".mui";
		const std::wstring working = extractResource(candidate);
		if (!working.empty()) return working;
	}
	return std::wstring();
}

/*! Loads a provider's resources, only once. */
/*! Paths where to look for a file declared in a provider's key.
 *
 *  TWO CANDIDATES. A RELATIVE path in a provider's key is relative to
 *  `System32`, whereas for a service it is relative to `%SystemRoot%` —
 *  `binaryPath` applies that second rule. Seen: a bare "storagewmi.dll" gave
 *  "C:\Windows\storagewmi.dll", which does not exist, instead of
 *  "C:\Windows\System32\storagewmi.dll". */
std::vector<std::wstring> candidatesFor(const std::wstring& declare) {
	const std::wstring resolved = binaryPath(declare);
	std::vector<std::wstring> candidates;
	if (!resolved.empty()) candidates.push_back(resolved);
	const std::filesystem::path p = resolved.empty() ? declare : resolved;
	const std::wstring nameOnly = p.filename().wstring();
	if (!nameOnly.empty())
		candidates.push_back(conf.systemDrive + L"\\Windows\\System32\\" + nameOnly);
	return candidates;
}

/*! Loads the message table of a declared file: from the binary, otherwise from
 *  its localised satellite. Returns the number of messages. */
size_t loadTable(const std::wstring& declare, TableMessages& table, std::wstring* file) {
	for (const std::wstring& c : candidatesFor(declare)) {
		const std::wstring working = extractResource(c);
		if (working.empty()) continue;
		if (file) *file = c;
		PeResource pe;
		size_t n = pe.open(working) ? table.analyse(pe.resource(PE_RT_MESSAGETABLE)) : 0;
		if (n == 0) {
			const std::wstring mui = findMui(c);
			PeResource peMui;
			if (!mui.empty() && peMui.open(mui))
				n = table.analyse(peMui.resource(PE_RT_MESSAGETABLE));
		}
		return n;
	}
	return 0;
}

Provider* load(const std::wstring& guid) {
	const std::map<std::wstring, std::unique_ptr<Provider>>::iterator it = g_cache.find(guid);
	if (it != g_cache.end()) return it->second.get();

	std::unique_ptr<Provider> f = std::make_unique<Provider>();

	// 1. The path of the resource file, in the SOFTWARE hive.
	const std::wstring key = L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + guid;
	std::wstring path;
	if (getRegSzValue(conf.Software, key.c_str(), L"ResourceFileName", &path) != ERROR_SUCCESS
	    || path.empty()) {
		if (getRegSzValue(conf.Software, key.c_str(), L"MessageFileName", &path) != ERROR_SUCCESS
		    || path.empty()) {
			f->reason = L"no resource file declared";
			++g_failures;
			log(2, L"🔥Provider " + guid + L" : " + f->reason);
			Provider* brut = f.get();
			g_cache.emplace(guid, std::move(f));
			return brut;
		}
	}
	// `%SystemRoot%`, `%windir%` and the like, and a path relative to System32.
	const std::wstring resolved = binaryPath(path);
	const std::vector<std::wstring> candidates = candidatesFor(path);

	// 2. The metadata, in the binary itself.
	std::wstring workingDll;
	for (const std::wstring& c : candidates) {
		workingDll = extractResource(c);
		if (!workingDll.empty()) { f->file = c; break; }
	}
	if (workingDll.empty()) {
		f->file = resolved;
		f->reason = L"resource binary unreadable";
		++g_failures;
		log(2, L"🔥Provider " + guid + L" : " + f->reason + L" — candidates: "
		     + (candidates.empty() ? L"(none)" : candidates[0])
		     + (candidates.size() > 1 ? L" ; " + candidates[1] : L""));
		Provider* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	PeResource pe;
	if (!pe.open(workingDll)) {
		f->reason = L"PE unreadable: " + pe.error();
		++g_failures;
		log(2, L"🔥Provider " + guid + L" : " + f->reason + L" (" + workingDll + L")");
		Provider* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	f->metadata.analyse(pe.namedResource(L"WEVT_TEMPLATE"), guid);

	// 3. The texts: first in the localised satellite, otherwise in the binary.
	size_t nbMessages = f->messages.analyse(pe.resource(PE_RT_MESSAGETABLE));
	if (nbMessages == 0) {
		const std::wstring mui = findMui(f->file);
		if (!mui.empty()) {
			PeResource peMui;
			if (peMui.open(mui))
				nbMessages = f->messages.analyse(peMui.resource(PE_RT_MESSAGETABLE));
		}
	}

	/* PARAMETER FILE. The enumerated values of an event are written "%%nnnn" in
	   its DATA, and Windows resolves them in the provider's parameter file.
	   Looking for them in its own table left 8,337 raw references in 3,700
	   Security messages — "Elevated Token: %%1842" instead of "Yes". */
	{
		/* The name of the value is "ParameterFileName" in the provider's WINEVT key;
		   "ParameterMessageFile" is the one of the old EventLog service key.
		   Looking only for the second found nothing: Security declares its own
		   under the first (msobjs.dll). */
		std::wstring declare;
		if ((getRegSzValue(conf.Software, key.c_str(), L"ParameterFileName", &declare) == ERROR_SUCCESS
		     && !declare.empty())
		    || (getRegSzValue(conf.Software, key.c_str(), L"ParameterMessageFile", &declare) == ERROR_SUCCESS
		     && !declare.empty())) {
			std::wstring parameterFile;
			const size_t n = loadTable(declare, f->parameters, &parameterFile);
			log(2, L"❇️Provider " + guid + L" : " + std::to_wstring(n)
			     + L" parameter label(s) — " + (parameterFile.empty() ? declare : parameterFile));
		}
	}

	f->usable = (f->metadata.size() > 0 && nbMessages > 0);
	if (!f->usable) {
		f->reason = L"metadata or message table absent ("
		         + std::to_wstring(f->metadata.size()) + L" event(s), "
		         + std::to_wstring(nbMessages) + L" message(s))";
		++g_failures;
		log(2, L"🔥Provider " + guid + L" : " + f->reason + L" — " + f->file);
	}
	else {
		log(2, L"❇️Provider " + guid + L" : " + std::to_wstring(f->metadata.size())
		     + L" event(s), " + std::to_wstring(nbMessages) + L" message(s) — "
		     + f->file);
	}
	Provider* brut = f.get();
	g_cache.emplace(guid, std::move(f));
	return brut;
}

} // namespace

void MessagesInit() {
	g_cache.clear();
	g_failures = 0;
	g_resolved = 0;
	g_bytes = 0;
	// Without the SOFTWARE hive, no provider can be located: that is said once
	// rather than at every event.
	g_ready = (conf.Software != NULL);
	if (!g_ready)
		log(2, L"🔥SOFTWARE hive unavailable: the event messages will not be resolved");
}

std::wstring EventMessage(const std::wstring& providerGuid,
                              uint16_t eventId,
                              uint8_t version,
                              const std::vector<std::wstring>& values) {
	if (!g_ready || providerGuid.empty()) return std::wstring();

	Provider* f = load(normalizeGuid(providerGuid));
	if (!f || !f->usable) return std::wstring();

	const uint32_t idMessage = f->metadata.messageId(eventId, version);
	if (idMessage == 0) return std::wstring();
	const std::wstring messageTemplate = f->messages.text(idMessage);
	if (messageTemplate.empty()) return std::wstring();

	/*  A piece of data of the form "%%1234" is not a text but a REFERENCE to
	    another message of the same table — that is how Windows encodes
	    enumerated values. Without that resolution, the final message would show
	    "%%1234" instead of the label. */
	std::vector<std::wstring> resolved;
	resolved.reserve(values.size());
	for (const std::wstring& v : values) {
		if (v.size() > 2 && v[0] == L'%' && v[1] == L'%') {
			bool digits = true;
			for (size_t i = 2; i < v.size(); ++i)
				if (v[i] < L'0' || v[i] > L'9') { digits = false; break; }
			if (digits) {
				const uint32_t id = (uint32_t)wcstoul(v.c_str() + 2, nullptr, 10);
				std::wstring t = f->parameters.text(id);           // first: as Windows does
				if (t.empty()) t = f->messages.text(id);
				// A table label ends with "\r\n": inserted into a sentence, it would
				// cut it.
				while (!t.empty() && (t.back() == L'\n' || t.back() == L'\r' || t.back() == L' '))
					t.pop_back();
				resolved.push_back(t.empty() ? v : t);
				continue;
			}
		}
		resolved.push_back(v);
	}

	const std::wstring phrase = formatMessage(messageTemplate, resolved);
	if (!phrase.empty()) ++g_resolved;
	return phrase;
}

void MessagesSummary(size_t* providers, size_t* failures,
                   unsigned long long* resolved, unsigned long long* bytes) {
	if (providers) *providers = g_cache.size();
	if (failures)       *failures = g_failures;
	if (resolved)      *resolved = g_resolved;
	if (bytes)       *bytes = g_bytes;
}

void MessagesRelease() {
	g_cache.clear();
}

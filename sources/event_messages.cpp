#include "event_messages.h"
#include "registry_common.h"
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
 *  \brief Finding, extracting and caching the providers' resource files.
 *
 *  See event_messages.h for the chain to bring together.
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

std::map<std::wstring, std::unique_ptr<Provider>> g_cache;   // guid -> provider
std::unique_ptr<RawReader> g_reader;   //!< the raw reader of the resource files, for the whole phase (see extractResource)

/*! A classic event source (ReportEvent): its message files, declared under
 *  `Services\EventLog\<log>\<source>`, in the order Windows tries them. */
struct ClassicSource {
	std::vector<TableMessages> tables;   //!< one per file of EventMessageFile that has messages
	TableMessages parameters;            //!< ParameterMessageFile: labels of the "%%nnnn" values
};
std::map<std::wstring, std::unique_ptr<ClassicSource>> g_classic;   // "<log>\<source>", lower case -> source
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
	/* A conversion reads the collection, never a volume: the file is found
	   through the manifest (it may share an exhibit stored under another
	   name, see ExhibitStoreIndex), and a file the collection does not hold is
	   absent — the analysis workstation's own copy would give the messages of
	   another build. */
	if (conf.mode == RunMode::Convert) {
		const std::map<std::wstring, StoredExhibit>& index = ExhibitStoreIndex();
		const auto stored = index.find(toLower(absolutePath));
		if (stored == index.end() || !isValidPe(stored->second.file)) return std::wstring();
		std::filesystem::create_directories(std::filesystem::path(working).parent_path(), ec);
		std::filesystem::copy_file(stored->second.file, working, std::filesystem::copy_options::skip_existing, ec);
		return ec ? std::wstring() : working;
	}
	std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);

	/* ONE READER FOR THE WHOLE PHASE (backlog B-033): each volume opened once,
	   each directory's index read once. Extracted one by one, each of the
	   thousand-odd provider files re-opened the volume and re-read System32's
	   index (4,659 entries): 26 s of a 44-s event phase on the test VM. The
	   files read are system binaries, which the collection does not change. */
	if (!g_reader) g_reader = std::make_unique<RawReader>();
	RawHiveExtraction line;
	const HRESULT hr = g_reader->read(absolutePath, target, line);
	std::vector<RawHiveExtraction> reading{ line };
	const bool absent = hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	if (absent) {
		// A candidate that does not exist: neither an exhibit, nor an empty directory
// in the exhibit store.
		std::filesystem::remove(std::filesystem::path(target).parent_path(), ec);
		return std::wstring();
	}
	ExhibitStoreAdd(reading, L"Raw NTFS reading (\\\\.\\" + volume
	                        + L": — resource file of an event provider)" + READ_IN_PLACE);
	const bool rawReadOk = SUCCEEDED(hr);
	if (!rawReadOk)
		log(3, L"🔈Raw reading unsuccessful, fallback expected: " + absolutePath);
	else
		for (const RawHiveExtraction& e : reading) g_bytes += e.fingerprints.bytes;

	/*  NO FALLBACK THROUGH THE API. Those binaries are compressed by WOF
	    ("Compact OS"): their $DATA attribute is sparse and the content lives in a
	    named stream. The raw reading now handles them entirely, XPRESS and LZX
	    (see xpress.h, lzx.h), and nothing is therefore opened on the examined
	    system. A file that stays unreadable is so for another reason — absent,
	    or damaged — and it is reported as such rather than read by a route
	    that would leave a trace. */
	if (!rawReadOk || !isValidPe(target)) {
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

	auto add = [](const std::wstring& l) {
		if (l.empty()) return;
		for (const std::wstring& d : languages) if (_wcsicmp(d.c_str(), l.c_str()) == 0) return;
		languages.push_back(l);
	};
	/* The machine's interface language is declared in the SYSTEM hive
	   (Control\MUI\Settings, then the installed languages under
	   Control\MUI\UILanguages); SOFTWARE's MUI\Settings is often empty. Reading
	   only the latter, WAC fell back on its list, en-US first: messages in
	   English on a French machine whenever an en-US satellite existed —
	   MsiInstaller, Defender (B-023). */
	std::vector<std::wstring> declared;
	if (conf.CurrentControlSet && getRegMultiSzValue(conf.CurrentControlSet, L"Control\\MUI\\Settings",
	        L"PreferredUILanguages", &declared) == ERROR_SUCCESS)
		for (const std::wstring& l : declared) add(l);
	declared.clear();
	if (conf.Software && getRegMultiSzValue(conf.Software,
	        L"Microsoft\\Windows\\CurrentVersion\\MUI\\Settings",
	        L"PreferredUILanguages", &declared) == ERROR_SUCCESS)
		for (const std::wstring& l : declared) add(l);
	if (conf.CurrentControlSet)
		for (const std::wstring& l : subkeys(conf.CurrentControlSet, L"Control\\MUI\\UILanguages")) add(l);

	for (PCWSTR l : { L"en-US", L"fr-FR", L"de-DE", L"es-ES", L"it-IT" }) add(l);
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

/*! Loads a message table as Windows chooses it: from the localised satellite
 *  first, in the interface's language, then from the binary itself. The
 *  binary's own table is the language-neutral fallback, usually English: read
 *  first, it gave MsiInstaller's messages in English on a French system
 *  (B-023).
 *  @param absolutePath the binary, on the examined machine
 *  @param working its copy in the working directory
 *  @param table receives the messages
 *  @return the number of messages */
size_t loadLocalisedTable(const std::wstring& absolutePath, const std::wstring& working, TableMessages& table) {
	const std::wstring mui = findMui(absolutePath);
	PeResource peMui;
	if (!mui.empty() && peMui.open(mui)) {
		const size_t n = table.analyse(peMui.resource(PE_RT_MESSAGETABLE));
		if (n > 0) return n;
	}
	PeResource pe;
	return pe.open(working) ? table.analyse(pe.resource(PE_RT_MESSAGETABLE)) : 0;
}

/*! Loads the message table of a declared file (see loadLocalisedTable).
 *  Returns the number of messages. */
size_t loadTable(const std::wstring& declare, TableMessages& table, std::wstring* file) {
	for (const std::wstring& c : candidatesFor(declare)) {
		const std::wstring working = extractResource(c);
		if (working.empty()) continue;
		if (file) *file = c;
		return loadLocalisedTable(c, working, table);
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
			log(2, L"🔥Provider " + guid + L": " + f->reason);
			Provider* provider = f.get();
			g_cache.emplace(guid, std::move(f));
			return provider;
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
		log(2, L"🔥Provider " + guid + L": " + f->reason + L" — candidates: "
		     + (candidates.empty() ? L"(none)" : candidates[0])
		     + (candidates.size() > 1 ? L" ; " + candidates[1] : L""));
		Provider* provider = f.get();
		g_cache.emplace(guid, std::move(f));
		return provider;
	}
	PeResource pe;
	if (!pe.open(workingDll)) {
		f->reason = L"PE unreadable: " + pe.error();
		++g_failures;
		log(2, L"🔥Provider " + guid + L": " + f->reason + L" (" + workingDll + L")");
		Provider* provider = f.get();
		g_cache.emplace(guid, std::move(f));
		return provider;
	}
	/* Windows 11 moved some binaries' resources into a resource-only twin,
	   %SystemRoot%\SystemResources\<name>.mun, where the loader looks for what
	   the binary no longer holds: shsvcs.dll (Shell-Core) has no
	   WEVT_TEMPLATE, its .mun has — 28 kinds of event without a message
	   (B-023). The satellite in the interface's language stays beside the
	   binary. */
	std::vector<uint8_t> manifest = pe.namedResource(L"WEVT_TEMPLATE");
	if (manifest.empty()) {
		const std::wstring twin = conf.systemDrive + L"\\Windows\\SystemResources\\"
		                        + std::filesystem::path(f->file).filename().wstring() + L".mun";
		const std::wstring workingTwin = extractResource(twin);
		PeResource peTwin;
		if (!workingTwin.empty() && peTwin.open(workingTwin)) {
			manifest = peTwin.namedResource(L"WEVT_TEMPLATE");
			if (!manifest.empty()) log(2, L"❇️Provider " + guid + L": manifest read in " + twin);
		}
	}
	f->metadata.analyse(manifest, guid);

	// 3. The texts: first in the localised satellite, otherwise in the binary.
	const size_t nbMessages = loadLocalisedTable(f->file, workingDll, f->messages);

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
		log(2, L"🔥Provider " + guid + L": " + f->reason + L" — " + f->file);
	}
	else {
		log(2, L"❇️Provider " + guid + L" : " + std::to_wstring(f->metadata.size())
		     + L" event(s), " + std::to_wstring(nbMessages) + L" message(s) — "
		     + f->file);
	}
	Provider* provider = f.get();
	g_cache.emplace(guid, std::move(f));
	return provider;
}

/*! Loads a classic source's message files, only once.
 *  @param logName the log the event is in (its channel: "Application")
 *  @param source the event's provider name
 *  @return the source; without any table when nothing usable is declared */
ClassicSource* loadClassic(const std::wstring& logName, const std::wstring& source) {
	std::wstring id = logName + L"\\" + source;
	for (wchar_t& c : id) c = (wchar_t)towlower(c);
	const auto it = g_classic.find(id);
	if (it != g_classic.end()) return it->second.get();
	std::unique_ptr<ClassicSource> s = std::make_unique<ClassicSource>();
	const std::wstring key = L"Services\\EventLog\\" + logName + L"\\" + source;
	std::wstring declared;
	/* A source registered with only a providerGuid ("COM+" for Complus) takes
	   its messages in that provider's MessageFileName, by the same full
	   identifier — as Windows does (Complus 781, B-023). */
	std::wstring providerGuid;
	if (conf.CurrentControlSet && conf.Software
	    && getRegSzValue(conf.CurrentControlSet, key.c_str(), L"EventMessageFile", &declared) != ERROR_SUCCESS
	    && getRegSzValue(conf.CurrentControlSet, key.c_str(), L"providerGuid", &providerGuid) == ERROR_SUCCESS
	    && !providerGuid.empty())
		getRegSzValue(conf.Software, (L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + normalizeGuid(providerGuid)).c_str(),
		              L"MessageFileName", &declared);
	if (conf.CurrentControlSet && !declared.empty()) {
		// Several files, separated by semicolons: each one is tried in turn.
		size_t start = 0;
		while (start <= declared.size()) {
			const size_t end = std::min(declared.find(L';', start), declared.size());
			const std::wstring file = declared.substr(start, end - start);
			if (!file.empty()) {
				TableMessages table;
				std::wstring found;
				if (loadTable(file, table, &found) > 0) s->tables.push_back(std::move(table));
				else log(2, L"🔥Event source " + logName + L"/" + source + L": no message table in " + file);
			}
			start = end + 1;
		}
		std::wstring parameters;
		if (getRegSzValue(conf.CurrentControlSet, key.c_str(), L"ParameterMessageFile", &parameters) == ERROR_SUCCESS
		    && !parameters.empty())
			loadTable(parameters, s->parameters, nullptr);
	}
	if (s->tables.empty()) {
		++g_failures;
		log(2, L"🔥Event source " + logName + L"/" + source + L": no message file declared or readable");
	}
	ClassicSource* result = s.get();
	g_classic.emplace(id, std::move(s));
	return result;
}

/*! The system's message tables, loaded once: kernelbase's for the Win32
 *  errors and HRESULTs, ntdll's for the NTSTATUS codes, each from its
 *  satellite in the interface's language first, as FormatMessage reads them.
 *  @return the tables; a missing one is null */
const SystemMessages& systemMessages() {
	static TableMessages errors, ntStatus;
	static SystemMessages tables;
	static bool loaded = false;
	if (loaded) return tables;
	loaded = true;
	if (loadTable(L"%SystemRoot%\\System32\\kernelbase.dll", errors, nullptr) > 0) tables.errors = &errors;
	else log(2, L"🔥System message table of kernelbase.dll unreadable: error codes left as numbers");
	if (loadTable(L"%SystemRoot%\\System32\\ntdll.dll", ntStatus, nullptr) > 0) tables.ntStatus = &ntStatus;
	else log(2, L"🔥System message table of ntdll.dll unreadable: NTSTATUS codes left as numbers");
	return tables;
}

/*! Fills a message template with the event's values.
 *
 *  A value of the form "%%1234" is not a text but a REFERENCE to another
 *  message — that is how Windows encodes enumerated values: looked for in the
 *  parameter file first, as Windows does, then in the provider's own tables.
 *  Without that resolution the message would show "%%1234" instead of the
 *  label.
 *  @param messageTemplate the template, with its %1 %2… marks
 *  @param parameters the parameter file's table
 *  @param own the provider's own tables
 *  @param values the event's values
 *  @return the sentence, or an empty string */
std::wstring render(const std::wstring& messageTemplate, const TableMessages& parameters,
                    const std::vector<const TableMessages*>& own, const std::vector<std::wstring>& values) {
	/* Every "%%nnnn" of a value is replaced where it stands: a value may hold
	   several — the account-control flags of a 4720 are "%%2080 %%2082
	   %%2084", one label per flag set. Resolving only a value that was a
	   single reference left those raw (B-023). */
	auto label = [&](uint32_t id) {
		std::wstring t = parameters.text(id);
		for (const TableMessages* table : own) if (t.empty()) t = table->text(id);
		// A table label ends with "\r\n": inserted into a sentence, it would cut it.
		while (!t.empty() && (t.back() == L'\n' || t.back() == L'\r' || t.back() == L' ')) t.pop_back();
		return t;
	};
	std::vector<std::wstring> resolved;
	resolved.reserve(values.size());
	for (const std::wstring& v : values) {
		std::wstring out;
		size_t i = 0;
		while (i < v.size()) {
			size_t digits = i + 2;
			while (digits < v.size() && v[digits] >= L'0' && v[digits] <= L'9' && digits - i < 12) ++digits;
			if (v.compare(i, 2, L"%%") == 0 && digits > i + 2) {
				const std::wstring text = label((uint32_t)wcstoul(v.substr(i + 2, digits - i - 2).c_str(), nullptr, 10));
				out += text.empty() ? v.substr(i, digits - i) : text;   // an unknown reference stays as written
				i = digits;
			} else out += v[i++];
		}
		resolved.push_back(out);
	}

	const std::wstring phrase = formatMessage(messageTemplate, resolved);
	if (!phrase.empty()) ++g_resolved;
	return phrase;
}

} // namespace

void MessagesInit() {
	g_cache.clear();
	g_classic.clear();
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
                              const std::vector<std::wstring>& values,
                              const std::vector<std::wstring>& names) {
	if (!g_ready || providerGuid.empty()) return std::wstring();

	Provider* f = load(normalizeGuid(providerGuid));
	if (!f || !f->usable) return std::wstring();

	const uint32_t idMessage = f->metadata.messageId(eventId, version);
	if (idMessage == 0) return std::wstring();
	const std::wstring messageTemplate = f->messages.text(idMessage);
	if (messageTemplate.empty()) return std::wstring();

	const std::vector<WevtItem>* items = f->metadata.items(eventId, version);
	if (!items) return render(messageTemplate, f->parameters, { &f->messages }, values);

	/* THE VALUES OF EACH ITEM, BY NAME. %N is the template's N-th item, and an
	   array item spreads over several Data of its name (Ntfs 170 version 13:
	   101 Data for 86 items, its ExtentsCountArray 16): taken by position,
	   every value after the array went to the wrong mark. Each item takes the
	   consecutive values of its name; when the names do not line up with the
	   items (data without names), the values are taken by position, and only
	   when there are as many as items. */
	std::vector<std::vector<std::wstring>> perItem(items->size());
	bool aligned = names.size() == values.size();
	size_t next = 0;
	for (size_t i = 0; aligned && i < items->size(); ++i)
		while (next < values.size() && !(*items)[i].name.empty() && names[next] == (*items)[i].name)
			perItem[i].push_back(values[next++]);
	aligned = aligned && next == values.size();
	if (!aligned) {
		if (items->size() != values.size()) return render(messageTemplate, f->parameters, { &f->messages }, values);
		for (size_t i = 0; i < values.size(); ++i) perItem[i] = { values[i] };
	}
	// Each item's first value, by which a map's label fills its own marks.
	std::vector<std::wstring> firsts;
	for (const std::vector<std::wstring>& v : perItem) firsts.push_back(v.empty() ? std::wstring() : v.front());
	// Each value as Windows shows it, by its template item (see formatItemValue).
	std::vector<std::wstring> shown;
	shown.reserve(items->size());
	for (size_t i = 0; i < items->size(); ++i) {
		const WevtValueMap* map = f->metadata.valueMap((*items)[i].map);
		std::wstring joined;
		for (const std::wstring& v : perItem[i]) {
			std::wstring value = formatItemValue((*items)[i], map, f->messages, systemMessages(), v);
			/* A map's label may itself hold marks, filled with the event's
			   values: SMBServer 1034's "…for interface %2. Current DadState: %6." */
			if (map && value.find(L'%') != std::wstring::npos) value = formatMessage(value, firsts);
			// An array's values joined by ", " — not measured: no message of the VM inserts one.
			if (!joined.empty()) joined += L", ";
			joined += value;
		}
		shown.push_back(joined);
	}
	return render(messageTemplate, f->parameters, { &f->messages }, shown);
}

std::wstring ClassicEventMessage(const std::wstring& logName, const std::wstring& source, uint32_t messageId,
                                 const std::vector<std::wstring>& values) {
	if (!g_ready || logName.empty() || source.empty()) return std::wstring();
	const ClassicSource* s = loadClassic(logName, source);
	std::vector<const TableMessages*> own;
	for (const TableMessages& t : s->tables) own.push_back(&t);
	// The files in the declared order: the first that has the message gives it.
	for (const TableMessages* table : own) {
		const std::wstring messageTemplate = table->text(messageId);
		if (!messageTemplate.empty()) return render(messageTemplate, s->parameters, own, values);
	}
	return std::wstring();
}

HRESULT MessagesCollectAll() {
	MessagesInit();
	if (!g_ready) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	ORHKEY publishers = NULL;
	HRESULT hr = OROpenKey(conf.Software, L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers", &publishers);
	if (hr != ERROR_SUCCESS) {
		log(2, L"🔥WINEVT\\Publishers unreadable: no event provider collected", hr);
		return hr;
	}
	for (DWORD i = 0;; ++i) {
		WCHAR guid[MAX_KEY_NAME] = L"";
		DWORD size = MAX_KEY_NAME;
		hr = OREnumKey(publishers, i, guid, &size, NULL, NULL, NULL);
		if (hr == ERROR_NO_MORE_ITEMS) { hr = ERROR_SUCCESS; break; }
		if (hr != ERROR_SUCCESS) {
			log(2, L"🔥WINEVT\\Publishers: enumeration stopped at " + std::to_wstring(i), hr);
			break;
		}
		load(normalizeGuid(guid));   // extracts its resource, parameter and .mui files
	}
	ORCloseKey(publishers);
	/* The classic sources (Services\EventLog\<log>\<source>), whose message
	   files are declared in SYSTEM, and the system's own tables (kernelbase,
	   ntdll) that give an error code its text: a conversion reads only what
	   was collected, and without them three events in eight lost their
	   message (B-023). */
	if (conf.CurrentControlSet)
		for (const std::wstring& logName : subkeys(conf.CurrentControlSet, L"Services\\EventLog"))
			for (const std::wstring& source : subkeys(conf.CurrentControlSet, L"Services\\EventLog\\" + logName))
				loadClassic(logName, source);
	systemMessages();
	log(2, L"❇️Event providers collected: " + std::to_wstring(g_cache.size() + g_classic.size()) + L", "
	     + std::to_wstring(g_failures) + L" without usable resources, "
	     + std::to_wstring(g_bytes / 1024 / 1024) + L" MiB");
	return hr;
}

void MessagesSummary(size_t* providers, size_t* failures,
                   unsigned long long* resolved, unsigned long long* bytes) {
	if (providers) *providers = g_cache.size() + g_classic.size();
	if (failures)       *failures = g_failures;
	if (resolved)      *resolved = g_resolved;
	if (bytes)       *bytes = g_bytes;
}

void MessagesRelease() {
	g_cache.clear();
	g_reader.reset();
	g_classic.clear();
}

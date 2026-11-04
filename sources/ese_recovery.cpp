/*! \file
 *  \brief Replay of an ESE database's transaction logs into its working copy
 *         (see ese_recovery.h).
 */
#include "ese_recovery.h"
#include "audit.h"
#include "long_path.h"
#include "system_library.h"
#include "tools.h"
#include <algorithm>
#include <esent.h>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <vector>

namespace {

/* JetInit3's and JetTerm2's options, as Microsoft documents them for esent.h
   (MinGW's header does not carry them). */
const JET_GRBIT REPLAY_IGNORE_MISSING_DB = 0x00000004;     //!< JET_bitReplayIgnoreMissingDB
const JET_GRBIT REPLAY_MISSING_MAP_ENTRY_DB = 0x00000020;  //!< JET_bitReplayMissingMapEntryDB: a database not in the map is missing
const JET_GRBIT TERM_COMPLETE = 0x00000001;                //!< JET_bitTermComplete

const size_t HEADER_PAGE_SIZE = 236;    //!< uint32, the page size, in the database's header (ese_database.h)
const size_t HEADER_STATE = 52;         //!< uint32, its state: 3 once shut down clean
const uint32_t CLEAN_SHUTDOWN = 3;

/*! The engine's functions, resolved from esent.dll. */
struct Engine {
	HMODULE module = nullptr;
	decltype(&JetCreateInstance2W) createInstance = nullptr;
	decltype(&JetSetSystemParameterW) setParameter = nullptr;
	decltype(&JetInit3W) init = nullptr;
	decltype(&JetTerm2) term = nullptr;
	~Engine() { if (module) FreeLibrary(module); }
};

/*! Loads esent.dll from System32 and its functions.
 *  @param engine receives them
 *  @return false if the library or one of them is missing */
bool loadEngine(Engine& engine) {
	engine.module = loadSystemLibrary(L"esent.dll");
	return engine.module
	    && resolveExport(engine.module, "JetCreateInstance2W", engine.createInstance)
	    && resolveExport(engine.module, "JetSetSystemParameterW", engine.setParameter)
	    && resolveExport(engine.module, "JetInit3W", engine.init)
	    && resolveExport(engine.module, "JetTerm2", engine.term);
}

/*! Two fields of the database's header.
 *  @param database the copy
 *  @param pageSize receives the page size
 *  @param state receives the state
 *  @return false if the header cannot be read */
bool readHeader(const std::filesystem::path& database, uint32_t& pageSize, uint32_t& state) {
	std::ifstream in(std::filesystem::path(extendedPath(database.wstring())), std::ios::binary);
	std::vector<uint8_t> header(HEADER_PAGE_SIZE + 4);
	if (!in.read(reinterpret_cast<char*>(header.data()), (std::streamsize)header.size())) return false;
	pageSize = readLittleEndian<uint32_t>(header, HEADER_PAGE_SIZE);
	state = readLittleEndian<uint32_t>(header, HEADER_STATE);
	return true;
}

/*! One replay under one base name, see ReplayEseLogsOnce. */
EseReplay replayUnder(const std::wstring& baseName, const std::filesystem::path& folder, const std::filesystem::path& systemFolder,
                      const std::wstring& workingDatabase, const std::wstring& originalDatabase) {
	EseReplay r;
	const std::filesystem::path database(workingDatabase);
	r.baseName = baseName;
	const std::filesystem::path current = folder / (r.baseName + L".log");
	if (!pathExists(current.wstring())) {
		r.detail = L"no current log " + r.baseName + L".log beside the copy: nothing to replay";
		return r;
	}
	uint32_t pageSize = 0, state = 0;
	if (!readHeader(database, pageSize, state)) {
		r.detail = L"header of the copy unreadable";
		return r;
	}
	if (state == CLEAN_SHUTDOWN) {
		r.detail = L"copy already in a clean state: nothing to replay";
		return r;
	}
	Engine engine;
	if (!loadEngine(engine)) {
		r.detail = L"esent.dll or one of its functions not available";
		return r;
	}
	uint64_t logSize = 0;
	if (!fileSizeOf(current.wstring(), logSize)) {
		r.detail = L"size of the current log unreadable: not replayed";
		return r;
	}
	/* The engine rewrites the copy's pages as it goes: stopped partway (a log
	   missing or damaged, written by a newer engine), it would leave a state
	   the database never had, read as if collected. The copy as collected is
	   kept aside, and put back when the replay is not applied. */
	const std::wstring asCollected = workingDatabase + L".as-collected";
	if (!copyFileLong(workingDatabase, asCollected, true)) {
		r.detail = L"copy of the database before its replay failed: not replayed";
		return r;
	}
	r.attempted = true;
	// The engine wants its folders with their trailing separator.
	const std::wstring logPath = folder.wstring() + L"\\", systemPath = systemFolder.wstring() + L"\\";
	JET_INSTANCE instance = 0;
	JET_ERR err = engine.setParameter(nullptr, 0, JET_paramDatabasePageSize, pageSize, nullptr);
	if (err >= 0) err = engine.setParameter(nullptr, 0, JET_paramDisablePerfmon, 1, nullptr);
	if (err >= 0) err = engine.createInstance(&instance, L"WAC-replay", L"WAC replay of a copied database", 0);
	if (err >= 0) {
		const struct { unsigned long id; JET_API_PTR number; const wchar_t* text; } parameters[] = {
			{ JET_paramSystemPath, 0, systemPath.c_str() },
			{ JET_paramLogFilePath, 0, logPath.c_str() },
			{ JET_paramTempPath, 0, systemPath.c_str() },
			{ JET_paramBaseName, 0, r.baseName.c_str() },
			{ JET_paramLogFileSize, (JET_API_PTR)(logSize / 1024), nullptr },
			{ JET_paramRecovery, 0, L"On" },
			// No event in the Application log of the machine it runs on, nor a folder created.
			{ JET_paramEventLoggingLevel, JET_EventLoggingDisable, nullptr },
			{ JET_paramNoInformationEvent, 1, nullptr },
			{ JET_paramCreatePathIfNotExist, 0, nullptr },
		};
		for (const auto& p : parameters)
			if (err >= 0) err = engine.setParameter(&instance, 0, p.id, p.number, p.text);
	}
	if (err >= 0) {
		// The logs name the database by its path on the examined machine: sent to the copy.
		std::wstring original = originalDatabase, copy = workingDatabase;
		JET_RSTMAP_W map = { &original[0], &copy[0] };
		JET_RSTINFO_W restore = {};
		restore.cbStruct = sizeof(restore);
		restore.rgrstmap = &map;
		restore.crstmap = 1;
		err = engine.init(&instance, &restore, REPLAY_IGNORE_MISSING_DB | REPLAY_MISSING_MAP_ENTRY_DB);
	}
	if (instance) engine.term(instance, TERM_COMPLETE);
	r.jetError = err;
	uint32_t after = 0;
	if (err >= 0 && readHeader(database, pageSize, after) && after == CLEAN_SHUTDOWN) {
		r.applied = true;
		r.detail = L"logs " + r.baseName + L"*.log replayed by esent.dll into the copy, now clean";
	}
	else {
		const bool restored = copyFileLong(asCollected, workingDatabase, true);
		r.detail = L"replay not applied (JET error " + std::to_wstring(err) + L", state " + std::to_wstring(after) + L"): "
		         + (restored ? L"the copy is read as collected" : L"the copy as collected could not be put back, read as the engine left it");
	}
	if (!DeleteFileW(extendedPath(asCollected).c_str()))
		log(2, L"🔥" + asCollected + L": not deleted after the replay");
	return r;
}

/*! Replays a copy's logs, under each base name found until one applies.
 *  A controller's NTDS folder has been measured holding two checkpoints: Api.chk,
 *  left by the promotion on Server 2016, and edb.chk, the database's. Under the
 *  wrong one the engine succeeds and leaves the copy dirty: the outcome, not the
 *  name, tells them apart. */
EseReplay replay(const std::wstring& workingDatabase, const std::wstring& originalDatabase, const std::wstring& workingLogFolder) {
	const std::filesystem::path database(workingDatabase);
	const std::filesystem::path folder = workingLogFolder.empty() ? database.parent_path() : std::filesystem::path(workingLogFolder);
	/* Logs moved by ntdsutil leave their checkpoint beside the database
	   (measured: edb.chk stays in NTDS, edb*.log go): the engine's system
	   path is the checkpoint's folder, its log path the logs'. */
	std::filesystem::path systemFolder = folder;
	std::vector<std::wstring> baseNames = eseLogBaseNames(folder);
	if (baseNames.empty() && !workingLogFolder.empty()) {
		systemFolder = database.parent_path();
		baseNames = eseLogBaseNames(systemFolder);
	}
	EseReplay outcome;
	outcome.detail = L"no checkpoint beside the copy: nothing to replay";
	for (const std::wstring& baseName : baseNames) {
		EseReplay r = replayUnder(baseName, folder, systemFolder, workingDatabase, originalDatabase);
		if (r.applied) return r;
		if (r.attempted || !outcome.attempted) outcome = std::move(r);
	}
	return outcome;
}

} // namespace

std::vector<std::wstring> eseLogBaseNames(const std::wstring& folder) {
	std::vector<std::wstring> names;
	std::error_code ec;
	for (std::filesystem::directory_iterator it(std::filesystem::path(extendedPath(folder)), ec), end; !ec && it != end; it.increment(ec))
		if (it->is_regular_file(ec) && toLower(it->path().extension().wstring()) == L".chk")
			names.push_back(it->path().stem().wstring());
	// The engine's default name first, then in a fixed order: the same outcome from one run to the next.
	std::sort(names.begin(), names.end(), [](const std::wstring& a, const std::wstring& b) {
		const std::wstring lowerA = toLower(a), lowerB = toLower(b);
		const bool firstA = lowerA == L"edb", firstB = lowerB == L"edb";
		return firstA != firstB ? firstA : lowerA < lowerB;
	});
	return names;
}

EseReplay ReplayEseLogsOnce(const std::wstring& workingDatabase, const std::wstring& originalDatabase,
                            const std::wstring& workingLogFolder) {
	/* One replay at a time: the engine's page size is a parameter of the
	   process, and the artefacts are converted in parallel. */
	static std::mutex lock;
	static std::map<std::wstring, EseReplay> done;
	std::lock_guard<std::mutex> guard(lock);
	const std::wstring key = toLower(workingDatabase);
	const auto found = done.find(key);
	if (found != done.end()) return found->second;
	EseReplay r = replay(workingDatabase, originalDatabase, workingLogFolder);
	log(2, (r.applied ? L"❇️" : L"🔥") + workingDatabase + L": " + r.detail);
	if (r.attempted)
		auditRecord(L"Replay of the transaction logs of a copied ESE database (" + r.baseName + L")",
		            workingDatabase + L" | " + r.detail,
		            r.applied ? ERROR_SUCCESS : E_FAIL, Footprint::ESE_REPLAY);
	done[key] = r;
	return r;
}

HRESULT OpenRecoveredEseDatabase(EseDatabase& database, const std::wstring& workingDatabase, const std::wstring& originalDatabase,
                                 const std::wstring& workingLogFolder) {
	const EseReplay replayed = ReplayEseLogsOnce(workingDatabase, originalDatabase, workingLogFolder);
	if (replayed.attempted && !replayed.applied)
		log(1, L"⚠️" + originalDatabase + L": transaction logs not replayed, its latest changes may be missing — " + replayed.detail);
	return database.open(workingDatabase);
}

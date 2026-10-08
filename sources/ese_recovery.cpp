/*! \file
 *  \brief Replay of an ESE database's transaction logs into its working copy
 *         (see ese_recovery.h).
 */
#include "ese_recovery.h"
#include "audit.h"
#include "system_library.h"
#include "tools.h"
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

/*! The logs' base name: the stem of the checkpoint file beside the database
 *  ("V01.chk" for the WebCache, "SRU.chk" for SRUM).
 *  @param folder the copy's folder
 *  @return the base name, empty if there is no checkpoint */
std::wstring logBaseName(const std::filesystem::path& folder) {
	std::error_code ec;
	for (const std::filesystem::directory_entry& e : std::filesystem::directory_iterator(folder, ec))
		if (e.is_regular_file(ec) && toLower(e.path().extension().wstring()) == L".chk")
			return e.path().stem().wstring();
	return L"";
}

/*! Two fields of the database's header.
 *  @param database the copy
 *  @param pageSize receives the page size
 *  @param state receives the state
 *  @return false if the header cannot be read */
bool readHeader(const std::filesystem::path& database, uint32_t& pageSize, uint32_t& state) {
	std::ifstream in(database, std::ios::binary);
	std::vector<uint8_t> header(HEADER_PAGE_SIZE + 4);
	if (!in.read(reinterpret_cast<char*>(header.data()), (std::streamsize)header.size())) return false;
	pageSize = readLittleEndian<uint32_t>(header, HEADER_PAGE_SIZE);
	state = readLittleEndian<uint32_t>(header, HEADER_STATE);
	return true;
}

/*! One replay, see ReplayEseLogsOnce. */
EseReplay replay(const std::wstring& workingDatabase, const std::wstring& originalDatabase) {
	EseReplay r;
	const std::filesystem::path database(workingDatabase);
	const std::filesystem::path folder = database.parent_path();
	r.baseName = logBaseName(folder);
	std::error_code ec;
	const std::filesystem::path current = folder / (r.baseName + L".log");
	if (r.baseName.empty() || !std::filesystem::exists(current, ec)) {
		r.detail = L"no checkpoint and current log beside the copy: nothing to replay";
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
	r.attempted = true;
	// The engine wants its folders with their trailing separator.
	const std::wstring path = folder.wstring() + L"\\";
	const uintmax_t logSize = std::filesystem::file_size(current, ec);
	JET_INSTANCE instance = 0;
	JET_ERR err = engine.setParameter(nullptr, 0, JET_paramDatabasePageSize, pageSize, nullptr);
	if (err >= 0) err = engine.setParameter(nullptr, 0, JET_paramDisablePerfmon, 1, nullptr);
	if (err >= 0) err = engine.createInstance(&instance, L"WAC-replay", L"WAC replay of a copied database", 0);
	if (err >= 0) {
		const struct { unsigned long id; JET_API_PTR number; const wchar_t* text; } parameters[] = {
			{ JET_paramSystemPath, 0, path.c_str() },
			{ JET_paramLogFilePath, 0, path.c_str() },
			{ JET_paramTempPath, 0, path.c_str() },
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
	else r.detail = L"replay not applied (JET error " + std::to_wstring(err) + L", state "
	              + std::to_wstring(after) + L"): the copy is read as collected";
	return r;
}

} // namespace

EseReplay ReplayEseLogsOnce(const std::wstring& workingDatabase, const std::wstring& originalDatabase) {
	/* One replay at a time: the engine's page size is a parameter of the
	   process, and the artefacts are converted in parallel. */
	static std::mutex lock;
	static std::map<std::wstring, EseReplay> done;
	std::lock_guard<std::mutex> guard(lock);
	const std::wstring key = toLower(workingDatabase);
	const auto found = done.find(key);
	if (found != done.end()) return found->second;
	EseReplay r = replay(workingDatabase, originalDatabase);
	log(2, (r.applied ? L"❇️" : L"🔥") + workingDatabase + L": " + r.detail);
	if (r.attempted)
		auditRecord(L"Replay of the transaction logs of a copied ESE database (" + r.baseName + L")",
		            workingDatabase + L" | " + r.detail,
		            r.applied ? ERROR_SUCCESS : E_FAIL, Footprint::ESE_REPLAY);
	done[key] = r;
	return r;
}

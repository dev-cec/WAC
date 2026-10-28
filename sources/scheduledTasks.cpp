/*! \file
 *  \brief Offline reading of the scheduled tasks (see scheduledTasks.h).
 */
#include "scheduledTasks.h"
#include "registry_common.h"
#include "xml_light.h"
#include <filesystem>
#include <map>

namespace {

//! Root of the task definitions, relative to the extraction point.
const wchar_t* TASKS_SUBFOLDER = L"\\Windows\\System32\\Tasks";
//! Before Vista: the .job files.
const wchar_t* JOBS_SUBFOLDER = L"\\Windows\\Tasks";

// The .job file (MS-TSCH 2.4.1): offsets of its fixed part, flags and statuses.
const size_t JOB_FIXED = 68, JOB_EXIT_CODE = 40, JOB_STATUS = 44, JOB_FLAGS = 48, JOB_RUN_DATE = 52;
const size_t JOB_TRIGGER = 48;           //!< size of a trigger
const uint32_t JOB_DISABLED = 0x4;       //!< TASK_FLAG_DISABLED, and TASK_TRIGGER_FLAG_DISABLED in a trigger
const uintmax_t JOB_MAX = 1 << 20;       //!< a .job is a few hundred bytes

/*! Execution history of a task, read in the TaskCache. */
struct History {
	FILETIME lastRunUtc = { 0 };
	LONG     lastResult = 0;
	bool     found = false;
};

/*! Decodes the binary value `DynamicInfo` of the TaskCache.
 *
 *  Layout (stable since Vista, variable length depending on the version):
 *    0x00 version (4)
 *    0x04 last registration        (FILETIME, 8)
 *    0x0C last run                 (FILETIME, 8)
 *    0x14 return code              (4)
 *    0x18 unknown                  (4)
 *    0x1C last successful run      (FILETIME, 8) — recent versions
 *
 *  The size is checked before reading: the value comes from the examined
 *  machine's registry, hence from an untrusted source.
 */
History decoderDynamicInfo(const BYTE* data, DWORD size) {
	History h;
	if (!data || size < 0x18) return h;
	const ULONGLONG lastRun100ns = *reinterpret_cast<const ULONGLONG*>(data + 0x0C);
	h.lastRunUtc.dwLowDateTime  = (DWORD)(lastRun100ns & 0xFFFFFFFFULL);
	h.lastRunUtc.dwHighDateTime = (DWORD)(lastRun100ns >> 32);
	h.lastResult = *reinterpret_cast<const LONG*>(data + 0x14);
	h.found = true;
	return h;
}

/*! Walks `TaskCache\Tree` and reads the GUID of every task.
 *
 *  The tree reproduces the hierarchy of the task folders: the walk is therefore
 *  recursive, with a depth guard (a corrupted registry index could loop).
 */
void walkTree(ORHKEY key, const std::wstring& path,
                    std::map<std::wstring, std::wstring>& idByPath,
                    unsigned depthLeft) {
	if (!key || depthLeft == 0) return;

	// A leaf carries the Id value; a branch carries subkeys.
	std::wstring id;
	if (getRegSzValue(key, L"", L"Id", &id) == ERROR_SUCCESS && !id.empty())
		idByPath.emplace(toLower(path), id);

	for (const Subkey& sub : subkeysOf(key)) {
		ORHKEY subKey = NULL;
		if (OROpenKey(key, sub.name.c_str(), &subKey) != ERROR_SUCCESS) continue;
		walkTree(subKey, path + L"\\" + sub.name, idByPath, depthLeft - 1);
		ORCloseKey(subKey);
	}
}

/*! Reads the TaskCache: task path -> execution history. */
std::map<std::wstring, History> readTaskCache() {
	std::map<std::wstring, History> result;
	if (!conf.Software) {
		log(2, L"🔥TaskCache: SOFTWARE hive unavailable, history not collected");
		return result;
	}

	const std::wstring root = L"Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
	ORHKEY treeKey = NULL;
	if (OROpenKey(conf.Software, (root + L"\\Tree").c_str(), &treeKey) != ERROR_SUCCESS) {
		log(2, L"🔥TaskCache\\Tree not found: execution history not collected");
		return result;
	}

	std::map<std::wstring, std::wstring> idByPath;
	walkTree(treeKey, L"", idByPath, 16);
	ORCloseKey(treeKey);
	log(2, L"❇️TaskCache : " + std::to_wstring(idByPath.size()) + L" task(s) referenced");

	for (const std::pair<const std::wstring, std::wstring>& e : idByPath) {
		const std::wstring taskKey = root + L"\\Tasks\\" + e.second;
		std::vector<BYTE> data;
		if (getRegBinaryValue(conf.Software, taskKey.c_str(), L"DynamicInfo", data) == ERROR_SUCCESS)
			result.emplace(e.first, decoderDynamicInfo(data.data(), (DWORD)data.size()));
	}
	return result;
}

//! True if the string looks like a SID ("S-1-…").
bool isSid(const std::wstring& v) {
	return v.size() > 2 && (v[0] == L'S' || v[0] == L's') && v[1] == L'-';
}

/*! Fills a task from its XML document. */
void readDefinition(const XmlNode& root, ScheduledTask& t) {
	if (const XmlNode* info = root.child(L"RegistrationInfo")) {
		t.author           = info->textOf(L"Author");
		t.description      = info->textOf(L"Description");
		t.registrationDate = info->textOf(L"Date");
	}

	// Principal: the account it runs as. UserId holds a name OR a SID.
	for (const XmlNode* p : root.descendants(L"Principal")) {
		const std::wstring userId = p->textOf(L"UserId");
		if (userId.empty()) continue;
		if (isSid(userId)) {
			t.runAsSid = userId;
			t.runAs    = getNameFromSid(userId);   // cached resolution
		}
		else t.runAs = userId;
		break;
	}
	if (t.runAs.empty()) t.runAs = root.textOf(L"Principals/Principal/GroupId");

	// Settings\Enabled is "true" by default when the element is absent.
	t.enabled = (root.textOf(L"Settings/Enabled") != L"false");
	t.state   = t.enabled ? L"Enabled" : L"Disabled";

	// Actions: Exec (an executable) or ComHandler (a CLSID).
	for (const XmlNode* a : root.descendants(L"Exec")) {
		Action act;
		act.type       = L"Exec";
		act.command    = a->textOf(L"Command");
		act.arguments  = a->textOf(L"Arguments");
		act.workingDir = a->textOf(L"WorkingDirectory");
		if (conf.binary && !act.command.empty()) {
			/* The path may be quoted and hold variables.
			   It used to be expanded with ExpandEnvironmentStringsW — WAC's
			   environment, and WAC runs as SYSTEM — and its existence tested
			   through the API: two readings of the live machine. The common
			   normalisation expands the system variables from the detected drive.
			   A bare name ("cmd.exe") is looked for where Windows would look
			   first, in System32. An absent executable is not an anomaly here
			   (software uninstalled): Command shows it. */
			const std::wstring command = replaceAll(act.command, L"\"", L"");
			std::wstring path = normalizeFilePath(command);
			if (path.empty() && command.find(L'\\') == std::wstring::npos
			    && command.find(L'%') == std::wstring::npos)
				path = conf.systemDrive + L"\\Windows\\System32\\" + command;
			if (!path.empty()) act.fingerprint = FingerprintFile(path);
		}
		t.actions.push_back(std::move(act));
	}
	for (const XmlNode* a : root.descendants(L"ComHandler")) {
		Action act;
		act.type    = L"ComHandler";
		act.classId = a->textOf(L"ClassId");
		act.data    = a->textOf(L"Data");
		t.actions.push_back(std::move(act));
	}

	// Triggers: each child of <Triggers> carries its type in its name.
	if (const XmlNode* trigs = root.child(L"Triggers")) {
		for (const std::unique_ptr<XmlNode>& n : trigs->children) {
			Trigger tr;
			tr.type     = n->name;                       // TimeTrigger, LogonTrigger…
			tr.start    = n->textOf(L"StartBoundary");
			tr.active    = (n->textOf(L"Enabled") != L"false");
			tr.interval = n->textOf(L"Repetition/Interval");
			t.triggers.push_back(std::move(tr));
		}
	}
}

//! The SCHED_S_TASK_* status of a .job, by name; another one in hexadecimal.
std::wstring jobStatusName(uint32_t status) {
	static const wchar_t* const NAMES[] = { L"Ready", L"Running", L"Disabled", L"HasNotRun", L"NoMoreRuns",
	                                        L"NotScheduled", L"Terminated", L"NoValidTriggers", L"EventTrigger" };
	if (status >= 0x41300 && status < 0x41300 + sizeof(NAMES) / sizeof(NAMES[0])) return NAMES[status - 0x41300];
	return L"0x" + to_hex(status, 8, HexLetters::Upper);
}

//! A counted UTF-16 string of a .job (its count, terminating null included); false past the end.
bool readJobString(const std::vector<uint8_t>& b, size_t& at, std::wstring& text) {
	if (!fits(b.size(), at, 2)) return false;
	const size_t count = readLittleEndian<uint16_t>(b.data() + at);
	at += 2;
	if (!fits(b.size(), at, count * 2)) return false;
	text = readWideZ(b.data(), at + count * 2, at);
	at += count * 2;
	return true;
}

} // namespace

bool parseJobFile(const std::vector<uint8_t>& b, ScheduledTask& task) {
	if (b.size() < JOB_FIXED + 2) return false;
	const uint32_t flags = readLittleEndian<uint32_t>(b.data() + JOB_FLAGS);
	task.enabled = (flags & JOB_DISABLED) == 0;
	task.state = task.enabled ? L"Enabled" : L"Disabled";
	task.jobStatus = jobStatusName(readLittleEndian<uint32_t>(b.data() + JOB_STATUS));
	task.lastTaskResult = (LONG)readLittleEndian<uint32_t>(b.data() + JOB_EXIT_CODE);
	// The last run, a SYSTEMTIME in the machine's local time; all zero when it never ran.
	SYSTEMTIME run = {};
	std::memcpy(&run, b.data() + JOB_RUN_DATE, sizeof run);
	FILETIME local = {};
	if (run.wYear && SystemTimeToFileTime(&run, &local)) task.lastRunTimeUtc = suspectLocalToUtc(local);
	size_t at = JOB_FIXED + 2;   // after the running-instance count
	Action exec;
	exec.type = L"Exec";
	if (!readJobString(b, at, exec.command) || !readJobString(b, at, exec.arguments) || !readJobString(b, at, exec.workingDir)
	    || !readJobString(b, at, task.author) || !readJobString(b, at, task.description)) return false;
	task.actions.push_back(std::move(exec));
	// User data and reserved data, each counted in bytes: skipped.
	for (int block = 0; block < 2; ++block) {
		if (!fits(b.size(), at, 2)) return true;
		at += 2 + readLittleEndian<uint16_t>(b.data() + at);
	}
	if (!fits(b.size(), at, 2)) return true;
	const size_t count = readLittleEndian<uint16_t>(b.data() + at);
	at += 2;
	static const wchar_t* const TYPES[] = { L"TimeTrigger", L"CalendarTrigger", L"CalendarTrigger", L"CalendarTrigger",
	                                        L"CalendarTrigger", L"IdleTrigger", L"BootTrigger", L"LogonTrigger" };
	for (size_t i = 0; i < count && fits(b.size(), at, JOB_TRIGGER); ++i, at += JOB_TRIGGER) {
		const uint8_t* t = b.data() + at;
		Trigger trigger;
		const uint32_t type = readLittleEndian<uint32_t>(t + 32);
		trigger.type = type < sizeof(TYPES) / sizeof(TYPES[0]) ? TYPES[type] : L"0x" + to_hex(type, 8, HexLetters::Upper);
		trigger.active = (readLittleEndian<uint32_t>(t + 28) & JOB_DISABLED) == 0;
		// The start as the XML's StartBoundary writes it: local time, to the minute.
		wchar_t start[32];
		swprintf(start, 32, L"%04u-%02u-%02uT%02u:%02u:00", readLittleEndian<uint16_t>(t + 4), readLittleEndian<uint16_t>(t + 6),
		         readLittleEndian<uint16_t>(t + 8), readLittleEndian<uint16_t>(t + 16), readLittleEndian<uint16_t>(t + 18));
		trigger.start = start;
		task.triggers.push_back(std::move(trigger));
	}
	return true;
}

Json ScheduledTask::toJson() const {
	log(3, L"🔈Scheduled task");
	Json o = Json::obj();
	o.add(L"Name",               Json::str(name));
	o.add(L"Description",        Json::str(description));
	o.add(L"Author",             Json::str(author));
	o.add(L"Enabled",            Json::boolean(enabled));
	o.add(L"RunAs",              Json::str(runAs));
	o.add(L"RunAsSID",           Json::str(runAsSid));
	o.add(L"Path",               Json::str(path));               // RAW path
	o.add(L"State",              Json::str(state));
	o.add(L"LastRun",            Json::str(utcTimeToIso8601Local(lastRunTimeUtc)));
	o.add(L"LastRunUtc",         Json::str(timeToIso8601Utc(lastRunTimeUtc)));
	if (lastTaskResult) o.add(L"LastTaskResult", Json::num((long long)*lastTaskResult));
	o.add(L"RegistrationDate",   Json::str(registrationDate));
	o.add(L"SourceXml",          Json::str(sourceXml));   // traceability of the source
	o.add(L"SourceJob",          Json::str(sourceJob));
	o.add(L"JobStatus",          Json::str(jobStatus));

	Json jsonActions = Json::arr();
	for (const Action& a : actions) {
		Json j = Json::obj();
		j.add(L"Type", Json::str(a.type));
		if (a.type == L"Exec") {
			addFingerprints(j, a.fingerprint);
			j.add(L"Command",          Json::str(a.command));
			j.add(L"Arguments",        Json::str(a.arguments));
			j.add(L"WorkingDirectory", Json::str(a.workingDir));
		}
		else {
			/* "ClassId Name" carried a space, and "data" was the only key in lower
			   case of the whole output: two forms that a query tool handles badly
			   and that do not follow the common naming. */
			j.add(L"ClassId",     Json::str(a.classId));
			j.add(L"ClassIdName", Json::str(trans_guid_to_wstring(a.classId)));
			j.add(L"Data",        Json::str(a.data));
		}
		jsonActions.push(std::move(j));
	}
	o.add(L"Actions", std::move(jsonActions));

	Json jsonTriggers = Json::arr();
	for (const Trigger& t : triggers) {
		Json j = Json::obj();
		j.add(L"Type",     Json::str(t.type));
		j.add(L"Enabled",  Json::boolean(t.active));
		j.add(L"Start",    Json::str(t.start));
		j.add(L"Interval", Json::str(t.interval));
		jsonTriggers.push(std::move(j));
	}
	o.add(L"Triggers", std::move(jsonTriggers));

	return o;
}

void ScheduledTask::clear() {
	log(3, L"🔈Scheduled task clear");
	actions.clear();
	triggers.clear();
}

HRESULT ScheduledTasks::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Scheduled tasks (offline) :");
	log(0, L"*******************************************************************************************************************");

	readJobFiles();
	const std::filesystem::path root = conf.mountpoint + TASKS_SUBFOLDER;
	std::error_code ec;
	if (!std::filesystem::exists(root, ec)) {
		if (!scheduledTasks.empty()) return ERROR_SUCCESS;   // Windows XP: the .job files are the tasks
		log(2, L"🔥Task definitions absent: " + root.wstring(), ERROR_PATH_NOT_FOUND);
		return ERROR_PATH_NOT_FOUND;
	}

	// History first: it is then tied to each task by its path.
	const std::map<std::wstring, History> historical = readTaskCache();

	// The definitions are files WITHOUT an extension, stored in a tree.
	std::vector<std::filesystem::path> files;
	for (std::filesystem::recursive_directory_iterator it(root, ec), end;
	     it != end && !ec; it.increment(ec)) {
		std::error_code fileWriter;
		if (it->is_regular_file(fileWriter) && !fileWriter) files.push_back(it->path());
	}
	log(2, L"❇️" + std::to_wstring(files.size()) + L" task definition(s) found");

	scheduledTasks.reserve(files.size());
	size_t iFile = 0, ignores = 0;
	for (const std::filesystem::path& file : files) {
		printProgressStep(L"ScheduledTask", ++iFile, files.size());

		std::unique_ptr<XmlNode> xmlRoot = xmlReadFile(file.wstring());
		if (!xmlRoot || xmlRoot->name != L"Task") {
			/* A file under Tasks\ that is not a task definition is reported rather
			   than producing an empty entry: the analyst must be able to tell
			   "no task" from "task not decoded". */
			++ignores;
			log(2, L"🔥Definition unreadable or unexpected: " + file.wstring());
			continue;
		}

		ScheduledTask t;
		t.name = file.filename().wstring();
		// Path as the scheduler presents it: relative to Tasks\, backslashes,
		// prefixed by a backslash — it is also the TaskCache's key.
		t.path = L"\\" + std::filesystem::relative(file, root, ec).wstring();
		t.sourceXml = originalPath(file.wstring());
		log(1, L"➕ScheduledTask");
		log(2, L"❇️Task : " + t.path);

		readDefinition(*xmlRoot, t);

		const std::map<std::wstring, History>::const_iterator h =
			historical.find(toLower(t.path));
		if (h != historical.end() && h->second.found) {
			t.lastRunTimeUtc = h->second.lastRunUtc;
			t.lastTaskResult = h->second.lastResult;
		}
		scheduledTasks.push_back(std::move(t));
	}
	if (ignores)
		log(2, L"❇️" + std::to_wstring(ignores) + L" file(s) ignored under Tasks\\");
	return ERROR_SUCCESS;
}

void ScheduledTasks::readJobFiles() {
	for (const std::filesystem::path& file : listFilesByExtension(extractedPath(JOBS_SUBFOLDER), { L".job" })) {
		std::vector<uint8_t> bytes;
		ScheduledTask t;
		t.name = file.stem().wstring();
		t.path = L"\\" + t.name;
		t.sourceJob = originalPath(file.wstring());
		if (!readWholeFile(file, JOB_MAX, bytes) || !parseJobFile(bytes, t)) {
			log(2, L"🔥.job unreadable or cut short: " + t.sourceJob);
			continue;
		}
		log(1, L"➕ScheduledTask");
		scheduledTasks.push_back(std::move(t));
	}
}

HRESULT ScheduledTasks::toJson() {
	log(3, L"🔈ScheduledTasks toJson");
	Json arr = Json::arr();
	for (const ScheduledTask& t : scheduledTasks) arr.push(t.toJson());
	return writeJsonFile("ScheduledTasks.json", arr);
}

void ScheduledTasks::clear() {
	log(3, L"🔈ScheduledTasks clear");
	scheduledTasks.clear();   // destroys the elements -> really releases them
}

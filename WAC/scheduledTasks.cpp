/*! \file
 *  \brief Offline reading of the scheduled tasks (see scheduledTasks.h).
 */
#include "scheduledTasks.h"
#include "xml_light.h"
#include <filesystem>
#include <map>

namespace {

//! Root of the task definitions, relative to the extraction point.
const wchar_t* TASKS_SUBFOLDER = L"\\Windows\\System32\\Tasks";

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
	const ULONGLONG brut = *reinterpret_cast<const ULONGLONG*>(data + 0x0C);
	h.lastRunUtc.dwLowDateTime  = (DWORD)(brut & 0xFFFFFFFFULL);
	h.lastRunUtc.dwHighDateTime = (DWORD)(brut >> 32);
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

	DWORD nSubKeys = 0;
	if (ORQueryInfoKey(key, NULL, NULL, &nSubKeys, NULL, NULL, NULL,
	                   NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		return;

	for (DWORD i = 0; i < nSubKeys; ++i) {
		WCHAR name[MAX_KEY_NAME] = L"";
		DWORD size = MAX_KEY_NAME;
		if (OREnumKey(key, i, name, &size, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
		ORHKEY subKey = NULL;
		if (OROpenKey(key, name, &subKey) != ERROR_SUCCESS) continue;
		walkTree(subKey, path + L"\\" + name, idByPath, depthLeft - 1);
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
		LPBYTE data = NULL;
		DWORD size = 0;
		if (getRegBinaryValue(conf.Software, taskKey.c_str(), L"DynamicInfo",
		                      &data, &size) == ERROR_SUCCESS) {
			result.emplace(e.first, decoderDynamicInfo(data, size));
			delete[] data;
		}
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

} // namespace

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
	o.add(L"LastRun",            Json::str(timeToIso8601Local(lastRunTime)));
	o.add(L"LastRunUtc",         Json::str(timeToIso8601Utc(lastRunTimeUtc)));
	o.add(L"LastTaskResult",     Json::num((long long)lastTaskResult));
	o.add(L"RegistrationDate",   Json::str(registrationDate));
	o.add(L"SourceXml",          Json::str(sourceXml));   // traceability of the source

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

	const std::filesystem::path root = conf.mountpoint + TASKS_SUBFOLDER;
	std::error_code ec;
	if (!std::filesystem::exists(root, ec)) {
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
			t.lastRunTime = utcToSuspectLocal(t.lastRunTimeUtc);
		}
		scheduledTasks.push_back(std::move(t));
	}
	if (ignores)
		log(2, L"❇️" + std::to_wstring(ignores) + L" file(s) ignored under Tasks\\");
	return ERROR_SUCCESS;
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

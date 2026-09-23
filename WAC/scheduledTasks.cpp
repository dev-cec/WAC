/*  scheduledTasks.cpp — voir scheduledTasks.h. */
#include "scheduledTasks.h"
#include "xml_light.h"
#include <filesystem>
#include <map>
#include <sddl.h>

namespace {

//! Racine des définitions de tâches, relative au point d'extraction.
const wchar_t* TASKS_SUBFOLDER = L"\\Windows\\System32\\Tasks";

/*! Historique d'exécution d'une tâche, lu dans TaskCache. */
struct History {
	FILETIME lastRunUtc = { 0 };
	LONG     lastResult = 0;
	bool     found = false;
};

/*! Décode la valeur binaire `DynamicInfo` du TaskCache.
 *
 *  Disposition (stable depuis Vista, longueur variable selon la version) :
 *    0x00 version (4)
 *    0x04 dernière inscription       (FILETIME, 8)
 *    0x0C dernière exécution         (FILETIME, 8)
 *    0x14 code de retour             (4)
 *    0x18 inconnu                    (4)
 *    0x1C dernière exécution réussie (FILETIME, 8) — versions récentes
 *
 *  La taille est vérifiée avant lecture : la valeur vient du registre de la
 *  machine examinée, donc d'une source non fiable.
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

/*! Parcourt `TaskCache\Tree` et relève le GUID de chaque tâche.
 *
 *  L'arbre reproduit l'arborescence des dossiers de tâches : le parcours est donc
 *  récursif, avec un garde-fou de profondeur (un index de registre corrompu
 *  pourrait boucler).
 */
void walkTree(ORHKEY key, const std::wstring& path,
                    std::map<std::wstring, std::wstring>& idByPath,
                    unsigned depthLeft) {
	if (!key || depthLeft == 0) return;

	// Une feuille porte la valeur Id ; une branche porte des sous-clés.
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

/*! Lit le TaskCache : chemin de tâche -> historique d'exécution. */
std::map<std::wstring, History> readTaskCache() {
	std::map<std::wstring, History> result;
	if (!conf.Software) {
		log(2, L"🔥TaskCache : ruche SOFTWARE indisponible, historique non collecte");
		return result;
	}

	const std::wstring root = L"Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
	ORHKEY treeKey = NULL;
	if (OROpenKey(conf.Software, (root + L"\\Tree").c_str(), &treeKey) != ERROR_SUCCESS) {
		log(2, L"🔥TaskCache\\Tree introuvable : historique d'execution non collecte");
		return result;
	}

	std::map<std::wstring, std::wstring> idByPath;
	walkTree(treeKey, L"", idByPath, 16);
	ORCloseKey(treeKey);
	log(2, L"❇️TaskCache : " + std::to_wstring(idByPath.size()) + L" tache(s) referencee(s)");

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

//! Vrai si la chaîne ressemble à un SID (« S-1-… »).
bool estUnSid(const std::wstring& v) {
	return v.size() > 2 && (v[0] == L'S' || v[0] == L's') && v[1] == L'-';
}

/*! Remplit une tâche depuis son document XML. */
void readDefinition(const XmlNode& root, ScheduledTask& t) {
	if (const XmlNode* info = root.child(L"RegistrationInfo")) {
		t.author           = info->textOf(L"Author");
		t.description      = info->textOf(L"Description");
		t.registrationDate = info->textOf(L"Date");
	}

	// Principal : compte d'exécution. UserId contient un nom OU un SID.
	for (const XmlNode* p : root.descendants(L"Principal")) {
		const std::wstring userId = p->textOf(L"UserId");
		if (userId.empty()) continue;
		if (estUnSid(userId)) {
			t.runAsSid = userId;
			t.runAs    = getNameFromSid(userId);   // résolution mise en cache
		}
		else t.runAs = userId;
		break;
	}
	if (t.runAs.empty()) t.runAs = root.textOf(L"Principals/Principal/GroupId");

	// Settings\Enabled vaut « true » par défaut quand l'élément est absent.
	t.enabled = (root.textOf(L"Settings/Enabled") != L"false");
	t.state   = t.enabled ? L"Enabled" : L"Disabled";

	// Actions : Exec (exécutable) ou ComHandler (CLSID).
	for (const XmlNode* a : root.descendants(L"Exec")) {
		Action act;
		act.type       = L"Exec";
		act.command    = a->textOf(L"Command");
		act.arguments  = a->textOf(L"Arguments");
		act.workingDir = a->textOf(L"WorkingDirectory");
		if (conf.binary && !act.command.empty()) {
			/* Le chemin peut être entre guillemets et contenir des variables.
			   Il était développé avec ExpandEnvironmentStringsW — l'environnement
			   de WAC, qui tourne en SYSTEM — et son existence testée par l'API :
			   deux lectures de la machine vivante. La normalisation commune
			   développe les variables système depuis le lecteur détecté.
			   Un nom nu (« cmd.exe ») est cherché comme Windows le ferait en
			   premier, dans System32. Un exécutable absent n'est pas une
			   anomalie ici (logiciel désinstallé) : Command le montre. */
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

	// Déclencheurs : chaque enfant de <Triggers> porte son type dans son nom.
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
	o.add(L"Path",               Json::str(path));               // chemin BRUT
	o.add(L"State",              Json::str(state));
	o.add(L"LastRun",            Json::str(timeToIso8601Local(lastRunTime)));
	o.add(L"LastRunUtc",         Json::str(timeToIso8601Utc(lastRunTimeUtc)));
	o.add(L"LastTaskResult",     Json::num((long long)lastTaskResult));
	o.add(L"RegistrationDate",   Json::str(registrationDate));
	o.add(L"SourceXml",          Json::str(sourceXml));   // traçabilité de la source

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
			/* « ClassId Name » portait une espace, et « data » était la seule clé
			   en minuscules de toute la sortie : deux formes qu'un outil de
			   requête traite mal et qui ne suivent pas le nommage commun. */
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
		log(2, L"🔥Definitions de taches absentes : " + root.wstring(), ERROR_PATH_NOT_FOUND);
		return ERROR_PATH_NOT_FOUND;
	}

	// Historique d'abord : il est rattaché ensuite à chaque tâche par son chemin.
	const std::map<std::wstring, History> historical = readTaskCache();

	// Les définitions sont des fichiers SANS extension, rangés en arborescence.
	std::vector<std::filesystem::path> files;
	for (std::filesystem::recursive_directory_iterator it(root, ec), end;
	     it != end && !ec; it.increment(ec)) {
		std::error_code fileWriter;
		if (it->is_regular_file(fileWriter) && !fileWriter) files.push_back(it->path());
	}
	log(2, L"❇️" + std::to_wstring(files.size()) + L" definition(s) de tache trouvee(s)");

	scheduledTasks.reserve(files.size());
	size_t iFile = 0, ignores = 0;
	for (const std::filesystem::path& file : files) {
		printProgressStep(L"ScheduledTask", ++iFile, files.size());

		std::unique_ptr<XmlNode> xmlRoot = xmlReadFile(file.wstring());
		if (!xmlRoot || xmlRoot->name != L"Task") {
			/* Un fichier sous Tasks\ qui n'est pas une définition de tâche est
			   signalé plutôt que de produire une entrée vide : l'analyste doit
			   pouvoir distinguer « pas de tâche » de « tâche non décodée ». */
			++ignores;
			log(2, L"🔥Definition illisible ou inattendue : " + file.wstring());
			continue;
		}

		ScheduledTask t;
		t.name = file.filename().wstring();
		// Chemin tel que le planificateur le présente : relatif à Tasks\,
		// antislashs, préfixé d'un antislash — c'est aussi la clé du TaskCache.
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
			utcToSuspectLocal(t.lastRunTimeUtc, &t.lastRunTime);
		}
		scheduledTasks.push_back(std::move(t));
	}
	if (ignores)
		log(2, L"❇️" + std::to_wstring(ignores) + L" fichier(s) ignore(s) sous Tasks\\");
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
	scheduledTasks.clear();   // detruit les elements -> libere reellement
}

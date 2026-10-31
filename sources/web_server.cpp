/*! \file
 *  \brief The web server of the examined machine: IIS (see web_server.h).
 */
#include "web_server.h"
#include "registry_common.h"
#include "xml_light.h"
#include <algorithm>
#include <filesystem>
#include <set>

namespace {

//! applicationHost.config, from the system volume's root.
const wchar_t* IIS_CONFIGURATION = L"\\Windows\\System32\\inetsrv\\config\\applicationHost.config";
//! IIS's defaults, where the configuration names none.
const wchar_t* DEFAULT_LOG_ROOT = L"%SystemDrive%\\inetpub\\logs\\LogFiles";
const wchar_t* DEFAULT_HISTORY = L"%SystemDrive%\\inetpub\\history";
//! HTTP.sys's own logs: the requests refused before a site saw them.
const wchar_t* HTTPERR_FOLDER = L"\\Windows\\System32\\LogFiles\\HTTPERR";

//! Largest configuration read: a few hundred kilobytes in practice.
const uintmax_t CONFIGURATION_MAX = 64ULL * 1024 * 1024;
//! Largest log read at once: IIS starts a new file each day; a larger one stays raw in the store.
const uintmax_t LOG_MAX = 512ULL * 1024 * 1024;
//! Deepest log file under a log folder: W3SVC<id>\u_ex<date>.log is at 2.
const int LOG_DEPTH = 3;

//! The JSON key of each field IIS and HTTP.sys write; another keeps its name, in PascalCase.
const std::vector<W3cFieldKey> FIELD_KEYS = {
	{ L"s-sitename", L"SiteName" }, { L"s-computername", L"ComputerName" }, { L"s-ip", L"ServerAddress" },
	{ L"cs-method", L"Method" }, { L"cs-uri-stem", L"UriStem" }, { L"cs-uri-query", L"UriQuery" },
	{ L"s-port", L"ServerPort" }, { L"cs-username", L"UserName" }, { L"c-ip", L"ClientAddress" },
	{ L"c-port", L"ClientPort" }, { L"cs-version", L"ProtocolVersion" }, { L"cs(User-Agent)", L"UserAgent" },
	{ L"cs(Cookie)", L"Cookie" }, { L"cs(Referer)", L"Referer" }, { L"cs-host", L"Host" },
	{ L"sc-status", L"Status" }, { L"sc-substatus", L"SubStatus" }, { L"sc-win32-status", L"Win32Status" },
	{ L"sc-bytes", L"BytesSent" }, { L"cs-bytes", L"BytesReceived" }, { L"time-taken", L"TimeTakenMs" },
	{ L"cs-uri", L"Uri" }, { L"streamid", L"StreamId" }, { L"s-siteid", L"SiteId" },
	{ L"s-reason", L"Reason" }, { L"s-queuename", L"QueueName" } };

//! The attributes of an element, by their JSON key; an empty value left out.
IisElement element(const XmlNode* node) {
	IisElement e;
	if (!node) return e;
	for (const auto& [name, value] : node->attributes)
		if (!value.empty()) e.attributes.emplace_back(registryNameToJsonKey(name), value);
	return e;
}

//! The attributes as a JSON object.
Json attributesJson(const IisElement& e) {
	Json o = Json::obj();
	for (const auto& [key, value] : e.attributes) o.add(key, Json::str(value));
	return o;
}

//! The children of a node that carry a name.
std::vector<const XmlNode*> children(const XmlNode* node, const wchar_t* name) {
	std::vector<const XmlNode*> out;
	if (node)
		for (const std::unique_ptr<XmlNode>& c : node->children) if (c->name == name) out.push_back(c.get());
	return out;
}

//! A node reached by a path of child names; nullptr if one is missing.
const XmlNode* descend(const XmlNode* node, std::initializer_list<const wchar_t*> path) {
	for (const wchar_t* name : path) node = node ? node->child(name) : nullptr;
	return node;
}

//! A folder of the configuration, as a local path; empty if it names none (a share, an unknown variable).
std::wstring folder(const std::wstring& written) {
	std::wstring path = normalizeFilePath(written);
	while (!path.empty() && path.back() == L'\\') path.pop_back();
	return path;
}

//! Adds a folder once, case ignored.
void addOnce(std::vector<std::wstring>& list, std::set<std::wstring>& seen, const std::wstring& path) {
	if (!path.empty() && seen.insert(toLower(path)).second) list.push_back(path);
}

} // namespace

std::wstring IisElement::attribute(const std::wstring& key) const {
	for (const auto& [k, v] : attributes) if (k == key) return v;
	return L"";
}

IisConfiguration parseIisConfiguration(const std::wstring& xml, const std::wstring& file) {
	IisConfiguration c;
	const std::unique_ptr<XmlNode> root = xmlParse(xml);
	if (!root || root->name != L"configuration") return c;
	const XmlNode* host = root->child(L"system.applicationHost");
	const XmlNode* sites = descend(host, { L"sites" });
	const std::wstring defaultLog = descend(sites, { L"siteDefaults", L"logFile" })
	                                ? descend(sites, { L"siteDefaults", L"logFile" })->attribute(L"directory") : L"";
	c.logRoot = folder(defaultLog.empty() ? DEFAULT_LOG_ROOT : defaultLog);
	const XmlNode* history = descend(host, { L"configHistory" });
	const std::wstring historyPath = history ? history->attribute(L"path") : L"";
	c.historyFolder = folder(historyPath.empty() ? DEFAULT_HISTORY : historyPath);
	for (const XmlNode* s : children(sites, L"site")) {
		IisSite site;
		site.site = element(s);
		site.file = file;
		for (const XmlNode* b : children(s->child(L"bindings"), L"binding")) site.bindings.push_back(element(b));
		for (const XmlNode* a : children(s, L"application")) {
			std::vector<IisElement> directories;
			for (const XmlNode* v : children(a, L"virtualDirectory")) directories.push_back(element(v));
			site.applications.emplace_back(element(a), std::move(directories));
		}
		site.logFile = element(s->child(L"logFile"));
		const std::wstring directory = site.logFile.attribute(L"Directory");
		const std::wstring logRoot = directory.empty() ? c.logRoot : folder(directory);
		const std::wstring id = site.site.attribute(L"Id");
		if (!logRoot.empty() && !id.empty()) site.logFolder = logRoot + L"\\W3SVC" + id;
		c.sites.push_back(std::move(site));
	}
	for (const XmlNode* p : children(descend(host, { L"applicationPools" }), L"add"))
		c.pools.emplace_back(element(p), element(p->child(L"processModel")));
	for (const XmlNode* m : children(descend(root.get(), { L"system.webServer", L"globalModules" }), L"add"))
		c.modules.push_back(element(m));
	return c;
}

Json IisSite::toJson() const {
	Json o = attributesJson(site);
	Json bindingList = Json::arr();
	for (const IisElement& b : bindings) bindingList.push(attributesJson(b));
	o.add(L"Bindings", std::move(bindingList));
	Json applicationList = Json::arr();
	for (const auto& [application, directories] : applications) {
		Json a = attributesJson(application);
		Json directoryList = Json::arr();
		for (const IisElement& d : directories) {
			Json v = attributesJson(d);
			// The folder as a local path, when IIS wrote it with a variable.
			const std::wstring written = d.attribute(L"PhysicalPath"), resolved = folder(written);
			if (!resolved.empty() && resolved != written) v.add(L"PhysicalPathResolved", Json::str(resolved));
			directoryList.push(std::move(v));
		}
		a.add(L"VirtualDirectories", std::move(directoryList));
		applicationList.push(std::move(a));
	}
	o.add(L"Applications", std::move(applicationList));
	o.add(L"LogFile", attributesJson(logFile));
	o.add(L"LogFolder", Json::str(logFolder));
	o.add(L"File", Json::str(file));
	return o;
}

std::wstring iisConfigurationFile() {
	return conf.systemDrive.substr(0, 2) + IIS_CONFIGURATION;
}

IisConfiguration readIisConfiguration() {
	const std::filesystem::path path = extractedPath(iisConfigurationFile());
	std::error_code ec;
	if (!std::filesystem::is_regular_file(path, ec)) return IisConfiguration{};
	std::string bytes;
	if (!readWholeFile(path, CONFIGURATION_MAX, bytes)) {
		log(2, L"🔥IIS configuration not read (unreadable or larger than 64 MiB): " + path.wstring());
		return IisConfiguration{};
	}
	return parseIisConfiguration(decodeTextFile(bytes), iisConfigurationFile());
}

IisSources iisSources(const IisConfiguration& configuration) {
	IisSources s;
	std::set<std::wstring> seenSites, seenLogs;
	for (const IisSite& site : configuration.sites) {
		for (const auto& [application, directories] : site.applications)
			for (const IisElement& d : directories) {
				const std::wstring path = folder(d.attribute(L"PhysicalPath"));
				// A volume's root is not a site's folder: the whole volume would be copied.
				if (path.size() <= 2) {
					if (!d.attribute(L"PhysicalPath").empty())
						log(2, L"🔈IIS: virtual directory not copied (a volume's root or not local): " + d.attribute(L"PhysicalPath"));
					continue;
				}
				addOnce(s.siteFolders, seenSites, path);
			}
		if (!site.logFolder.empty()) addOnce(s.logFolders, seenLogs, site.logFolder.substr(0, site.logFolder.rfind(L'\\')));
	}
	addOnce(s.logFolders, seenLogs, configuration.logRoot.empty() ? folder(DEFAULT_LOG_ROOT) : configuration.logRoot);
	addOnce(s.logFolders, seenLogs, conf.systemDrive.substr(0, 2) + HTTPERR_FOLDER);
	s.historyFolder = configuration.historyFolder.empty() ? folder(DEFAULT_HISTORY) : configuration.historyFolder;
	return s;
}

std::vector<W3cLogEntry> parseIisLog(const std::wstring& text, const std::wstring& file) {
	return parseW3cLog(text, file, FIELD_KEYS, W3cTime::Utc);
}

HRESULT WebServer::getData() {
	configuration_ = readIisConfiguration();
	log(2, L"❇️IIS: " + std::to_wstring(configuration_.sites.size()) + L" site(s), "
	       + std::to_wstring(configuration_.pools.size()) + L" pool(s), "
	       + std::to_wstring(configuration_.modules.size()) + L" global module(s)");
	return ERROR_SUCCESS;
}

HRESULT WebServer::toJson() {
	HRESULT result = writeList("web_server_sites.json", configuration_.sites);
	Json pools = Json::arr();
	for (const auto& [pool, processModel] : configuration_.pools) {
		Json p = attributesJson(pool);
		p.add(L"ProcessModel", attributesJson(processModel));
		pools.push(std::move(p));
	}
	if (writeJsonFile("web_server_application_pools.json", pools) != ERROR_SUCCESS) result = E_FAIL;
	Json modules = Json::arr();
	for (const IisElement& m : configuration_.modules) modules.push(attributesJson(m));
	if (writeJsonFile("web_server_modules.json", modules) != ERROR_SUCCESS) result = E_FAIL;

	/* The logs, one file at a time and one line at a time: a busy server
	   keeps millions of requests, which are written and forgotten. */
	JsonArrayWriter out("web_server_logs.json");
	for (const std::wstring& logFolder : iisSources(configuration_).logFolders) {
		const std::filesystem::path copy = extractedPath(logFolder);
		std::error_code ec;
		if (!std::filesystem::is_directory(copy, ec)) continue;
		std::vector<std::filesystem::path> files;
		for (std::filesystem::recursive_directory_iterator it(copy, ec), end; !ec && it != end; it.increment(ec)) {
			if (it.depth() >= LOG_DEPTH) it.disable_recursion_pending();
			if (it->is_regular_file(ec) && toLower(it->path().extension().wstring()) == L".log") files.push_back(it->path());
		}
		std::sort(files.begin(), files.end());
		for (const std::filesystem::path& f : files) {
			const std::wstring examined = logFolder + L"\\" + std::filesystem::relative(f, copy, ec).wstring();
			std::string bytes;
			if (!readWholeFile(f, LOG_MAX, bytes)) {
				log(2, L"🔥IIS log not converted (unreadable or larger than 512 MiB, kept raw): " + examined);
				continue;
			}
			const std::vector<W3cLogEntry> lines = parseIisLog(decodeTextFile(bytes), examined);
			for (const W3cLogEntry& e : lines) out.add(e.toJson());
			log(2, L"❇️" + examined + L" : " + std::to_wstring(lines.size()) + L" line(s)");
		}
	}
	if (out.close() != ERROR_SUCCESS) result = E_FAIL;
	return result;
}

void WebServer::clear() { configuration_ = IisConfiguration{}; }

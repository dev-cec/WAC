/*! \file
 *  \brief The web server of the examined machine: IIS (see web_server.h).
 */
#include "web_server.h"
#include "web_installations.h"
#include "registry_common.h"
#include "sqlite_reader.h"
#include "xml_light.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
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
//! Deepest file looked for in a site's folder: the depth its tree is copied to.
const int SITE_DEPTH = 32;
//! Largest web.config read: a few kilobytes in practice.
const uintmax_t WEB_CONFIG_MAX = 16ULL * 1024 * 1024;
//! Rows read of one account table: far above a real site's users, a bound on a forged one.
const size_t ACCOUNT_ROWS_MAX = 1000000;
//! A BLOB value of an account row up to this size is given in hexadecimal; a larger one by its size.
const size_t ACCOUNT_BLOB_MAX = 1024;

//! The extensions of the database files a connection string can name.
const std::vector<std::wstring> DATABASE_EXTENSIONS = {
	L".db", L".db3", L".sqlite", L".sqlite3", L".mdb", L".accdb", L".mdf", L".sdf" };
//! Among them, SQLite's: the ones WAC reads.
const std::vector<std::wstring> SQLITE_EXTENSIONS = { L".db", L".db3", L".sqlite", L".sqlite3" };
//! The first 16 bytes of every SQLite database, its terminating zero included.
const char SQLITE_HEADER[] = "SQLite format 3";

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

/*! The files under a folder of the working copy, sorted, to a depth.
 *  @param keep says which file, by its path, is wanted */
std::vector<std::filesystem::path> filesUnder(const std::filesystem::path& root, int depth,
                                              const std::function<bool(const std::filesystem::path&)>& keep) {
	std::vector<std::filesystem::path> files;
	std::error_code ec;
	if (!std::filesystem::is_directory(root, ec)) return files;
	for (std::filesystem::recursive_directory_iterator it(root, ec), end; !ec && it != end; it.increment(ec)) {
		if (it.depth() >= depth) it.disable_recursion_pending();
		if (it->is_regular_file(ec) && keep(it->path())) files.push_back(it->path());
	}
	std::sort(files.begin(), files.end());
	return files;
}

//! Whether a path ends with one of the extensions, case ignored.
bool hasExtension(const std::wstring& path, const std::vector<std::wstring>& extensions) {
	const std::wstring extension = toLower(std::filesystem::path(path).extension().wstring());
	return std::find(extensions.begin(), extensions.end(), extension) != extensions.end();
}

/*! The keys and values of a connection string, keys lower case with their
 *  spaces removed ("Data Source" → "datasource"); a value may be quoted. */
std::vector<std::pair<std::wstring, std::wstring>> connectionKeys(const std::wstring& text) {
	std::vector<std::pair<std::wstring, std::wstring>> keys;
	size_t i = 0;
	while (i < text.size()) {
		const size_t equal = text.find(L'=', i);
		if (equal == std::wstring::npos) break;
		std::wstring key;
		for (size_t k = i; k < equal; ++k) if (text[k] != L' ' && text[k] != L';') key += (wchar_t)towlower(text[k]);
		size_t v = equal + 1;
		while (v < text.size() && text[v] == L' ') ++v;
		std::wstring value;
		if (v < text.size() && (text[v] == L'"' || text[v] == L'\'')) {
			const size_t close = text.find(text[v], v + 1);
			value = text.substr(v + 1, (close == std::wstring::npos ? text.size() : close) - v - 1);
			i = close == std::wstring::npos ? text.size() : close + 1;
			i = text.find(L';', i) == std::wstring::npos ? text.size() : text.find(L';', i) + 1;
		}
		else {
			const size_t end = text.find(L';', v);
			value = text.substr(v, (end == std::wstring::npos ? text.size() : end) - v);
			while (!value.empty() && value.back() == L' ') value.pop_back();
			i = end == std::wstring::npos ? text.size() : end + 1;
		}
		if (!key.empty()) keys.emplace_back(key, value);
	}
	return keys;
}

//! A text value of an account row as JSON: a number stays a number.
Json columnValue(const SqliteRow& row, int column) {
	switch (row.type(column)) {
	case SqliteType::Integer: return Json::num((long long)row.integer(column));
	case SqliteType::Real: return Json::real(row.real(column));
	case SqliteType::Blob: {
		const std::vector<uint8_t> bytes = row.blob(column);
		if (bytes.size() > ACCOUNT_BLOB_MAX) return Json::str(L"<" + std::to_wstring(bytes.size()) + L" bytes>");
		return Json::str(toHexadecimal(bytes.data(), bytes.size()));
	}
	default: return Json::str(row.text(column));
	}
}

//! Whether a table's name says it holds the application's accounts.
bool accountTableName(const std::wstring& table) {
	const std::wstring t = toLower(table);
	for (const wchar_t* end : { L"users", L"user", L"accounts", L"account", L"members", L"member", L"logins", L"login" })
		if (t.size() >= wcslen(end) && t.compare(t.size() - wcslen(end), wcslen(end), end) == 0) return true;
	return false;
}

//! Whether a column's name says it holds a password or its hash.
bool passwordColumn(const std::wstring& column) {
	const std::wstring c = toLower(column);
	return c.find(L"pass") != std::wstring::npos || c.find(L"hash") != std::wstring::npos
	       || c.find(L"pwd") != std::wstring::npos;
}

//! The subfolders of a folder in the working copy.
std::vector<std::wstring> workingSubfolders(const std::wstring& folder) {
	std::vector<std::wstring> names;
	std::error_code ec;
	const std::filesystem::path copy = extractedPath(folder);
	if (!std::filesystem::is_directory(copy, ec)) return names;
	for (std::filesystem::directory_iterator it(copy, ec), end; !ec && it != end; it.increment(ec))
		if (it->is_directory(ec)) names.push_back(it->path().filename().wstring());
	return names;
}

/*! The lines of logs in the working copy, as JSON, one file at a time.
 *  @param files their paths on the examined machine
 *  @param parse reads a line: its text, its file, its number
 *  @param out where they go */
void writeTextLogs(const std::vector<std::wstring>& files,
                   W3cLogEntry (*parse)(const std::wstring&, const std::wstring&, unsigned long long),
                   JsonArrayWriter& out) {
	for (const std::wstring& file : files) {
		std::string bytes;
		if (!readWholeFile(extractedPath(file), LOG_MAX, bytes)) {
			log(2, L"🔥Web server log not converted (unreadable or larger than 512 MiB, kept raw): " + file);
			continue;
		}
		const std::vector<std::wstring> lines = splitLines(decodeTextFile(bytes));
		for (size_t i = 0; i < lines.size(); ++i) {
			std::wstring line = lines[i];
			if (!line.empty() && line.back() == L'\r') line.pop_back();
			if (!line.empty()) out.add(parse(line, file, i + 1).toJson());
		}
		log(2, L"❇️" + file + L" : " + std::to_wstring(lines.size()) + L" line(s)");
	}
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

std::wstring connectionDatabaseFile(const std::wstring& connectionString, const std::wstring& siteFolder) {
	for (const auto& [key, written] : connectionKeys(connectionString)) {
		if (key != L"datasource" && key != L"attachdbfilename" && key != L"dbq" && key != L"filename") continue;
		std::wstring value = written;
		/* |DataDirectory| is the application's App_Data (ASP.NET's own
		   substitution); the site's folder stands for the application's. */
		const std::wstring marker = L"|datadirectory|";
		const size_t at = toLower(value).find(marker);
		if (at != std::wstring::npos) {
			std::wstring rest = value.substr(at + marker.size());
			if (!rest.empty() && rest[0] != L'\\') rest = L"\\" + rest;
			value = siteFolder + L"\\App_Data" + rest;
		}
		// A file on a local volume only: a server's name, a share, a relative path name no file here.
		if (value.size() < 4 || value[1] != L':' || value[2] != L'\\' || !hasExtension(value, DATABASE_EXTENSIONS)) continue;
		return normalizeFilePath(value);
	}
	return L"";
}

std::vector<IisConnectionString> parseConnectionStrings(const std::wstring& xml, const std::wstring& file,
                                                        const std::wstring& siteFolder) {
	std::vector<IisConnectionString> out;
	const std::unique_ptr<XmlNode> root = xmlParse(xml);
	if (!root || root->name != L"configuration") return out;
	const XmlNode* section = root->child(L"connectionStrings");
	if (!section) return out;
	/* An encrypted section (aspnet_regiis -pe) holds only its EncryptedData,
	   which the machine's key decrypts: said, by its provider, not decoded. */
	const std::wstring provider = section->attribute(L"configProtectionProvider");
	if (!provider.empty()) {
		IisConnectionString c;
		c.protectedBy = provider;
		c.file = file;
		out.push_back(std::move(c));
		return out;
	}
	for (const XmlNode* a : children(section, L"add")) {
		IisConnectionString c;
		c.name = a->attribute(L"name");
		c.connectionString = a->attribute(L"connectionString");
		c.providerName = a->attribute(L"providerName");
		c.databaseFile = connectionDatabaseFile(c.connectionString, siteFolder);
		c.file = file;
		out.push_back(std::move(c));
	}
	return out;
}

Json IisConnectionString::toJson() const {
	Json o = Json::obj();
	o.add(L"Name", Json::str(name));
	o.add(L"ConnectionString", Json::str(connectionString));
	o.add(L"ProviderName", Json::str(providerName));
	o.add(L"DatabaseFile", Json::str(databaseFile));
	o.add(L"ProtectedBy", Json::str(protectedBy));
	o.add(L"File", Json::str(file));
	return o;
}

std::vector<IisConnectionString> readConnectionStrings(const std::vector<std::wstring>& siteFolders) {
	/* Each web.config once, with the deepest site's folder that holds it: a
	   nested application is a site's folder of its own, its App_Data its own. */
	std::vector<std::pair<std::wstring, std::wstring>> found;   // web.config, site's folder
	for (const std::wstring& site : siteFolders) {
		const std::filesystem::path copy = extractedPath(site);
		std::error_code ec;
		for (const std::filesystem::path& f : filesUnder(copy, SITE_DEPTH, [](const std::filesystem::path& p) {
			     return toLower(p.filename().wstring()) == L"web.config"; })) {
			const std::wstring examined = site + L"\\" + std::filesystem::relative(f, copy, ec).wstring();
			auto known = std::find_if(found.begin(), found.end(), [&](const auto& e) { return toLower(e.first) == toLower(examined); });
			if (known == found.end()) found.emplace_back(examined, site);
			else if (site.size() > known->second.size()) known->second = site;
		}
	}
	std::vector<IisConnectionString> out;
	for (const auto& [file, site] : found) {
		std::string bytes;
		if (!readWholeFile(extractedPath(file), WEB_CONFIG_MAX, bytes)) {
			log(2, L"🔥web.config not read (unreadable or larger than 16 MiB): " + file);
			continue;
		}
		for (IisConnectionString& c : parseConnectionStrings(decodeTextFile(bytes), file, site)) out.push_back(std::move(c));
	}
	return out;
}

std::vector<std::wstring> externalDatabases(const std::vector<IisConnectionString>& connections,
                                            const std::vector<std::wstring>& siteFolders) {
	std::vector<std::wstring> files;
	std::set<std::wstring> seen;
	for (const IisConnectionString& c : connections) {
		if (c.databaseFile.empty()) continue;
		const bool inSite = std::any_of(siteFolders.begin(), siteFolders.end(),
		                                [&](const std::wstring& site) { return folderHolds(site, c.databaseFile); });
		if (!inSite) addOnce(files, seen, c.databaseFile);
	}
	return files;
}

std::wstring passwordHashFormat(const std::wstring& value) {
	/* By the prefix the scheme writes itself, then, for a bare digest, by its
	   length in hexadecimal: a length says the size, not the algorithm, and
	   is named so. Anything else is left unnamed — never guessed. */
	const std::pair<const wchar_t*, const wchar_t*> PREFIXES[] = {
		{ L"$wp$2", L"bcrypt (WordPress 6.8)" }, { L"$2a$", L"bcrypt" }, { L"$2b$", L"bcrypt" }, { L"$2y$", L"bcrypt" },
		{ L"$P$", L"phpass" }, { L"$H$", L"phpass" }, { L"$argon2id$", L"argon2id" }, { L"$argon2i$", L"argon2i" },
		{ L"$1$", L"md5crypt" }, { L"$5$", L"sha256crypt" }, { L"$6$", L"sha512crypt" },
		{ L"pbkdf2_sha256$", L"PBKDF2-SHA256 (Django)" }, { L"pbkdf2_sha1$", L"PBKDF2-SHA1 (Django)" },
		{ L"AQAAAA", L"PBKDF2 (ASP.NET Core Identity v3)" } };
	for (const auto& [prefix, name] : PREFIXES)
		if (value.compare(0, wcslen(prefix), prefix) == 0) return name;
	if (!value.empty() && value.find_first_not_of(L"0123456789abcdefABCDEF") == std::wstring::npos) {
		switch (value.size()) {
		case 32: return L"unsalted 128-bit digest (MD5?)";
		case 40: return L"unsalted 160-bit digest (SHA-1?)";
		case 64: return L"unsalted 256-bit digest (SHA-256?)";
		case 128: return L"unsalted 512-bit digest (SHA-512?)";
		default: break;
		}
	}
	return L"";
}

std::vector<Json> readApplicationAccounts(const std::wstring& workingFile, const std::wstring& examinedFile) {
	std::vector<Json> rows;
	// A file that is no SQLite database (a Thumbs.db, an Access base) is left quietly.
	std::ifstream in(std::filesystem::path(workingFile), std::ios::binary);
	char header[sizeof SQLITE_HEADER] = {};
	if (!in.read(header, sizeof header) || std::memcmp(header, SQLITE_HEADER, sizeof header) != 0) return rows;
	in.close();
	SqliteDatabase db;
	if (db.open(workingFile) != ERROR_SUCCESS) return rows;
	std::vector<std::wstring> tables;
	if (db.query("SELECT name FROM sqlite_master WHERE type = 'table'", [&](const SqliteRow& r) { tables.push_back(r.text(0)); }) != ERROR_SUCCESS) {
		log(2, L"🔥" + examinedFile + L": tables not listed");
		return rows;
	}
	for (const std::wstring& table : tables) {
		if (!accountTableName(table)) continue;
		size_t read = 0;
		const HRESULT hr = db.queryTable(table, [&](const SqliteRow& r) {
			if (++read > ACCOUNT_ROWS_MAX) return;
			// The columns as values, never as keys: their names come from the database.
			Json fields = Json::arr();
			std::wstring hashColumn, hash;
			for (int c = 0; c < r.columnCount(); ++c) {
				if (r.isNull(c) || (r.type(c) == SqliteType::Text && r.text(c).empty())) continue;
				if (hashColumn.empty() && passwordColumn(r.name(c)) && r.type(c) == SqliteType::Text) {
					hashColumn = r.name(c);
					hash = r.text(c);
					continue;
				}
				Json field = Json::obj();
				field.add(L"Column", Json::str(r.name(c)));
				field.add(L"Value", columnValue(r, c));
				fields.push(std::move(field));
			}
			// A table named like accounts without a password column is another table (a user's settings).
			if (hashColumn.empty()) return;
			Json o = Json::obj();
			o.add(L"Table", Json::str(table));
			o.add(L"PasswordColumn", Json::str(hashColumn));
			o.add(L"PasswordHash", Json::str(hash));
			o.add(L"HashFormat", Json::str(passwordHashFormat(hash)));
			o.add(L"Fields", std::move(fields));
			o.add(L"Database", Json::str(examinedFile));
			rows.push_back(std::move(o));
		});
		if (read > ACCOUNT_ROWS_MAX)
			log(2, L"🔥" + examinedFile + L": table " + table + L" read up to " + std::to_wstring(ACCOUNT_ROWS_MAX) + L" rows");
		if (hr != ERROR_SUCCESS) log(2, L"🔥" + examinedFile + L": table " + table + L" not read");
	}
	return rows;
}

HRESULT WebServer::getData() {
	configuration_ = readIisConfiguration();
	const IisSources sources = iisSources(configuration_);
	connections_ = readConnectionStrings(sources.siteFolders);
	std::vector<std::wstring> folders = sources.siteFolders;
	for (const WebCandidate& candidate : webCandidates(examinedServices(), workingSubfolders, conf.systemDrive.substr(0, 2))) {
		WebInstallation installation = readWebInstallation(candidate);
		if (installation.hosts.empty()) continue;   // the folder of its name holds no server
		for (const WebHost& h : installation.hosts)
			for (const std::wstring& root : h.documentRoots) folders.push_back(root);
		installations_.push_back(std::move(installation));
	}
	engines_ = readDatabaseEngines();
	/* The accounts of every SQLite database of the sites — copied with
	   their folders — and of those their web.config name elsewhere. */
	std::vector<std::wstring> databases;
	std::set<std::wstring> seenDatabases;
	for (const std::wstring& site : folders) {
		const std::filesystem::path copy = extractedPath(site);
		std::error_code ec;
		for (const std::filesystem::path& f : filesUnder(copy, SITE_DEPTH, [](const std::filesystem::path& p) {
			     return hasExtension(p.wstring(), SQLITE_EXTENSIONS); })) {
			const std::wstring file = site + L"\\" + std::filesystem::relative(f, copy, ec).wstring();
			if (seenDatabases.insert(toLower(file)).second) databases.push_back(file);
		}
	}
	for (const std::wstring& file : externalDatabases(connections_, sources.siteFolders))
		if (hasExtension(file, SQLITE_EXTENSIONS)) databases.push_back(file);
	for (const std::wstring& file : databases)
		for (Json& row : readApplicationAccounts(extractedPath(file), file)) accounts_.push_back(std::move(row));
	log(2, L"❇️IIS: " + std::to_wstring(configuration_.sites.size()) + L" site(s), "
	       + std::to_wstring(configuration_.pools.size()) + L" pool(s), "
	       + std::to_wstring(configuration_.modules.size()) + L" global module(s), "
	       + std::to_wstring(connections_.size()) + L" connection string(s), "
	       + std::to_wstring(accounts_.size()) + L" application account(s), "
	       + std::to_wstring(installations_.size()) + L" other web server(s), "
	       + std::to_wstring(engines_.size()) + L" database engine(s)");
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
	if (writeList("web_server_connection_strings.json", connections_) != ERROR_SUCCESS) result = E_FAIL;
	Json accounts = Json::arr();
	for (const Json& row : accounts_) accounts.push(row);
	if (writeJsonFile("web_server_accounts.json", accounts) != ERROR_SUCCESS) result = E_FAIL;
	if (writeList("web_server_installations.json", installations_) != ERROR_SUCCESS) result = E_FAIL;
	if (writeList("web_server_database_engines.json", engines_) != ERROR_SUCCESS) result = E_FAIL;

	/* The logs, one file at a time and one line at a time: a busy server
	   keeps millions of requests, which are written and forgotten. */
	JsonArrayWriter out("web_server_logs.json");
	for (const std::wstring& logFolder : iisSources(configuration_).logFolders) {
		const std::filesystem::path copy = extractedPath(logFolder);
		std::error_code ec;
		for (const std::filesystem::path& f : filesUnder(copy, LOG_DEPTH, [](const std::filesystem::path& p) {
			     return toLower(p.extension().wstring()) == L".log"; })) {
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
	JsonArrayWriter errors("web_server_error_logs.json");
	for (const WebInstallation& installation : installations_) {
		std::vector<std::wstring> access, failures;
		for (const WebHost& h : installation.hosts) {
			access.insert(access.end(), h.accessLogs.begin(), h.accessLogs.end());
			failures.insert(failures.end(), h.errorLogs.begin(), h.errorLogs.end());
		}
		writeTextLogs(rotatedLogs(access), parseAccessLogLine, out);
		writeTextLogs(rotatedLogs(failures), parseErrorLogLine, errors);
	}
	if (out.close() != ERROR_SUCCESS || errors.close() != ERROR_SUCCESS) result = E_FAIL;
	return result;
}

void WebServer::clear() {
	configuration_ = IisConfiguration{};
	installations_.clear();
	engines_.clear();
	connections_.clear();
	accounts_.clear();
}

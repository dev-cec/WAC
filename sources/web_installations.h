/*! \file
 *  \brief The web servers other than IIS, and the database engines of the
 *  examined machine (backlog B-035, lot 3): Apache, nginx, MySQL and MariaDB,
 *  PostgreSQL.
 *
 *  FOUND WITHOUT RUNNING ANYTHING. Nothing registers these products in a
 *  place of their own. A service says where its binary is
 *  (`Services\<name>\ImagePath`, or `Parameters\Application` for one wrapped
 *  by NSSM); a server started by hand has none, and is looked for by the
 *  folder its archive unpacks to: `\Apache24`, `\nginx-1.28.0`, `\xampp\apache`,
 *  `\Program Files\Apache Software Foundation\Apache2.4`.
 *
 *  THE CONFIGURATION says what runs and from where: Apache's httpd.conf with
 *  its Include and IncludeOptional (`Define`d variables expanded), nginx's
 *  nginx.conf with its include. Read as written, a conditional section
 *  (<IfModule>, <IfDefine>) included: what it holds is on the disk, whether
 *  or not the condition held. An include is followed to 16 levels, each file
 *  once, in what the collection copied: one outside it is said, not read.
 *
 *  THE LOGS. Access logs in the common and combined formats, the default of
 *  both products, whose date carries its offset: converted to UTC exactly.
 *  Error logs in the three layouts met — Apache 2.2, Apache 2.4, nginx — whose
 *  date is local without offset. A line in another format is given raw, never
 *  dropped. Apache 2.4's own ErrorLogFormat can make any layout: raw too.
 *
 *  THE DATABASE ENGINES are taken raw, not decoded: the data folder whole up
 *  to max_database_mib of wac.yml; above, its configuration and logs alone,
 *  and said (raw_collect). Their files are read through the volume, a running
 *  engine locks nothing that way. The binary is `mariadbd.exe` or `mysqld.exe`
 *  (MariaDB 10.5 renamed it, and keeps both); PostgreSQL's service names its
 *  folder (`pg_ctl runservice -D`), MySQL's its option file, whose `datadir`
 *  says the rest. Logs and write-ahead files lie in the data folder, whatever
 *  their name (pg_log or log, pg_xlog or pg_wal, before and since version 10).
 *
 *  OUTPUT. web_server_installations.json, web_server_database_engines.json,
 *  web_server_error_logs.json; the access logs join web_server_logs.json.
 */
#pragma once

#include <functional>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "w3c_log.h"

/*! A service's command, as the registry keeps it. */
struct WebServiceEntry {
	std::wstring name;         //!< the service's key
	std::wstring imagePath;    //!< its ImagePath
	std::wstring application;  //!< its Parameters\Application, for a service NSSM wraps; empty otherwise
};

/*! Where a web server may be installed. */
struct WebCandidate {
	std::wstring product;      //!< "Apache" or "nginx"
	std::wstring root;         //!< the folder its relative paths start from
	std::wstring configFile;   //!< its main configuration, absolute
	std::wstring source;       //!< what named it: "service <name>", or "folder"
};

/*! A database engine a service names. */
struct DatabaseEngine {
	std::wstring product;      //!< "MySQL or MariaDB", or "PostgreSQL"
	std::wstring service;      //!< the service
	std::wstring binary;       //!< its binary, absolute
	std::wstring configFile;   //!< MySQL's option file; PostgreSQL's postgresql.conf; empty if none is named
	std::wstring dataFolder;   //!< its data folder, absolute; empty until read, for MySQL
	bool copied = false;       //!< the data folder is in the collection
	Json toJson() const;       //!< @return the engine as a JSON object
};

/*! A virtual host, or the server's main one. */
struct WebHost {
	std::vector<std::wstring> serverNames;
	std::vector<std::wstring> listen;
	std::vector<std::wstring> documentRoots;  //!< DocumentRoot, Alias, ScriptAlias; root, alias: absolute
	std::vector<std::wstring> accessLogs;     //!< absolute; a pipe or syslog left out
	std::vector<std::wstring> errorLogs;      //!< absolute; a pipe or syslog left out
	std::wstring file;                        //!< the configuration file it starts in
	Json toJson() const;                      //!< @return the host as a JSON object
};

/*! What a web server's configuration holds. */
struct WebInstallation {
	std::wstring product;      //!< as its candidate
	std::wstring source;       //!< as its candidate
	std::wstring root;         //!< ServerRoot as read, or the candidate's
	std::wstring configFile;   //!< as its candidate
	std::vector<std::pair<std::wstring, std::wstring>> modules;  //!< the modules loaded (LoadModule, load_module): name, file
	std::vector<WebHost> hosts;  //!< the main one first
	std::vector<std::wstring> notRead;  //!< the includes named and not in the collection
	Json toJson() const;       //!< @return the installation as a JSON object
};

/*! How a parser reaches the files of a configuration: the working copy in
 *  WAC, strings in the tests. Paths are those of the examined machine. */
struct WebConfigFiles {
	std::function<bool(const std::wstring& path, std::wstring& text)> read;  //!< @return false if not there
	std::function<std::vector<std::wstring>(const std::wstring& pattern)> matches;  //!< the files of a folder, or of a wildcard in its last part
};

/*! Lists the folders of a folder: the volume at the collection, the working
 *  copy at the conversion. */
using WebFolderLister = std::function<std::vector<std::wstring>(const std::wstring& folder)>;

/*! Whether a path is a folder or lies under it, case ignored; a folder of a
 *  similar name (`wwwroot2` for `wwwroot`) does not. */
bool folderHolds(const std::wstring& folder, const std::wstring& path);

/*! The words of a service's command: quotes kept out, a backslash literal
 *  (a Windows path), `--name="a b"` one word `--name=a b`.
 *  @param line the command */
std::vector<std::wstring> commandWords(const std::wstring& line);

/*! The web servers services and folders name, each root once.
 *  @param services the machine's services
 *  @param folders lists a folder's subfolders
 *  @param drive the system volume ("C:") */
std::vector<WebCandidate> webCandidates(const std::vector<WebServiceEntry>& services, const WebFolderLister& folders,
                                        const std::wstring& drive);

/*! The database engines the services name. */
std::vector<DatabaseEngine> databaseEngines(const std::vector<WebServiceEntry>& services);

/*! MySQL's data folder, from its option file: `datadir` of [mysqld], [mariadb] or [server].
 *  @param ini the file's text
 *  @return the folder, backslashes, without a final one; empty if not there */
std::wstring mysqlDataFolder(const std::wstring& ini);

/*! Reads Apache's configuration.
 *  @param candidate where it is
 *  @param files how to reach its files
 *  @return what it holds; no host if its main file is not there */
WebInstallation parseApacheConfiguration(const WebCandidate& candidate, const WebConfigFiles& files);

/*! Reads nginx's configuration.
 *  @param candidate where it is
 *  @param files how to reach its files
 *  @return what it holds; no host if its main file is not there */
WebInstallation parseNginxConfiguration(const WebCandidate& candidate, const WebConfigFiles& files);

/*! One line of an access log in the common or combined format.
 *  @return the entry, date in UTC; a line in another format as its Raw field */
W3cLogEntry parseAccessLogLine(const std::wstring& line, const std::wstring& file, unsigned long long number);

/*! One line of an error log: Apache 2.2, Apache 2.4 or nginx.
 *  @return the entry, date in the machine's local time; another line as its Raw field */
W3cLogEntry parseErrorLogLine(const std::wstring& line, const std::wstring& file, unsigned long long number);

/*! The services of the examined machine, from its SYSTEM hive. */
std::vector<WebServiceEntry> examinedServices();

/*! The files of a web server's logs as named by its configuration, and those
 *  rotated beside them (access.log, access.log.1), in the working copy.
 *  @param named the logs the configuration names
 *  @return their paths on the examined machine, each once */
std::vector<std::wstring> rotatedLogs(const std::vector<std::wstring>& named);

/*! The engines the services name, their data folder read in the option file
 *  when the command does not give it, and whether the collection holds it. */
std::vector<DatabaseEngine> readDatabaseEngines();

/*! A web server's configuration read in the working copy. */
WebInstallation readWebInstallation(const WebCandidate& candidate);

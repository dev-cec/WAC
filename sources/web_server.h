/*! \file
 *  \brief The web server of the examined machine: IIS (backlog B-035, lots 1
 *  and 2), and the artefact's whole conversion; Apache, nginx and the database
 *  engines are read in web_installations.h (lot 3).
 *
 *  WHAT THE ARTEFACT PROVES. On a web server, a compromise goes through the
 *  site: a web shell dropped in its folder and the requests that call it, a
 *  native module added to IIS (a backdoor that sees every request, ATT&CK
 *  T1505.004), an application pool switched to a privileged identity. The
 *  configuration says what IIS runs and from where, the logs who asked for
 *  what, the site's folder what was dropped.
 *
 *  WHERE.
 *  - `Windows\System32\inetsrv\config\applicationHost.config` (IIS 7 and
 *    later, Vista and Server 2008 on): the sites, their bindings, their
 *    applications and virtual directories (physical path), the application
 *    pools and their identity, the native modules loaded in every worker
 *    (globalModules), the settings of the logs. Its earlier states are kept
 *    by IIS itself in `inetpub\history\CFGHISTORY_<n>` (configHistory,
 *    every two minutes after a change, ten kept): taken too.
 *  - IIS 5.1 and 6 (XP, Server 2003) keep it in `inetsrv\MetaBase.xml`:
 *    collected raw, not converted — no machine of the test cycle has it.
 *  - The logs: per site, `<directory>\W3SVC<id>\u_ex<date>.log`, the
 *    directory from the site's logFile, else siteDefaults', else
 *    `%SystemDrive%\inetpub\logs\LogFiles`; those of HTTP.sys — requests
 *    refused before any site saw them — in `Windows\System32\LogFiles\
 *    HTTPERR`. Each log folder is taken whole (its .log files), for the
 *    sites removed since.
 *  - The site's content: the folder of each virtual directory, taken whole,
 *    whatever its files (user decision of 2026-09-26: the code, the data,
 *    what an attacker dropped among them).
 *
 *  - The application's databases: a site's web.config names them in its
 *    connection strings (`|DataDirectory|` is its App_Data). One inside a
 *    site's folder comes with it; one elsewhere is taken on its own, with
 *    its -wal and -journal, up to `max_database_mib` of wac.yml — a larger
 *    one is said, not copied (an engine's server, SQL Server or MySQL, is
 *    not a file: lot 3).
 *  - The application's accounts: in each SQLite database, a table whose
 *    name says accounts (users, wp_users, AspNetUsers, members…) and that
 *    has a password column; each row given, its hash with the scheme its
 *    form names (bcrypt, phpass, PBKDF2…), its other columns as
 *    {Column, Value} — a name from the database is never a JSON key.
 *    Judging a weak password is WAE's.
 *
 *  THE LOGS' FORMAT: W3C extended (w3c_log.h), IIS's default; the dates in
 *  UTC — IIS writes W3C in UTC whatever its localTimeRollover, which only
 *  names the files. The other formats (IIS, NCSA, custom) are taken raw,
 *  not converted.
 *
 *  OUTPUT. web_server_sites.json, web_server_application_pools.json,
 *  web_server_modules.json (the configuration, each element's attributes as
 *  IIS stores them — a password of a pool or a virtual directory stays as
 *  IIS encrypted it), web_server_logs.json (one object per request),
 *  web_server_connection_strings.json (each connection string as written:
 *  its password in clear when the site keeps it so; an encrypted section
 *  said by its provider, not decoded), web_server_accounts.json (one object
 *  per account row).
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "w3c_log.h"
#include "web_installations.h"

/*! An element of the configuration: its attributes as written, by their
 *  JSON key, and the elements read beneath it. */
struct IisElement {
	std::vector<std::pair<std::wstring, std::wstring>> attributes; //!< by JSON key ("physicalPath": "PhysicalPath"), in document order
	std::wstring attribute(const std::wstring& key) const;         //!< @return the value of an attribute, by its JSON key; empty if absent
};

/*! A site of applicationHost.config. */
struct IisSite {
	IisElement site;                    //!< name, id, serverAutoStart…
	std::vector<IisElement> bindings;   //!< protocol, bindingInformation
	/*! Its applications, each with its virtual directories. */
	std::vector<std::pair<IisElement, std::vector<IisElement>>> applications;
	IisElement logFile;                 //!< its own log settings, if any
	std::wstring logFolder;             //!< where its W3C logs are: the directory resolved, then W3SVC<id>; empty if unknown
	std::wstring file;                  //!< the configuration it was read in
	Json toJson() const;                //!< @return the site as a JSON object
};

/*! What IIS's configuration holds. */
struct IisConfiguration {
	std::vector<IisSite> sites;
	std::vector<std::pair<IisElement, IisElement>> pools; //!< each pool, with its processModel (identity)
	std::vector<IisElement> modules;                      //!< globalModules: name, image, preCondition
	std::wstring logRoot;                                 //!< the logs' directory of siteDefaults, resolved; the default if none
	std::wstring historyFolder;                           //!< configHistory's path, resolved; the default if none
};

/*! Reads applicationHost.config.
 *  @param xml its text
 *  @param file its path on the examined machine
 *  @return what it holds; empty if it is not IIS's configuration */
IisConfiguration parseIisConfiguration(const std::wstring& xml, const std::wstring& file);

/*! applicationHost.config on the examined machine, absolute. */
std::wstring iisConfigurationFile();

/*! The configuration as the collection copied it, read from the working
 *  copy; empty when IIS is not there. */
IisConfiguration readIisConfiguration();

/*! What the collection takes of IIS, from its configuration (or the
 *  defaults, without one): every folder absolute, each once. */
struct IisSources {
	std::vector<std::wstring> siteFolders;  //!< the physical path of each virtual directory; a volume's root left out
	std::vector<std::wstring> logFolders;   //!< the logs' directories (W3SVC<id> beneath them) and HTTPERR
	std::wstring historyFolder;             //!< the configuration's history
};

/*! @param configuration as read; an empty one gives the defaults
 *  @return the folders to take */
IisSources iisSources(const IisConfiguration& configuration);

/*! IIS's W3C logs and HTTP.sys's, parsed.
 *  @param text a log, decoded
 *  @param file its path on the examined machine
 *  @return its lines, dates in UTC */
std::vector<W3cLogEntry> parseIisLog(const std::wstring& text, const std::wstring& file);

/*! A connection string of a web.config. */
struct IisConnectionString {
	std::wstring name;              //!< its name in the section
	std::wstring connectionString;  //!< as written
	std::wstring providerName;      //!< the data provider ("System.Data.SQLite")
	std::wstring databaseFile;      //!< the database file it names, resolved; empty for a server or a share
	std::wstring protectedBy;       //!< an encrypted section's provider: its strings are not read
	std::wstring file;              //!< the web.config, on the examined machine
	Json toJson() const;            //!< @return the connection string as a JSON object
};

/*! The database file a connection string names: the value of Data Source,
 *  AttachDbFilename, Dbq or Filename, `|DataDirectory|` as the site's
 *  App_Data, kept only if it is a local path with a database's extension.
 *  @param connectionString as written
 *  @param siteFolder the folder of the site whose web.config holds it
 *  @return the file, absolute; empty if it names none */
std::wstring connectionDatabaseFile(const std::wstring& connectionString, const std::wstring& siteFolder);

/*! The connection strings of a web.config.
 *  @param xml its text
 *  @param file its path on the examined machine
 *  @param siteFolder the folder of its site, for `|DataDirectory|`
 *  @return one per `add`; one with protectedBy alone for an encrypted section */
std::vector<IisConnectionString> parseConnectionStrings(const std::wstring& xml, const std::wstring& file,
                                                        const std::wstring& siteFolder);

/*! The connection strings of every web.config under the sites' folders, as
 *  the collection copied them (working copy).
 *  @param siteFolders the sites' folders (iisSources) */
std::vector<IisConnectionString> readConnectionStrings(const std::vector<std::wstring>& siteFolders);

/*! The database files the connection strings name outside the sites' folders,
 *  each once: those the copy of the sites does not bring. */
std::vector<std::wstring> externalDatabases(const std::vector<IisConnectionString>& connections,
                                            const std::vector<std::wstring>& siteFolders);

/*! The scheme a password hash names by its form: its prefix ($2y$ bcrypt, $P$
 *  phpass, pbkdf2_sha256$…), or, for a bare hexadecimal digest, its size.
 *  @return the scheme; empty when the form names none */
std::wstring passwordHashFormat(const std::wstring& value);

/*! The account rows of an SQLite database: every table whose name says
 *  accounts and that has a password column.
 *  @param workingFile the database in the working copy
 *  @param examinedFile its path on the examined machine
 *  @return one JSON object per row; none for a file that is no SQLite database */
std::vector<Json> readApplicationAccounts(const std::wstring& workingFile, const std::wstring& examinedFile);

/*! The web server (web_server_*.json). */
class WebServer {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without IIS
	HRESULT toJson();           //!< @return the result of the writes; the logs streamed
	void clear();               //!< releases what was read
private:
	IisConfiguration configuration_;
	std::vector<IisConnectionString> connections_;
	std::vector<Json> accounts_;   //!< the application's account rows
	std::vector<WebInstallation> installations_;  //!< Apache and nginx (web_installations.h)
	std::vector<DatabaseEngine> engines_;         //!< the database engines
};

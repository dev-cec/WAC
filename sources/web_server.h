/*! \file
 *  \brief The web server of the examined machine: IIS (backlog B-035, lot 1).
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
 *  THE LOGS' FORMAT: W3C extended (w3c_log.h), IIS's default; the dates in
 *  UTC — IIS writes W3C in UTC whatever its localTimeRollover, which only
 *  names the files. The other formats (IIS, NCSA, custom) are taken raw,
 *  not converted.
 *
 *  OUTPUT. web_server_sites.json, web_server_application_pools.json,
 *  web_server_modules.json (the configuration, each element's attributes as
 *  IIS stores them — a password of a pool or a virtual directory stays as
 *  IIS encrypted it), web_server_logs.json (one object per request).
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "w3c_log.h"

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

/*! The web server (web_server_*.json). */
class WebServer {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without IIS
	HRESULT toJson();           //!< @return the result of the writes; the logs streamed
	void clear();               //!< releases the configuration
private:
	IisConfiguration configuration_;
};

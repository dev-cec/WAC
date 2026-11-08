/*! \file
 *  \brief The table of the applications' traces (see application_traces.h).
 */
#include "application_traces.h"

const wchar_t* const PROFILE_MARK = L"%profile%";

namespace {

const unsigned WHOLE = 8;    //!< a product's folder taken with its subfolders, guard against an abnormal tree
const std::vector<std::wstring> ALL = {};
const std::vector<std::wstring> METADATA = { L".db", L".db-wal", L".db-shm", L".sqlite", L".sqlite3", L".sqlite-wal", L".sqlite-shm", L".log", L".txt" };

//! Remote administration tools, a usual way in and the usual way to stay.
std::vector<TraceProduct> remoteAdministration() {
	return {
		{ "ammyy", L"Ammyy Admin", { { L"\\ProgramData\\Ammyy", ALL, WHOLE } } },
		{ "anydesk", L"AnyDesk", {
			{ L"%profile%\\AppData\\Roaming\\AnyDesk", { L".trace", L".conf", L"connection_trace.txt" }, 0 },
			{ L"\\ProgramData\\AnyDesk", { L".trace", L".conf", L"connection_trace.txt" }, 0 },
			{ L"%profile%\\Videos\\AnyDesk", { L".anydesk" }, 0 },
			{ L"\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\AnyDesk", ALL, 0 },
			{ L"\\Windows\\SysWOW64\\config\\systemprofile\\AppData\\Roaming\\AnyDesk", ALL, 0 } } },
		{ "atera", L"Atera Agent", { { L"\\Program Files\\ATERA Networks\\AteraAgent", { L".ini", L".txt", L".db", L".config", L".cfg" }, WHOLE } } },
		{ "kaseya", L"Kaseya", {
			{ L"\\ProgramData\\Kaseya\\Log", ALL, WHOLE },
			{ L"%profile%\\AppData\\Local\\Kaseya\\Log", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Kaseya\\Log", ALL, WHOLE },
			{ L"\\Program Files*\\Kaseya\\*", { L"agentmon.log*" }, 0 },
			{ L"\\Windows\\Temp", { L"KASetup.log" }, 0 } } },
		{ "logmein", L"LogMeIn", {
			{ L"\\ProgramData\\LogMeIn\\Logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Local\\Temp\\LogMeInLogs", ALL, WHOLE } } },
		{ "radmin", L"Radmin", {
			{ L"\\Windows\\System32\\rserver30", { L"Radm_log.htm" }, 0 },
			{ L"\\Windows\\SysWOW64\\rserver30", { L"Radm_log.htm" }, 0 },
			{ L"\\Windows\\System32\\rserver30\\CHATLOGS", { L".htm" }, 2 },
			{ L"\\Windows\\SysWOW64\\rserver30\\CHATLOGS", { L".htm" }, 2 },
			{ L"%profile%\\Documents\\ChatLogs", { L".htm" }, 2 } } },
		{ "remote_utilities", L"Remote Utilities", {
			{ L"\\Program Files*\\Remote Utilities - Host\\Logs", { L"rut_log_*.html" }, 0 },
			{ L"\\ProgramData\\Remote Utilities", { L"install.log" }, 0 } } },
		// Not a KAPE target: the folders the project's own documentation gives.
		{ "rustdesk", L"RustDesk", {
			{ L"%profile%\\AppData\\Roaming\\RustDesk", { L".log", L".toml" }, WHOLE },
			{ L"\\ProgramData\\RustDesk", { L".log", L".toml" }, WHOLE } } },
		{ "screenconnect", L"ScreenConnect", {
			{ L"\\Program Files*\\ScreenConnect\\App_Data", { L"Session.db", L"User.xml" }, 0 },
			{ L"\\ProgramData\\ScreenConnect Client*", { L"user.config" }, 0 } } },
		{ "splashtop", L"Splashtop", {
			{ L"\\Program Files*\\Splashtop\\Splashtop Remote\\Server\\log", ALL, WHOLE },
			{ L"\\ProgramData\\Splashtop\\Temp\\log", ALL, WHOLE } } },
		{ "supremo", L"Supremo", {
			{ L"\\ProgramData\\SupremoRemoteDesktop\\Log", { L".log" }, 0 },
			{ L"\\ProgramData\\SupremoRemoteDesktop\\Inbox", ALL, 0 } } },
		{ "teamviewer", L"TeamViewer", {
			{ L"\\Program Files*\\TeamViewer", { L"connections*.txt", L"TeamViewer*_Logfile*" }, 0 },
			{ L"%profile%\\AppData\\Roaming\\TeamViewer", { L"connections*.txt", L"TeamViewer*_Logfile*" }, 0 },
			{ L"%profile%\\AppData\\Roaming\\TeamViewer\\MRU\\RemoteSupport", ALL, WHOLE } } },
		{ "ultraviewer", L"UltraViewer", {
			{ L"%profile%\\AppData\\Roaming\\UltraViewer", ALL, WHOLE },
			{ L"\\Program Files*\\UltraViewer", { L"UltraViewerService_log.txt", L"ConnectionLog.Log" }, 0 } } },
		{ "vnc", L"VNC", {
			{ L"%profile%\\AppData\\Local\\RealVNC", { L"vncserver.log" }, 0 },
			{ L"\\ProgramData\\RealVNC-Service", { L"vncserver.log" }, 0 } } },
		{ "mremoteng", L"mRemoteNG", {
			{ L"%profile%\\AppData\\Roaming\\mRemoteNG", { L"mRemoteNG.log", L"confCons.xml*" }, 0 },
			{ L"%profile%\\AppData\\Local\\mRemoteNG", { L"user.config" }, 3 },
			{ L"%profile%\\AppData\\Roaming\\mRemoteNG", { L"user.config" }, 3 } } },
	};
}

//! OpenSSH: who may come in, where the machine went. No private key (application_traces.h).
std::vector<TraceProduct> ssh() {
	return {
		{ "openssh_server", L"OpenSSH server", {
			{ L"\\ProgramData\\ssh", { L"sshd_config", L"administrators_authorized_keys", L".pub" }, 0 },
			{ L"\\ProgramData\\ssh\\logs", ALL, 0 },
			{ L"%profile%\\.ssh", { L"authorized_keys", L"authorized_keys2" }, 0 } } },
		{ "openssh_client", L"OpenSSH client", { { L"%profile%\\.ssh", { L"config", L"known_hosts", L"known_hosts.old", L".pub" }, 0 } } },
	};
}

//! Antivirus other than Defender, which has its own artefacts: what each one saw and removed.
std::vector<TraceProduct> antivirus() {
	return {
		{ "avast", L"Avast", {
			{ L"\\ProgramData\\Avast Software\\Avast\\Log", ALL, WHOLE },
			{ L"\\ProgramData\\Avast Software\\Avast\\Chest", { L"index.xml" }, 0 },
			{ L"\\ProgramData\\Avast Software\\Persistent Data\\Avast\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\Avast Software\\Icarus\\Logs", ALL, WHOLE },
			{ L"%profile%\\Avast Software\\Avast\\Log", ALL, WHOLE } } },
		{ "avg", L"AVG", {
			{ L"\\ProgramData\\AVG\\Antivirus\\log", ALL, WHOLE },
			{ L"\\ProgramData\\AVG\\Antivirus\\report", ALL, WHOLE },
			{ L"\\ProgramData\\AVG\\Persistent Data\\Antivirus\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\AVG\\Antivirus", { L"FileInfo2.db", L"lsdb2.json" }, 0 } } },
		{ "avira", L"Avira", {
			{ L"\\ProgramData\\Avira\\Antivirus\\LOGFILES", ALL, WHOLE },
			{ L"\\ProgramData\\Avira\\Security\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\Avira\\VPN", ALL, WHOLE } } },
		{ "bitdefender", L"Bitdefender", {
			{ L"\\ProgramData\\Bitdefender\\Endpoint Security\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\Bitdefender\\Desktop\\Profiles\\Logs", ALL, WHOLE },
			{ L"\\Program Files*\\Bitdefender*", { L".db", L".db-wal", L".db-shm" }, WHOLE } } },
		{ "cybereason", L"Cybereason", {
			{ L"\\ProgramData\\crs1\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\apv2\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\crb1\\Logs", ALL, WHOLE } } },
		{ "emsisoft", L"Emsisoft", { { L"\\ProgramData\\Emsisoft\\Reports", { L"scan*.txt" }, 0 } } },
		{ "eset", L"ESET", {
			{ L"\\ProgramData\\ESET\\ESET NOD32 Antivirus\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\ESET\\ESET Security\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\ESET\\RemoteAdministrator\\Agent\\EraAgentApplicationData\\Logs", ALL, 0 } } },
		{ "fsecure", L"F-Secure", {
			{ L"\\ProgramData\\F-Secure\\Log", ALL, WHOLE },
			{ L"%profile%\\AppData\\Local\\F-Secure\\Log", ALL, WHOLE },
			{ L"\\ProgramData\\F-Secure\\Antivirus\\ScheduledScanReports", ALL, WHOLE } } },
		{ "hitmanpro", L"HitmanPro", {
			{ L"\\ProgramData\\HitmanPro\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\HitmanPro.Alert\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\HitmanPro.Alert", { L"excalibur.db" }, 0 } } },
		{ "malwarebytes", L"Malwarebytes", {
			{ L"\\ProgramData\\Malwarebytes\\Malwarebytes Anti-Malware\\Logs", { L"mbam-log-*.xml" }, 0 },
			{ L"\\ProgramData\\Malwarebytes\\MBAMService\\logs", { L"mbamservice.log*" }, 0 },
			{ L"%profile%\\AppData\\Roaming\\Malwarebytes\\Malwarebytes Anti-Malware\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\Malwarebytes\\MBAMService\\ScanResults", ALL, WHOLE } } },
		{ "mcafee", L"McAfee", {
			{ L"\\ProgramData\\McAfee\\DesktopProtection", ALL, WHOLE },
			{ L"\\ProgramData\\McAfee\\Endpoint Security\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\McAfee\\Endpoint Security\\Logs_Old", ALL, WHOLE },
			{ L"\\ProgramData\\McAfee\\VirusScan", ALL, WHOLE } } },
		{ "roguekiller", L"RogueKiller", { { L"\\ProgramData\\RogueKiller\\logs", { L"AdliceReport_*.json" }, 0 } } },
		{ "secureage", L"SecureAge", { { L"\\ProgramData\\SecureAge Technology\\SecureAge\\log", ALL, WHOLE } } },
		{ "sentinelone", L"SentinelOne", { { L"\\ProgramData\\Sentinel\\Logs", ALL, WHOLE } } },
		{ "sophos", L"Sophos", { { L"\\ProgramData\\Sophos\\Sophos *\\Logs", ALL, WHOLE } } },
		{ "superantispyware", L"SUPERAntiSpyware", { { L"%profile%\\AppData\\Roaming\\SUPERAntiSpyware\\Logs", ALL, WHOLE } } },
		{ "symantec", L"Symantec Endpoint Protection", {
			{ L"\\ProgramData\\Symantec\\Symantec Endpoint Protection\\*\\Data\\Logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Local\\Symantec\\Symantec Endpoint Protection\\Logs", ALL, WHOLE },
			{ L"\\ProgramData\\Symantec\\Symantec Endpoint Protection\\*\\Data\\Quarantine", ALL, WHOLE },
			{ L"\\ProgramData\\Symantec\\Symantec Endpoint Protection\\*\\Data\\CmnClnt\\ccSubSDK", ALL, WHOLE },
			{ L"\\ProgramData\\Symantec\\Symantec Endpoint Protection\\*\\Data", { L"registrationInfo.xml" }, 0 } } },
		{ "totalav", L"TotalAV", {
			{ L"\\Program Files*\\TotalAV\\logs", ALL, WHOLE },
			{ L"\\ProgramData\\TotalAV\\logs", ALL, WHOLE } } },
		{ "trend_micro", L"Trend Micro", {
			{ L"\\ProgramData\\Trend Micro", ALL, WHOLE },
			{ L"\\Program Files*\\Trend Micro\\Security Agent\\Report", { L".log" }, 0 },
			{ L"\\Program Files*\\Trend Micro\\Security Agent\\ConnLog", { L".log" }, 0 } } },
		{ "vipre", L"VIPRE", {
			{ L"\\ProgramData\\VIPRE Business Agent\\Logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\VIPRE Business", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\GFI Software\\AntiMalware\\Logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Sunbelt Software\\AntiMalware\\Logs", ALL, WHOLE } } },
		{ "webroot", L"Webroot", { { L"\\ProgramData\\WRData", { L"WRLog.log" }, 0 } } },
	};
}

//! Messaging: what was said, to whom, what was received. As KAPE takes them, caches included.
std::vector<TraceProduct> messaging() {
	return {
		{ "discord", L"Discord", {
			{ L"%profile%\\AppData\\Roaming\\discord\\Cache", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\discord\\Local Storage\\leveldb", ALL, WHOLE } } },
		{ "jabber", L"Cisco Jabber", { { L"%profile%\\AppData\\Local\\Cisco\\Unified Communications\\Jabber\\CSF\\History", { L".db" }, 0 } } },
		{ "mattermost", L"Mattermost", { { L"%profile%\\AppData\\Roaming\\Mattermost\\IndexedDB", ALL, WHOLE } } },
		{ "signal", L"Signal", {
			{ L"%profile%\\AppData\\Roaming\\Signal\\attachments.noindex", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Signal\\logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Signal", { L"config.json" }, 0 },
			{ L"%profile%\\AppData\\Roaming\\Signal\\sql", { L"db.sqlite" }, 0 } } },
		{ "skype", L"Skype", {
			{ L"%profile%\\AppData\\Local\\Packages\\Microsoft.SkypeApp_*\\LocalState", { L"main.db", L"skype.db", L"s4l-*.db" }, 2 },
			{ L"%profile%\\AppData\\Roaming\\Skype", { L"main.db" }, 2 },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Skype for Desktop\\IndexedDB", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Skype for Desktop\\Cache", ALL, WHOLE } } },
		{ "slack", L"Slack", {
			{ L"%profile%\\AppData\\Roaming\\Slack\\IndexedDB", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Slack\\Local Storage\\leveldb", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Slack\\logs", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Slack\\Cache", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Slack\\storage", ALL, WHOLE } } },
		{ "teams", L"Microsoft Teams", {
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Teams\\IndexedDB", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Teams\\Local Storage\\leveldb", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Teams\\Cache", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Teams", { L"desktop-config.json" }, 0 },
			{ L"%profile%\\AppData\\Local\\Packages\\MicrosoftTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\Logs", ALL, 0 } } },
		{ "telegram", L"Telegram", {
			{ L"%profile%\\AppData\\Roaming\\Telegram Desktop", ALL, WHOLE },
			{ L"%profile%\\Downloads\\Telegram Desktop", ALL, WHOLE } } },
		{ "viber", L"Viber", {
			{ L"%profile%\\AppData\\Roaming\\ViberPC", { L"config.db", L"viber.db" }, 1 },
			{ L"%profile%\\AppData\\Roaming\\ViberPC\\*\\Avatars", ALL, 0 },
			{ L"%profile%\\AppData\\Roaming\\ViberPC\\*\\Backgrounds", ALL, 0 },
			{ L"%profile%\\AppData\\Roaming\\ViberPC\\*\\Thumbnails", ALL, 0 } } },
		{ "whatsapp", L"WhatsApp", {
			{ L"%profile%\\AppData\\Roaming\\WhatsApp\\Cache", ALL, 0 },
			{ L"%profile%\\AppData\\Roaming\\WhatsApp\\Local Storage\\leveldb", ALL, 0 } } },
		{ "zoom", L"Zoom", {
			{ L"%profile%\\AppData\\Roaming\\Zoom\\logs", ALL, WHOLE },
			{ L"%profile%\\Documents\\Zoom", ALL, WHOLE },
			{ L"%profile%\\AppData\\Roaming\\Zoom Plugin", { L".json" }, 0 } } },
	};
}

//! Cloud storage: what was synchronised, where to. Its metadata, not the user's files.
std::vector<TraceProduct> cloudStorage() {
	return {
		{ "box", L"Box", {
			{ L"%profile%\\AppData\\Local\\Box\\Box", METADATA, WHOLE },
			{ L"%profile%\\AppData\\Local\\Box Sync", METADATA, WHOLE } } },
		{ "dropbox", L"Dropbox", {
			{ L"%profile%\\AppData\\Local\\Dropbox", { L"info.json", L"host.db", L"host.dbx" }, 0 },
			{ L"%profile%\\AppData\\Local\\Dropbox\\machine_storage", { L"tray-thumbnails.db" }, 0 },
			{ L"%profile%\\AppData\\Local\\Dropbox\\instance*", ALL, WHOLE } } },
		/* Its databases and logs, not `content_cache`: the user's files, under names
		   without extension. */
		{ "google_drive", L"Google Drive", {
			{ L"%profile%\\AppData\\Local\\Google\\Drive", { L".db", L".db-wal", L".db-shm", L".log", L".txt", L".json" }, WHOLE },
			{ L"%profile%\\AppData\\Local\\Google\\DriveFS", { L".db", L".db-wal", L".db-shm", L".log", L".txt", L".json" }, WHOLE } } },
		{ "pcloud", L"pCloud", { { L"%profile%\\AppData\\Local\\pCloud", { L".db", L".db-wal", L".db-shm" }, 0 } } },
		{ "sugarsync", L"SugarSync", { { L"%profile%\\AppData\\Local\\SugarSync", { L"sc1.log" }, 0 } } },
	};
}

//! File transfer: what left, what came, to which server.
std::vector<TraceProduct> fileTransfer() {
	return {
		{ "filezilla_client", L"FileZilla", { { L"%profile%\\AppData\\Roaming\\FileZilla", { L".xml", L".xml~", L".sqlite3", L".sqlite3-wal", L".sqlite3-shm" }, 0 } } },
		{ "freefilesync", L"FreeFileSync", { { L"%profile%\\AppData\\Roaming\\FreeFileSync\\Logs", ALL, 0 } } },
		{ "teracopy", L"TeraCopy", { { L"%profile%\\AppData\\Roaming\\TeraCopy", ALL, WHOLE } } },
		// KAPE looks for WinSCP.ini over the whole volume: here where the program keeps it.
		{ "winscp", L"WinSCP", {
			{ L"%profile%\\AppData\\Roaming", { L"WinSCP.ini" }, 0 },
			{ L"\\Program Files*\\WinSCP", { L"WinSCP.ini" }, 0 } } },
	};
}

//! VPN clients: the tunnels the machine can open or opened.
std::vector<TraceProduct> vpn() {
	return {
		{ "openvpn", L"OpenVPN", {
			{ L"%profile%\\OpenVPN\\config", ALL, WHOLE },
			{ L"\\Program Files*\\OpenVPN\\config", ALL, WHOLE },
			{ L"%profile%\\OpenVPN\\log", { L".log" }, 0 } } },
		{ "protonvpn", L"Proton VPN", { { L"%profile%\\AppData\\Local\\ProtonVPN\\Logs", ALL, 0 } } },
		// Not KAPE targets: the folders the projects' documentation gives. Tunnels an intruder installs.
		{ "tailscale", L"Tailscale", {
			{ L"\\ProgramData\\Tailscale", { L".log", L".txt", L".conf" }, 1 },
			{ L"%profile%\\AppData\\Local\\Tailscale", { L".log", L".txt", L".conf" }, 1 } } },
		{ "wireguard", L"WireGuard", { { L"\\Program Files\\WireGuard\\Data", { L"log.bin", L".dpapi" }, 1 } } },
	};
}

//! Virtualisation: a machine inside the machine. Configuration and logs, no disk, no memory.
std::vector<TraceProduct> virtualisation() {
	return {
		{ "virtualbox", L"VirtualBox", {
			{ L"%profile%\\.VirtualBox", { L".xml", L".xml-prev", L"VBoxSVC.log*" }, 0 },
			{ L"%profile%\\VirtualBox VMs", { L".vbox", L".vbox-prev", L"VBox.log*", L"VBoxHardening.log" }, 2 } } },
		{ "vmware", L"VMware Workstation", { { L"%profile%\\AppData\\Roaming\\VMware", ALL, 0 } } },
		// The home folders of a WSL 1 distribution; WSL 2's lie inside a virtual disk, not taken.
		{ "wsl", L"Windows Subsystem for Linux", {
			{ L"%profile%\\AppData\\Local\\Packages\\*\\LocalState\\rootfs\\home\\*", { L".bash_history", L".bash_logout", L".bashrc", L".profile" }, 0 },
			{ L"%profile%\\AppData\\Local\\Packages\\*\\LocalState\\rootfs\\root", { L".bash_history", L".bash_logout", L".bashrc", L".profile" }, 0 },
			{ L"%profile%", { L".wslconfig" }, 0 } } },
	};
}

//! Applications of a server, whose logs say who came and what they did.
std::vector<TraceProduct> serverApplications() {
	return {
		{ "confluence", L"Confluence", {
			{ L"\\Atlassian\\Application Data\\Confluence\\logs", { L".log", L"*.log.*" }, 0 },
			{ L"\\Program Files\\Atlassian\\Confluence\\logs", { L".log" }, 0 } } },
		{ "exchange", L"Exchange Server", {
			{ L"\\Program Files\\Microsoft\\Exchange Server\\*\\TransportRoles\\Logs", { L".log" }, WHOLE },
			{ L"\\Program Files\\Microsoft\\Exchange Server\\*\\Logging", { L".log" }, WHOLE } } },
		{ "filezilla_server", L"FileZilla Server", {
			{ L"%profile%\\AppData\\Roaming\\FileZilla Server", { L".xml", L".xml~" }, 0 },
			{ L"\\Program Files*\\FileZilla Server\\Logs", { L"*.log*" }, 0 } } },
		{ "manageengine", L"ManageEngine", { { L"\\ManageEngine\\DesktopCentral_Server\\logs", ALL, WHOLE } } },
		{ "sql_server", L"SQL Server", { { L"\\Program Files*\\Microsoft SQL Server\\*\\MSSQL\\Log", { L"ERRORLOG", L"ERRORLOG.*", L"SQLAGENT.*", L".xel", L".trc" }, 0 } } },
	};
}

//! The logs of a domain's servers, that no event log repeats.
std::vector<TraceProduct> serverLogs() {
	return {
		// A certification authority's database: who asked for which certificate. Open by its service: its logs with it.
		{ "certificate_authority", L"Certification authority", { { L"\\Windows\\System32\\CertLog", { L".edb", L".log", L".chk", L".jfm", L".dat" }, 0 } } },
		{ "dcpromo", L"Domain controller promotion", { { L"\\Windows\\debug", { L"dcpromo.log", L"dcpromoui*.log", L"dcpromo.bak", L"dcpromoui*.bak" }, 0 } } },
		{ "netlogon", L"Netlogon", { { L"\\Windows\\debug", { L"netlogon.log", L"netlogon.bak" }, 0 } } },
		{ "netsetup", L"Domain join", { { L"\\Windows\\debug", { L"NetSetup.log", L"NetSetup.LOG.*" }, 0 } } },
		// RADIUS: who connected through the VPN or the Wi-Fi.
		{ "nps", L"Network Policy Server", { { L"\\Windows\\System32\\LogFiles", { L"IN*.log", L"IAS*.log" }, 0 } } },
		{ "remote_access", L"Routing and Remote Access", { { L"\\Windows\\Tracing", { L".log" }, 0 } } },
	};
}

//! What Windows itself keeps, beyond the other artefacts.
std::vector<TraceProduct> systemTraces() {
	return {
		{ "crash_dumps", L"Crash dumps of the programs", { { L"%profile%\\AppData\\Local\\CrashDumps", { L".dmp" }, 0 } } },
		{ "custom_shims", L"Custom application shims", {
			{ L"\\Windows\\apppatch\\Custom", { L".sdb" }, 0 },
			{ L"\\Windows\\apppatch\\Custom\\Custom64", { L".sdb" }, 0 } } },
		{ "encapsulation_logging", L"Encapsulation logging", { { L"\\Windows\\appcompat\\Programs", { L"EncapsulationLogging.hve*" }, 0 } } },
		{ "event_transcript", L"Diagnostic data store", { { L"\\ProgramData\\Microsoft\\Diagnosis\\EventTranscript", { L"EventTranscript.db*" }, 0 } } },
		{ "microsoft_sccm", L"Configuration Manager client", { { L"\\Windows\\CCM\\Logs", { L".log", L".lo_" }, 0 } } },
		{ "minidumps", L"Kernel crash dumps", { { L"\\Windows\\Minidump", { L".dmp" }, 0 } } },
		{ "notifications", L"Windows notifications", { { L"%profile%\\AppData\\Local\\Microsoft\\Windows\\Notifications", { L"wpndatabase.db*", L"appdb.dat" }, 0 } } },
		{ "office_cache", L"Office document cache", { { L"%profile%\\AppData\\Local\\Microsoft\\Office\\*\\OfficeFileCache", ALL, WHOLE } } },
		// Windows 11 22H2 and later: what the Program Compatibility Assistant saw run.
		{ "pca", L"Program Compatibility Assistant", { { L"\\Windows\\appcompat\\pca", ALL, 0 } } },
		{ "pcw_diagnostics", L"Program compatibility diagnostics", {
			{ L"%profile%\\AppData\\Local\\Diagnostics", { L"PCW.debugreport.xml" }, 2 },
			{ L"%profile%\\AppData\\Local\\ElevatedDiagnostics", { L"PCW.debugreport.xml" }, 2 } } },
		{ "power_diagnostics", L"Power efficiency diagnostics", { { L"\\ProgramData\\Microsoft\\Windows\\Power Efficiency Diagnostics", ALL, 0 } } },
		{ "powershell_transcripts", L"PowerShell transcripts", {
			{ L"%profile%\\Documents", { L"PowerShell_transcript.*.txt" }, 1 } } },
		{ "scheduled_task_log", L"Task Scheduler's log", {
			{ L"\\Windows", { L"SchedLgU.txt" }, 0 },
			{ L"\\Windows\\Tasks", { L"SchedLgU.txt" }, 0 } } },
		{ "search_gather_logs", L"Windows Search's gathering logs", { { L"\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs", ALL, WHOLE } } },
		{ "sleep_study", L"Sleep study", { { L"\\Windows\\System32\\SleepStudy", ALL, WHOLE } } },
		{ "snip_sketch", L"Snipping tool's screenshots", { { L"%profile%\\AppData\\Local\\Packages\\Microsoft.ScreenSketch_8wekyb3d8bbwe\\TempState", { L".png" }, 0 } } },
		{ "startup_info", L"Startup information", { { L"\\Windows\\System32\\WDI\\LogFiles\\StartupInfo", { L".xml" }, 0 } } },
		{ "sticky_notes", L"Sticky Notes", {
			{ L"%profile%\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState", { L"plum.sqlite*" }, 0 },
			{ L"%profile%\\AppData\\Roaming\\Microsoft\\Sticky Notes", { L"StickyNotes.snt" }, 0 } } },
		{ "syscache", L"Syscache", { { L"\\System Volume Information", { L"Syscache.hve*" }, 0 } } },
		{ "windows_old", L"The previous Windows", {
			{ L"\\Windows.old\\Windows\\System32\\config", { L"SAM", L"SECURITY", L"SOFTWARE", L"SYSTEM" }, 0 },
			{ L"\\Windows.old\\Windows\\System32\\winevt\\Logs", { L".evtx" }, 0 },
			{ L"\\Windows.old\\Windows\\Prefetch", { L".pf" }, 0 },
			{ L"\\Windows.old\\Windows\\System32\\Tasks", ALL, WHOLE },
			{ L"\\Windows.old\\Windows\\appcompat\\Programs", { L"Amcache.hve*" }, 0 },
			{ L"\\Windows.old\\Windows\\System32\\sru", ALL, 0 } } },
		{ "windows_upgrade", L"Windows setup and upgrade logs", {
			{ L"\\Windows\\Panther", { L"MigLog.xml", L"setupact.log", L"*HumanReadable.xml" }, 1 },
			{ L"\\Windows\\Panther\\Rollback", { L"FolderMoveLog.txt" }, 0 },
			{ L"\\ProgramData\\USOPrivate\\UpdateStore", { L"store.db" }, 0 } } },
	};
}

} // namespace

const std::vector<TraceGroup>& applicationTraces() {
	static const std::vector<TraceGroup> groups = {
		{ "antivirus", antivirus() },
		{ "cloud_storage", cloudStorage() },
		{ "file_transfer", fileTransfer() },
		{ "messaging", messaging() },
		{ "remote_administration", remoteAdministration() },
		{ "server_applications", serverApplications() },
		{ "server_logs", serverLogs() },
		{ "ssh", ssh() },
		{ "system_traces", systemTraces() },
		{ "virtualisation", virtualisation() },
		{ "vpn", vpn() },
	};
	return groups;
}

const TraceGroup* traceGroup(const std::string& key) {
	for (const TraceGroup& group : applicationTraces()) if (group.key == key) return &group;
	return nullptr;
}

bool isPasswordValue(const std::wstring& name) {
	return wildcardMatch(L"*password*", name);
}

bool traceProductWanted(const std::set<std::string>& off, const std::string& group, const std::string& product) {
	return off.count(group) == 0 && off.count(group + "." + product) == 0;
}

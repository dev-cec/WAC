/*! \file
 *  \brief The table of the artefacts by version of Windows (see
 *         artefact_catalogue.h).
 */
#include "artefact_catalogue.h"

namespace {

// First build of each release that changed an artefact.
const unsigned XP = 2600, SERVER_2003 = 3790, VISTA = 6000, SEVEN = 7600, EIGHT = 9200, EIGHT_1 = 9600,
               TEN = 10240, TEN_1607 = 14393, TEN_1709 = 16299, TEN_1803 = 17134, TEN_1903 = 18362,
               ELEVEN = 22000;

/* ShimCache of Windows 8 and 8.1: both headers are 0x80 bytes long and
   their first DWORD is no magic number, so the piece is told by the tag of
   its first entry, read as a little-endian number. */
const unsigned SHIMCACHE_00TS = 0x73743030, SHIMCACHE_10TS = 0x73743031;

} // namespace

const std::vector<WindowsRelease>& windowsReleases() {
	static const std::vector<WindowsRelease> releases = {
		{ XP, 2600, false, L"Windows XP" },
		{ VISTA, 6003, false, L"Windows Vista" },
		{ SEVEN, 7601, false, L"Windows 7" },
		{ EIGHT, 9200, false, L"Windows 8" },
		{ EIGHT_1, 9600, false, L"Windows 8.1" },
		{ TEN, 19045, false, L"Windows 10" },
		{ ELEVEN, 26200, false, L"Windows 11" },
		{ SERVER_2003, 3790, true, L"Windows Server 2003" },
		{ 6001, 6003, true, L"Windows Server 2008" },
		{ SEVEN, 7601, true, L"Windows Server 2008 R2" },
		{ EIGHT, 9200, true, L"Windows Server 2012" },
		{ EIGHT_1, 9600, true, L"Windows Server 2012 R2" },
		{ TEN_1607, 14393, true, L"Windows Server 2016" },
		{ 17763, 17763, true, L"Windows Server 2019" },
		{ 20348, 20348, true, L"Windows Server 2022" },
		{ 26100, 26100, true, L"Windows Server 2025" },
	};
	return releases;
}

const std::vector<ArtefactEntry>& artefactCatalogue() {
	static const std::vector<ArtefactEntry> catalogue = {
		{ "activities_cache", TEN_1803, 0, 0,
		  { { TEN_1803, L"Users\\<user>\\AppData\\Local\\ConnectedDevicesPlatform\\<account>\\ActivitiesCache.db", L"SQLite", true } },
		  L"Still written by Windows 11 (measured, build 26200), though the Timeline is no longer shown. Server editions to be measured." },
		{ "amcache", SEVEN, 0, TEN,
		  { { SEVEN, L"Windows\\AppCompat\\Programs\\RecentFileCache.bcf", L"BCF", false },
		    { EIGHT, L"Windows\\AppCompat\\Programs\\Amcache.hve", L"registry hive, File and Programs keys", false },
		    { TEN_1607, L"Windows\\AppCompat\\Programs\\Amcache.hve", L"registry hive, Inventory* keys", true } },
		  L"Amcache.hve also on Windows 7 with update KB2952664." },
		{ "bam", TEN_1709, 0, 0,
		  { { TEN_1709, L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings", L"registry values, FILETIME", true },
		    { TEN_1803, L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings", L"registry values, FILETIME", true } },
		  L"Server editions to be measured." },
		{ "bits", XP, 0, 0,
		  { { XP, L"ProgramData\\Microsoft\\Network\\Downloader\\qmgr0.dat, qmgr1.dat", L"BITS state file", false },
		    { TEN_1709, L"ProgramData\\Microsoft\\Network\\Downloader\\qmgr.db", L"ESE", true } },
		  L"Before Vista: Documents and Settings\\All Users\\Application Data\\Microsoft\\Network\\Downloader." },
		{ "defender", EIGHT, 0, 0,
		  { { EIGHT, L"ProgramData\\Microsoft\\Windows Defender\\Support\\MPLog-*.log", L"UTF-16 text", true },
		    { TEN_1903, L"ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\Service\\DetectionHistory", L"DetectionHistory records", true } },
		  L"Server 2012 and 2012 R2 have no built-in Defender; quarantine copied encrypted on every version." },
		{ "defender_configuration", VISTA, 0, 0,
		  { { VISTA, L"SOFTWARE\\Microsoft\\Windows Defender, SOFTWARE\\Policies\\Microsoft\\Windows Defender", L"registry values", true } }, L"" },
		{ "devices", XP, 0, 0,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Enum\\USB, SCSI", L"registry keys", true },
		    { VISTA, L"…and SOFTWARE\\Microsoft\\Windows Portable Devices, device properties with dates (Windows 8)", L"registry keys", true } }, L"" },
		{ "dpapi_master_keys", XP, 0, 0,
		  { { XP, L"<profile>\\Application Data\\Microsoft\\Protect\\<SID>", L"master key file, version 2", true },
		    { VISTA, L"Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>", L"master key file, version 2", true } }, L"" },
		{ "emails", XP, 0, 0,
		  { { XP, L"Outlook PST and OST, Thunderbird mbox, in each profile", L"PST/OST (ANSI and Unicode), mbox", true } },
		  L"Depends on the mail program installed, not on Windows." },
		{ "error_reports", VISTA, 0, 0,
		  { { VISTA, L"ProgramData\\Microsoft\\Windows\\WER, Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\WER", L"Report.wer, UTF-16 text", true } },
		  L"Windows XP: Dr Watson (drwtsn32.log, user.dmp), not collected." },
		{ "event_log_configuration", XP, 0, XP,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Services\\EventLog", L"registry keys", true },
		    { VISTA, L"…and SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels, Control\\WMI\\Autologger", L"registry keys", true } }, L"" },
		{ "events", XP, 0, XP,
		  { { XP, L"Windows\\System32\\config\\*.evt", L"EVT (LfLe records)", false },
		    { VISTA, L"Windows\\System32\\winevt\\Logs\\*.evtx", L"EVTX, binary XML", true } }, L"" },
		{ "explorer_recent_docs", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs", L"MRUListEx and shell items", true } }, L"" },
		{ "fat_volumes", XP, 0, 0,
		  { { XP, L"FAT12, FAT16, FAT32 volumes", L"FAT directory entries", true },
		    { VISTA, L"…and exFAT volumes (Vista SP1; XP with KB955704)", L"exFAT directory entries", true } }, L"" },
		{ "firewall", XP, 0, 0,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy (XP SP2)", L"registry values, profiles and port lists", false },
		    { VISTA, L"…\\FirewallPolicy\\FirewallRules", L"registry values, rule strings v2.x", true } }, L"" },
		{ "hosts", XP, 0, XP,
		  { { XP, L"Windows\\System32\\drivers\\etc\\hosts", L"text", true } }, L"" },
		{ "installed_programs", XP, 0, XP,
		  { { XP, L"SOFTWARE and NTUSER.DAT …\\CurrentVersion\\Uninstall, Installer\\UserData", L"registry keys", true } }, L"" },
		{ "internet_settings", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", L"registry values", true } }, L"" },
		{ "jump_lists", SEVEN, 0, 0,
		  { { SEVEN, L"Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations, CustomDestinations", L"OLE compound file, DestList version 1", true, { 1 } },
		    { TEN, L"the same folders", L"OLE compound file, DestList version 3 and 4", true, { 3, 4 } },
		    { ELEVEN, L"the same folders", L"OLE compound file, DestList version 6", true, { 6 } } },
		  L"DestList version 6 measured on build 26200; the custom lists (CustomDestinations) carry no version." },
		{ "known_networks", VISTA, 0, 0,
		  { { VISTA, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList", L"registry keys, SYSTEMTIME dates", true } }, L"" },
		{ "local_groups", XP, 0, XP,
		  { { XP, L"SAM\\SAM\\Domains\\Builtin\\Aliases", L"SAM alias records", true } }, L"" },
		{ "log_file", XP, 0, 0,
		  { { XP, L"$LogFile", L"NTFS log, raw copy", false },
		    { VISTA, L"…and $Extend\\$RmMetadata\\$TxfLog", L"transactional NTFS log, raw copy", false } }, L"Copied raw on every version: not converted." },
		{ "mft", XP, 0, 0,
		  { { XP, L"$MFT", L"NTFS 3.1 file records", true } }, L"" },
		{ "mounted_devices", XP, 0, XP,
		  { { XP, L"SYSTEM\\MountedDevices", L"registry values", true } }, L"" },
		{ "mount_points", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", L"registry keys", true } }, L"" },
		{ "mru", XP, 0, 0,
		  { { XP, L"NTUSER.DAT …\\Explorer\\ComDlg32\\OpenSaveMRU, LastVisitedMRU", L"MRUList and strings", false },
		    { VISTA, L"NTUSER.DAT …\\Explorer\\ComDlg32\\OpenSavePidlMRU, LastVisitedPidlMRU", L"MRUListEx and shell items", true } }, L"" },
		{ "mru_apps", XP, 0, 0,
		  { { XP, L"NTUSER.DAT …\\Explorer\\ComDlg32\\LastVisitedMRU", L"MRUList and strings", false },
		    { VISTA, L"NTUSER.DAT …\\Explorer\\ComDlg32\\LastVisitedPidlMRU", L"MRUListEx and shell items", true } }, L"" },
		{ "muicache", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache", L"registry values", false },
		    { VISTA, L"UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache", L"registry values", true } }, L"" },
		{ "network", XP, 0, 0,
		  { { XP, L"live: TCP/IP tables of the running system", L"observation", true } }, L"" },
		{ "network_configuration", XP, 0, XP,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces, Control\\Network", L"registry values", true },
		    { TEN, L"…and Control\\NetworkSetup2\\Interfaces\\<guid>\\Kernel: hardware addresses", L"registry values", true } },
		  L"Before Windows 10, the adapters' hardware addresses are in no documented key of the hives: not given." },
		{ "network_shares", XP, 0, 0,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares", L"registry values, security descriptors", true } }, L"" },
		{ "ntfs_volumes", XP, 0, 0,
		  { { XP, L"$Boot, $Extend\\$UsnJrnl:$Max", L"NTFS boot sector, journal header", true } }, L"" },
		{ "office_trust_records", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Office\\<version>\\<program>\\Security\\Trusted Documents\\TrustRecords", L"registry values", true } },
		  L"Depends on Office (2010 and later), not on Windows." },
		{ "operating_system", XP, 0, XP,
		  { { XP, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, SYSTEM\\…\\Control", L"registry values", true } }, L"" },
		{ "persistence", XP, 0, XP,
		  { { XP, L"SOFTWARE, SYSTEM and NTUSER.DAT: IFEO, AppInit_DLLs, Winlogon, LSA, Active Setup…", L"registry values", true } }, L"" },
		{ "powershell_history", TEN, 0, 0,
		  { { TEN, L"Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", L"UTF-8 text", true } },
		  L"Earlier with PSReadLine installed by hand (PowerShell 5, Windows 7 and later)." },
		{ "prefetch", XP, 0, 0,
		  { { XP, L"Windows\\Prefetch\\*.pf", L"SCCA version 17", false, { 17 } },
		    { VISTA, L"Windows\\Prefetch\\*.pf", L"SCCA version 23", false, { 23 } },
		    { EIGHT, L"Windows\\Prefetch\\*.pf", L"SCCA version 26", false, { 26 } },
		    { TEN, L"Windows\\Prefetch\\*.pf", L"SCCA version 30 and 31, compressed (MAM)", true, { 30, 31 } } },
		  L"Switched off by default on the server editions." },
		{ "processes", XP, 0, 0,
		  { { XP, L"live: processes of the running system", L"observation", true } }, L"" },
		{ "program_usage", XP, 0, 0,
		  { { XP, L"NTUSER.DAT …\\AppCompatFlags\\Layers", L"registry values", true },
		    { VISTA, L"…and AppCompatFlags\\Compatibility Assistant\\Store, Explorer\\Taskband", L"registry values", true },
		    { TEN_1903, L"…and Explorer\\FeatureUsage, Search\\JumplistData", L"registry values", true } }, L"" },
		{ "rdp_client", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Terminal Server Client; …\\Terminal Server Client\\Cache\\bcache*.bmc", L"registry values; BMC bitmap cache", false },
		    { SEVEN, L"…and Cache\\Cache????.bin", L"BIN bitmap cache", true } },
		  L"Registry values and .rdp files read on every version; only the tiles of the .bmc cache are not exported." },
		{ "rdp_server", VISTA, 0, 0,
		  { { VISTA, L"Security.evtx, TerminalServices-LocalSessionManager and RemoteConnectionManager logs", L"EVTX events", true } },
		  L"Windows XP and Server 2003: events 528 and 682 of Security.evt, not converted." },
		{ "recent_documents", XP, 0, 0,
		  { { XP, L"<profile>\\Recent\\*.lnk", L"shell link", true },
		    { VISTA, L"Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.lnk", L"shell link", true } }, L"" },
		{ "recycle_bin", XP, 0, 0,
		  { { XP, L"RECYCLER\\<SID>\\INFO2", L"INFO2 records", false },
		    { VISTA, L"$Recycle.Bin\\<SID>\\$I*", L"$I version 1", true, { 1 } },
		    { TEN, L"$Recycle.Bin\\<SID>\\$I*", L"$I version 2", true, { 2 } } }, L"" },
		{ "registry_backups", XP, 0, 0,
		  { { XP, L"Windows\\repair", L"registry hives", false },
		    { VISTA, L"Windows\\System32\\config\\RegBack", L"registry hives, raw copy", false } },
		  L"Empty since Windows 10 1803 unless the backup task was switched back on. Copied raw: not converted." },
		{ "root_certificates", XP, 0, XP,
		  { { XP, L"SOFTWARE and NTUSER.DAT …\\SystemCertificates\\Root, AuthRoot", L"certificate blobs", true } }, L"" },
		{ "run_keys", XP, 0, XP,
		  { { XP, L"SOFTWARE and NTUSER.DAT …\\CurrentVersion\\Run, RunOnce", L"registry values", true } }, L"" },
		{ "scheduled_tasks", XP, 0, XP,
		  { { XP, L"Windows\\Tasks\\*.job", L"JOB binary", false },
		    { VISTA, L"Windows\\System32\\Tasks, SOFTWARE …\\Schedule\\TaskCache", L"XML, registry values", true } }, L"" },
		{ "search_index", VISTA, 0, 0,
		  { { VISTA, L"ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb", L"ESE", false },
		    { ELEVEN, L"…\\Windows\\Windows.db, Windows-gather.db", L"SQLite", true } },
		  L"Windows.edb is collected with its logs, not converted. Windows XP: Windows Desktop Search, an optional install." },
		{ "security", XP, 0, XP,
		  { { XP, L"SECURITY hive: Policy\\Secrets, Cache, PolAdtEv", L"registry values", true } }, L"" },
		{ "security_descriptors", XP, 0, 0,
		  { { XP, L"$Secure:$SDS", L"NTFS security descriptor stream", true } }, L"" },
		{ "services", XP, 0, XP,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Services", L"registry keys", true } }, L"" },
		{ "sessions", XP, 0, 0,
		  { { XP, L"live: logon sessions of the running system", L"observation", true } }, L"" },
		{ "setupapi", XP, 0, XP,
		  { { XP, L"Windows\\setupapi.log", L"text, XP layout", false },
		    { VISTA, L"Windows\\INF\\setupapi.dev.log", L"text, sections", true } }, L"" },
		{ "shellbags", XP, 0, 0,
		  { { XP, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell and ShellNoRoam", L"BagMRU shell items", false },
		    { VISTA, L"UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell, and NTUSER.DAT", L"BagMRU shell items", true } }, L"" },
		{ "shimcache", XP, 0, XP,
		  { { XP, L"SYSTEM\\…\\Control\\Session Manager\\AppCompatibility\\AppCompatCache", L"header 0xDEADBEEF, 96 entries", false, { 0xDEADBEEF } },
		    { SERVER_2003, L"SYSTEM\\…\\Control\\Session Manager\\AppCompatCache\\AppCompatCache", L"header 0xBADC0FFE", false, { 0xBADC0FFE } },
		    { SEVEN, L"the same value", L"header 0xBADC0FEE", false, { 0xBADC0FEE } },
		    { EIGHT, L"the same value", L"header 0x80, entries \"00ts\"", false, { SHIMCACHE_00TS } },
		    { EIGHT_1, L"the same value", L"header of 0x80 bytes starting with 0, entries \"10ts\"", false, { SHIMCACHE_10TS } },
		    { TEN, L"the same value", L"header 0x30 or 0x34, entries \"10ts\"", true, { 0x30, 0x34 } } },
		  L"Windows 8 and 8.1 have a header of 0x80 bytes: they are told apart by the tag of their first entry, which is their signature here. Windows 8.1 measured on build 9600." },
		{ "shortcuts", XP, 0, 0,
		  { { XP, L"Start menu, desktops, Quick Launch of each profile and of All Users", L"shell link", true } }, L"" },
		{ "srum", EIGHT, 0, EIGHT,
		  { { EIGHT, L"Windows\\System32\\sru\\SRUDB.dat", L"ESE", true } }, L"" },
		{ "startup_folders", XP, 0, 0,
		  { { XP, L"Start Menu\\Programs\\Startup of each profile and of All Users", L"files", true } }, L"" },
		{ "thumbcache", XP, 0, 0,
		  { { XP, L"Thumbs.db in each folder", L"OLE compound file", false },
		    { VISTA, L"Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\Explorer\\thumbcache_*.db", L"CMMM, Vista and 7 layout", false, { 0x14, 0x15 } },
		    { EIGHT, L"the same folder, with iconcache_*.db", L"CMMM, Windows 8 and later layout", true, { 0x1E, 0x1F, 0x20 } } }, L"" },
		{ "typed_paths", VISTA, 0, 0,
		  { { VISTA, L"NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", L"registry values", true } }, L"" },
		{ "usbstor", XP, 0, 0,
		  { { XP, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", L"registry keys", true },
		    { EIGHT, L"…with the device properties' dates (first install, last connection, last removal)", L"registry keys, FILETIME", true } }, L"" },
		{ "userassist", XP, 0, 0,
		  { { XP, L"NTUSER.DAT …\\Explorer\\UserAssist\\{5E6AB780-…}, {75048700-…}", L"ROT13 names, 16-byte values", false },
		    { SEVEN, L"NTUSER.DAT …\\Explorer\\UserAssist\\{CEBFF5CD-…}, {F4E57C4B-…}", L"ROT13 names, 72-byte values", true } }, L"" },
		{ "users", XP, 0, XP,
		  { { XP, L"SAM\\SAM\\Domains\\Account\\Users", L"F and V records, hashes under RC4 (boot key)", true },
		    { TEN_1607, L"the same keys", L"F and V records, hashes under AES", true } }, L"" },
		{ "user_shell_folders", XP, 0, 0,
		  { { XP, L"NTUSER.DAT …\\Explorer\\User Shell Folders", L"registry values", true } }, L"" },
		{ "usn_journal", XP, 0, 0,
		  { { XP, L"$Extend\\$UsnJrnl:$J", L"USN_RECORD_V2", true },
		    { EIGHT, L"the same stream", L"USN_RECORD_V2, V3 (128-bit references)", true },
		    { EIGHT_1, L"the same stream", L"USN_RECORD_V2, V3, V4 (range tracking)", true } },
		  L"The journal exists only where it was created: always on the system volume from Vista on." },
		{ "web_client", XP, 0, 0,
		  { { XP, L"Internet Explorer 5 to 9: index.dat of History, cache, cookies, downloads", L"MSIE Cache File 5.2", true },
		    { EIGHT, L"Internet Explorer 10 and 11, Edge Legacy: …\\WebCache\\WebCacheV01.dat", L"ESE", true },
		    { TEN, L"…and Chromium browsers, Firefox: History, places.sqlite, session files", L"SQLite, SNSS, mozLz4", true } },
		  L"Chromium and Firefox depend on the browser installed, not on Windows." },
		{ "wmi", XP, 0, XP,
		  { { XP, L"Windows\\System32\\wbem\\Repository\\FS", L"CIM repository of Windows XP (INDEX.BTR, OBJECTS.DATA, MAPPING, in FS)", false },
		    { VISTA, L"Windows\\System32\\wbem\\Repository", L"CIM repository (INDEX.BTR, OBJECTS.DATA, MAPPING)", true } },
		  L"Windows XP keeps the repository in a FS subfolder (measured, SP1): collected, not converted until its layout is checked." },
		{ "word_wheel_query", SEVEN, 0, 0,
		  { { SEVEN, L"NTUSER.DAT …\\Explorer\\WordWheelQuery", L"MRUListEx and UTF-16 strings", true } },
		  L"Windows XP: Search Assistant\\ACMru, not collected." },
		{ "zone_identifiers", XP, 0, 0,
		  { { XP, L"<file>:Zone.Identifier (XP SP2)", L"alternate data stream, INI text", true } }, L"" },
	};
	return catalogue;
}

bool classicEventLogs(const WindowsVersion& version) {
	return version.build != 0 && version.build < VISTA;
}

const WindowsRelease& releaseOf(const WindowsVersion& version, bool& known) {
	const std::vector<WindowsRelease>& releases = windowsReleases();
	const WindowsRelease* found = nullptr;
	const WindowsRelease* last = nullptr;
	const WindowsRelease* first = nullptr;
	for (const WindowsRelease& r : releases) {
		if (r.server != version.server) continue;
		if (!first) first = &r;
		last = &r;
		if (version.build >= r.firstBuild) found = &r;
	}
	// The families are never empty: RELEASES holds clients and servers.
	if (!found) found = first;
	known = version.build >= first->firstBuild && version.build <= last->lastBuild;
	return *found;
}

const ArtefactEntry* artefactEntry(const std::string& key) {
	for (const ArtefactEntry& e : artefactCatalogue())
		if (key == e.key) return &e;
	return nullptr;
}

Availability availabilityOf(const std::string& key, const WindowsVersion& version) {
	const ArtefactEntry* entry = artefactEntry(key);
	if (!entry || version.build == 0) return Availability::Present;
	if (version.build < entry->sinceBuild) return Availability::AbsentFromThisVersion;
	if (entry->untilBuild != 0 && version.build >= entry->untilBuild) return Availability::AbsentFromThisVersion;
	return Availability::Present;
}

std::vector<std::string> absentAmong(const std::vector<std::string>& asked, const WindowsVersion& version) {
	std::vector<std::string> absent;
	for (const std::string& key : asked)
		if (availabilityOf(key, version) == Availability::AbsentFromThisVersion) absent.push_back(key);
	return absent;
}

bool expectedOn(const std::string& key, const WindowsVersion& version) {
	const ArtefactEntry* entry = artefactEntry(key);
	return entry && entry->expectedSinceBuild != 0 && !version.server && version.build >= entry->expectedSinceBuild
	    && availabilityOf(key, version) == Availability::Present;
}

PieceFormat pieceFormat(const std::string& key, unsigned signature) {
	const ArtefactEntry* entry = artefactEntry(key);
	if (entry)
		for (const ArtefactForm& form : entry->forms)
			for (unsigned known : form.signatures)
				if (known == signature) return PieceFormat{ form.decoded, &form };
	return PieceFormat{ false, nullptr };
}

bool undecodedOn(const std::string& key, const WindowsVersion& version) {
	const ArtefactEntry* entry = artefactEntry(key);
	if (!entry || version.build == 0 || availabilityOf(key, version) != Availability::Present) return false;
	bool converted = false, signedForms = false;
	for (const ArtefactForm& form : entry->forms) {
		converted = converted || form.decoded;
		signedForms = signedForms || !form.signatures.empty();
	}
	return converted && !signedForms && !formOf(*entry, version).decoded;
}

const ArtefactForm& formOf(const ArtefactEntry& entry, const WindowsVersion& version) {
	const ArtefactForm* form = &entry.forms.front();
	for (const ArtefactForm& f : entry.forms)
		if (version.build >= f.sinceBuild) form = &f;
	return *form;
}

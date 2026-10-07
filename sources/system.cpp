/*! \file
 *  \brief Offline reading of the system information (see system.h).
 */
#include "system.h"
#include "live_snapshot.h"
#include "running_machine.h"

namespace {

/*! Adds a value to the JSON only if it has a source.
*
* WHY OMIT RATHER THAN EMIT EMPTY. A key that is present but empty reads as a
* failed reading — the analyst cannot tell "the hive does not hold that value"
* from "WAC could not read it". The values that really are unreadable are, for
* their part, recorded in the log and in investigation.json.
*/
void addIfSet(Json& o, PCWSTR name, const std::wstring& value) {
	if (!value.empty()) o.add(name, Json::str(value));
}

/*! Translates PROCESSOR_ARCHITECTURE (the hive's text value) into a label.
* The hive stores the environment string, not the numeric constant: it is
* therefore converted to the same vocabulary as `os_architecture()`, so that the
* output stays comparable between versions of WAC.
*/
std::wstring architectureFromHive(const std::wstring& value) {
	if (value == L"AMD64") return os_architecture(PROCESSOR_ARCHITECTURE_AMD64);
	if (value == L"x86")   return os_architecture(PROCESSOR_ARCHITECTURE_INTEL);
	if (value == L"ARM64") return os_architecture(PROCESSOR_ARCHITECTURE_ARM64);
	if (value == L"ARM")   return os_architecture(PROCESSOR_ARCHITECTURE_ARM);
	if (value == L"IA64")  return os_architecture(PROCESSOR_ARCHITECTURE_IA64);
	// Unexpected value: returned as it is rather than hidden behind "unknown", so
	// that the case not covered stays visible.
	return value.empty() ? os_architecture(PROCESSOR_ARCHITECTURE_UNKNOWN) : value;
}

} // namespace

HRESULT snapshotSystemClock() {
	/* Measured live, without a trace. Kept in UTC; the local version is
	   derived at output with the SUSPECT's offset, the one its label carries,
	   as every other date of the collection. */
	FILETIME collectionTimeUtc = { 0, 0 };
	long long clockCorrection100ns = 0;
	bool bootFromKernel = false;
	log(3, L"🔈GetSystemTimeAsFileTime");
	GetSystemTimeAsFileTime(&collectionTimeUtc);

	/* Time of the last boot.
	 *
	 * SOURCE: the kernel, through
	 * NtQuerySystemInformation(SystemTimeOfDayInformation) — an in-memory query,
	 * with no WMI and no trace. It returns `BootTime`, the instant of the boot
	 * expressed in the CURRENT clock, and `BootTimeBias`, the total of the clock
	 * corrections applied since. `BootTime − BootTimeBias` is therefore what the
	 * clock showed at boot time: the same reference as the event logs and the
	 * logons, timestamped as they happened.
	 *
	 * WHAT WAS WRONG. The time was estimated by "current time minus
	 * GetTickCount64", which ignores clock adjustments. On the test VM, suspended
	 * then adjusted, it fell 3.5 s AFTER the real boot — and after the first
	 * logons, which check-json.py caught. Verified: BootTime 20:00:00.87 minus
	 * BootTimeBias 4.37 s gives 19:59:56.50, exactly the StartTime of the
	 * Kernel-General 12 event; the old estimate gave 20:00:00.
	 *
	 * The estimate remains as a fallback if the query fails, and BootTimeSource
	 * says which of the two served.
	 */
	log(3, L"🔈GetTickCount64");
	const ULONGLONG uptimeMs = GetTickCount64();
	const unsigned long long uptimeSeconds = uptimeMs / 1000ULL;
	const ULONGLONG now100ns = ticksFromFiletime(collectionTimeUtc);
	ULONGLONG boot100ns = 0;
	{
		struct TimeOfDay {                     // SYSTEM_TIMEOFDAY_INFORMATION
			LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias;
			ULONG TimeZoneId, Reserved;
			ULONGLONG BootTimeBias, SleepTimeBias;
		} timeOfDay = {};
		typedef LONG (WINAPI *NtQsiFn)(ULONG, PVOID, ULONG, PULONG);
		const NtQsiFn ntQsi = reinterpret_cast<NtQsiFn>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
		ULONG returned = 0;
		log(3, L"🔈NtQuerySystemInformation SystemTimeOfDayInformation");
		if (ntQsi && ntQsi(3 /*SystemTimeOfDayInformation*/, &timeOfDay, sizeof(timeOfDay), &returned) >= 0
		    && timeOfDay.BootTime.QuadPart > (LONGLONG)timeOfDay.BootTimeBias) {
			boot100ns = (ULONGLONG)timeOfDay.BootTime.QuadPart - timeOfDay.BootTimeBias;
			clockCorrection100ns = (long long)timeOfDay.BootTimeBias;
			bootFromKernel = true;
		}
		else
			log(2, L"🔥NtQuerySystemInformation: boot time estimated through GetTickCount64");
	}
	if (!bootFromKernel && now100ns > uptimeMs * 10000ULL)
		boot100ns = now100ns - uptimeMs * 10000ULL;
	if (boot100ns)
		log(2, L"❇️Last boot (UTC) : " + timeToIso8601Utc(filetimeFromTicks(boot100ns)));
	else
		log(2, L"🔥Uptime inconsistent with the system time: boot time not computed");

	// Raw values, in 100 ns ticks: nothing lost between observation and conversion.
	Json clock = Json::obj();
	clock.add(L"CollectionTime100ns", Json::num((unsigned long long)now100ns));
	if (boot100ns) clock.add(L"BootTime100ns", Json::num((unsigned long long)boot100ns));
	clock.add(L"BootTimeFromKernel", Json::num(bootFromKernel ? 1 : 0));
	clock.add(L"ClockCorrection100ns", Json::num(clockCorrection100ns));
	clock.add(L"UptimeSeconds", Json::num(uptimeSeconds));
	return writeLiveSnapshot("system-clock.json", clock, L"system clock and boot time");

}

HRESULT SystemInfo::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Operating System :");
	log(0, L"*******************************************************************************************************************");
	log(1, L"➕System");

	/*******************************************************************
	* 1. Identity of the machine — SYSTEM hive
	*******************************************************************/
	if (conf.CurrentControlSet) {
		log(3, L"🔈getRegSzValue ComputerName");
		getRegSzValue(conf.CurrentControlSet, L"Control\\ComputerName\\ComputerName",
		              L"ComputerName", &netbiosName);

		/* DNS name. `Hostname` is the name in force, `NV Hostname` the one that was
		   persisted: they differ only between a rename and the next reboot, a
		   case that deserves to be visible. */
		log(3, L"🔈getRegSzValue Tcpip Hostname");
		if (getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
		                  L"Hostname", &computerName) != ERROR_SUCCESS)
			getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
			              L"NV Hostname", &computerName);
		if (computerName.empty()) computerName = netbiosName;

		log(3, L"🔈getRegSzValue Tcpip Domain");
		if (getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
		                  L"Domain", &domainName) != ERROR_SUCCESS || domainName.empty())
			getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
			              L"NV Domain", &domainName);
		if (domainName.empty()) domainName = L"WORKGROUP";

		std::wstring archiBrute;
		log(3, L"🔈getRegSzValue PROCESSOR_ARCHITECTURE");
		getRegSzValue(conf.CurrentControlSet, L"Control\\Session Manager\\Environment",
		              L"PROCESSOR_ARCHITECTURE", &archiBrute);
		osArchitecture = architectureFromHive(archiBrute);

		log(2, L"❇️Computer name : " + computerName);
		log(2, L"❇️Domain name : " + domainName);
	}
	else
		log(2, L"🔥CurrentControlSet unavailable: machine identity not read");

	/*******************************************************************
	* 2. Installation — SOFTWARE hive
	*******************************************************************/
	if (conf.Software) {
		PCWSTR key = L"Microsoft\\Windows NT\\CurrentVersion";

		log(3, L"🔈getRegSzValue ProductName");
		getRegSzValue(conf.Software, key, L"ProductName",            &productNameRaw);
		getRegSzValue(conf.Software, key, L"EditionID",              &editionId);
		getRegSzValue(conf.Software, key, L"InstallationType",       &installationType);
		getRegSzValue(conf.Software, key, L"BuildLabEx",             &buildLabEx);
		getRegSzValue(conf.Software, key, L"CSDVersion",             &servicePack);
		getRegSzValue(conf.Software, key, L"RegisteredOwner",        &registeredOwner);
		getRegSzValue(conf.Software, key, L"RegisteredOrganization", &registeredOrganization);
		getRegSzValue(conf.Software, key, L"ProductId",              &productId);
		getRegSzValue(conf.Software, key, L"SystemRoot",             &systemRoot);

		/* DisplayVersion ("23H2") replaced ReleaseId ("2009", frozen) from version
		   20H2 on: the first one available is taken. */
		if (getRegSzValue(conf.Software, key, L"DisplayVersion", &displayVersion) != ERROR_SUCCESS)
			getRegSzValue(conf.Software, key, L"ReleaseId", &displayVersion);

		/* Version number. CurrentMajorVersionNumber / CurrentMinorVersionNumber
		   exist only from Windows 10 on; before that, only the `CurrentVersion`
		   string ("6.1") carries the information. */
		std::wstring build;
		getRegSzValue(conf.Software, key, L"CurrentBuildNumber", &build);
		if (build.empty()) getRegSzValue(conf.Software, key, L"CurrentBuild", &build);

		DWORD major = 0, minor = 0;
		if (getRegDwordValue(conf.Software, key, L"CurrentMajorVersionNumber", &major) == ERROR_SUCCESS) {
			getRegDwordValue(conf.Software, key, L"CurrentMinorVersionNumber", &minor);
			version = std::to_wstring(major) + L"." + std::to_wstring(minor);
		}
		else
			getRegSzValue(conf.Software, key, L"CurrentVersion", &version);
		if (!build.empty()) version += (version.empty() ? L"" : L".") + build;

		// UBR = monthly revision: distinguishes two machines of the same build.
		DWORD ubr = 0;
		if (getRegDwordValue(conf.Software, key, L"UBR", &ubr) == ERROR_SUCCESS && !version.empty())
			version += L"." + std::to_wstring(ubr);

		/* Correction of the OS label (see the file header). Windows 11 declares
		   itself as "Windows 10" in ProductName; the build is the only
		   discriminant. */
		osName = productNameRaw;
		const unsigned long buildNumber = build.empty() ? 0UL : wcstoul(build.c_str(), nullptr, 10);
		if (buildNumber >= 22000 && osName.find(L"Windows 10") != std::wstring::npos) {
			osName.replace(osName.find(L"Windows 10"), 10, L"Windows 11");
			log(2, L"❇️ProductName corrected: build " + build + L" => " + osName);
		}

		/* Installation date. `InstallTime` (REG_QWORD, UTC FILETIME) has existed
		   since Windows 8 and is precise; `InstallDate` (REG_DWORD, Unix time
		   UTC) is the fallback for earlier systems. */
		unsigned long long installTime = 0;
		if (getRegQwordValue(conf.Software, key, L"InstallTime", &installTime) == ERROR_SUCCESS
		    && installTime != 0) {
			installDateUtc.dwLowDateTime  = (DWORD)(installTime & 0xFFFFFFFFULL);
			installDateUtc.dwHighDateTime = (DWORD)(installTime >> 32);
		}
		else {
			DWORD installDate = 0;
			if (getRegDwordValue(conf.Software, key, L"InstallDate", &installDate) == ERROR_SUCCESS
			    && installDate != 0) {
				installDateUtc = unixToFiletime(installDate);
				installDatePrecision = Precision::Second;   // a Unix time counts seconds
			}
		}

		// Unique identifier of the installation: serves to correlate artefacts coming
		// from different machines (telemetry, application logs).
		log(3, L"🔈getRegSzValue MachineGuid");
		getRegSzValue(conf.Software, L"Microsoft\\Cryptography", L"MachineGuid", &machineGuid);

		log(2, L"❇️OS : " + osName + L" " + version);
	}
	else
		log(2, L"🔥SOFTWARE hive unavailable: installation information not read");

	readSettings();

	/*******************************************************************
	* 3. Instant of the collection and boot time — observed live by
	*    snapshotSystemClock, read back from the snapshot
	*******************************************************************/
	Json clock = Json::null();
	if (readLiveSnapshot("system-clock.json", clock) == ERROR_SUCCESS) {
		long long collection = 0, boot = 0, correction = 0, uptime = 0, kernel = 0;
		if (snapshotInteger(clock, L"CollectionTime100ns", collection) && collection > 0)
			collectionTimeUtc = filetimeFromTicks(collection);
		if (snapshotInteger(clock, L"BootTime100ns", boot) && boot > 0)
			lastBootUpTimeUtc = filetimeFromTicks(boot);
		if (snapshotInteger(clock, L"UptimeSeconds", uptime) && uptime >= 0) uptimeSeconds = (unsigned long long)uptime;
		if (snapshotInteger(clock, L"ClockCorrection100ns", correction)) clockCorrection100ns = correction;
		if (snapshotInteger(clock, L"BootTimeFromKernel", kernel)) bootFromKernel = kernel != 0;
	}
	else
		log(2, L"🔥System clock snapshot absent: collection and boot times not published");
	return ERROR_SUCCESS;
}

void SystemInfo::readSettings() {
	/* The settings that change how the other artefacts read, each for a reason:
	   last access dates (NTFS), 8.3 names, Prefetch on or off, page file and
	   crash dumps, the control sets, remote desktop, the Windows timeline, the
	   last user who logged on. Values as stored; absent ones are not emitted. */
	struct Wanted { const wchar_t* hive; const wchar_t* key; std::vector<const wchar_t*> names; };
	const Wanted WANTED[] = {
		{ L"SYSTEM", L"Control\\FileSystem", { L"NtfsDisableLastAccessUpdate", L"NtfsDisable8dot3NameCreation",
		  L"LongPathsEnabled", L"NtfsDisableCompression", L"NtfsDisableEncryption", L"DisableDeleteNotification" } },
		{ L"SYSTEM", L"Control\\Session Manager\\Memory Management", { L"ClearPageFileAtShutdown", L"PagingFiles", L"ExistingPageFiles" } },
		{ L"SYSTEM", L"Control\\Session Manager\\Memory Management\\PrefetchParameters", { L"EnablePrefetcher", L"EnableSuperfetch" } },
		{ L"SYSTEM", L"Control\\CrashControl", { L"CrashDumpEnabled", L"DumpFile" } },
		{ L"SYSTEM", L"Control\\Terminal Server", { L"fDenyTSConnections" } },
		{ L"SYSTEM", L"Control\\Terminal Server\\WinStations\\RDP-Tcp", { L"UserAuthentication", L"SecurityLayer", L"PortNumber" } },
		{ L"SYSTEM", L"Select", { L"Current", L"Default", L"LastKnownGood", L"Failed" } },
		{ L"SOFTWARE", L"Policies\\Microsoft\\Windows\\System", { L"EnableActivityFeed", L"PublishUserActivities", L"UploadUserActivities" } },
		{ L"SOFTWARE", L"Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI",
		  { L"LastLoggedOnUser", L"LastLoggedOnSAMUser", L"LastLoggedOnDisplayName", L"LastLoggedOnUserSID" } },
	};
	for (const Wanted& w : WANTED) {
		// Select is at the root of SYSTEM; the other SYSTEM keys under CurrentControlSet.
		const ORHKEY root = std::wstring(w.hive) == L"SOFTWARE" ? conf.Software
		                  : std::wstring(w.key) == L"Select" ? conf.System : conf.CurrentControlSet;
		if (!root) continue;
		for (const wchar_t* name : w.names) {
			DWORD type = 0, size = 0;
			if (ORGetValue(root, w.key, name, &type, nullptr, &size) != ERROR_SUCCESS) continue;
			std::vector<BYTE> data(size);
			if (ORGetValue(root, w.key, name, &type, data.data(), &size) != ERROR_SUCCESS) continue;
			data.resize(size);
			settings.push_back({ w.hive, w.key, name, registryValueToJson(type, data) });
			if (std::wstring(name) == L"NtfsDisableLastAccessUpdate" && type == REG_DWORD && size >= 4) {
				DWORD v;
				memcpy(&v, data.data(), 4);
				ntfsLastAccessUpdated = (v & 1) == 0;
			}
		}
	}
	// The last orderly shutdown: a FILETIME, binary.
	std::vector<BYTE> shutdown;
	if (conf.CurrentControlSet && getRegBinaryValue(conf.CurrentControlSet, L"Control\\Windows", L"ShutdownTime", shutdown) == ERROR_SUCCESS
	    && shutdown.size() >= sizeof(FILETIME))
		memcpy(&shutdownTimeUtc, shutdown.data(), sizeof(FILETIME));
}

HRESULT SystemInfo::toJson() {
	log(3, L"🔈system toJson");
	Json o = Json::obj();

	addIfSet(o, L"ComputerName",    computerName);
	addIfSet(o, L"NetbiosName",     netbiosName);
	addIfSet(o, L"DomainName",      domainName);
	addIfSet(o, L"OsArchitecture",  osArchitecture);

	addIfSet(o, L"OsName",          osName);
	/* The raw value is repeated only when it DIFFERS from the label kept: it is
	   then the trace of the Windows 10 / Windows 11 correction, which must stay
	   verifiable. Otherwise it would be a duplicate. */
	if (!productNameRaw.empty() && productNameRaw != osName)
		o.add(L"ProductNameRaw", Json::str(productNameRaw));
	addIfSet(o, L"Version",                version);
	addIfSet(o, L"DisplayVersion",         displayVersion);
	addIfSet(o, L"EditionId",              editionId);
	addIfSet(o, L"InstallationType",       installationType);
	addIfSet(o, L"BuildLabEx",             buildLabEx);
	addIfSet(o, L"ServicePack",            servicePack);
	addIfSet(o, L"RegisteredOwner",        registeredOwner);
	addIfSet(o, L"RegisteredOrganization", registeredOrganization);
	addIfSet(o, L"ProductId",              productId);
	addIfSet(o, L"SystemRoot",             systemRoot);
	addIfSet(o, L"MachineGuid",            machineGuid);
	// installDateUtc is in UTC: the local version must be CONVERTED, not merely
	// relabelled (a defect caught by the harness's cross-check).
	addIfSet(o, L"InstallDate",            utcTimeToIso8601Local(installDateUtc, installDatePrecision));
	addIfSet(o, L"InstallDateUtc",         timeToIso8601Utc(installDateUtc, installDatePrecision));

	addIfSet(o, L"LocalDateTime",     utcTimeToIso8601Local(collectionTimeUtc));
	addIfSet(o, L"LocalDateTimeUtc",  timeToIso8601Utc(collectionTimeUtc));
	addIfSet(o, L"LastBootUpTime",    utcTimeToIso8601Local(lastBootUpTimeUtc));
	addIfSet(o, L"LastBootUpTimeUtc", timeToIso8601Utc(lastBootUpTimeUtc));
	o.add(L"UptimeSeconds",     Json::num(uptimeSeconds));
	// The source goes along with the value: an estimate must not read as a
	// measurement.
	o.add(L"BootTimeSource",    Json::str(bootFromKernel
		? L"kernel (SystemTimeOfDayInformation: BootTime - BootTimeBias), "
		  L"the time the clock showed at boot"
		: L"estimated: current time minus GetTickCount64; ignores the clock adjustments "
		  L"made since the boot"));
	/* In milliseconds, sign included: emitted only if there was a correction.
	   Positive: the clock was moved forward since the boot. */
	if (bootFromKernel && clockCorrection100ns != 0)
		o.add(L"ClockAdjustedSinceBootMs", Json::num(clockCorrection100ns / 10000LL));

	addDate(o, L"ShutdownTime", shutdownTimeUtc);
	if (ntfsLastAccessUpdated) o.add(L"NtfsLastAccessUpdated", Json::boolean(*ntfsLastAccessUpdated));
	if (!settings.empty()) {
		Json list = Json::arr();
		for (const Setting& st : settings) {
			Json e = Json::obj();
			e.add(L"Hive", Json::str(st.hive));
			e.add(L"Key", Json::str(st.key));
			e.add(L"Name", Json::str(st.name));
			e.add(L"Value", st.value);
			list.push(std::move(e));
		}
		o.add(L"Settings", std::move(list));
	}

	/* Time zone: the SUSPECT's when the hive could be read. The TimeZoneSource
	   field says which of the two origins served — without it, an unexpected
	   offset would be indistinguishable from a reading error. */
	if (conf.timeZone.valid) {
		addIfSet(o, L"CurrentTimeZoneId",      conf.timeZone.keyName);
		/* The seasonal label is stored as a MUI reference ("@tzres.dll,-301") on
		   recent systems. `CurrentTimeZoneId` ("Romance Standard Time") remains
		   the canonical identifier and is enough to interpret local times; the
		   reference is kept for traceability, without being presented as a
		   name. */
		const std::wstring caption = conf.timeZone.daylightInEffect
		                           ? conf.timeZone.daylightName
		                           : conf.timeZone.standardName;
		if (!caption.empty()) {
			if (isMuiReference(caption))
				o.add(L"CurrentTimeZoneCaptionResource", Json::str(caption));
			else
				o.add(L"CurrentTimeZoneCaption", Json::str(caption));
		}
		o.add(L"CurrentBias",       Json::num((long long)conf.timeZone.activeBiasMinutes));
		o.add(L"DaylightInEffect",  Json::boolean(conf.timeZone.daylightInEffect));
		o.add(L"TimeZoneSource",    Json::str(L"SYSTEM hive of the examined machine"));
	}
	else {
		/* Fallback: the running examined machine, as observed live in the
		   collection (running_machine.h) — never the machine that converts. */
		const RunningMachine& machine = runningMachine();
		if (machine.timeZoneId != TIME_ZONE_ID_INVALID) {
			const TIME_ZONE_INFORMATION& tz = machine.timeZone;
			const bool wasSummer = (machine.timeZoneId == TIME_ZONE_ID_DAYLIGHT);
			o.add(L"CurrentTimeZoneCaption",
			      Json::str(wasSummer ? tz.DaylightName : tz.StandardName));
			o.add(L"CurrentBias",      Json::num((long long)(tz.Bias
			                           + (wasSummer ? tz.DaylightBias : tz.StandardBias))));
			o.add(L"DaylightInEffect", Json::boolean(wasSummer));
			o.add(L"TimeZoneSource",   Json::str(L"examined machine observed live (SYSTEM hive unreadable)"));
		}
	}

	/* ANSI code page used to decode the non-Unicode text of the artefacts,
	   and where it comes from — as for the time zone. */
	if (conf.ansiCodePage) {
		o.add(L"AnsiCodePage",       Json::num((unsigned long long)conf.ansiCodePage));
		o.add(L"AnsiCodePageSource", Json::str(L"SYSTEM hive of the examined machine"));
	}
	else if (runningMachine().ansiCodePage) {
		o.add(L"AnsiCodePage",       Json::num((unsigned long long)runningMachine().ansiCodePage));
		o.add(L"AnsiCodePageSource", Json::str(L"examined machine observed live (SYSTEM hive unreadable)"));
	}

	return writeJsonFile("OperatingSystem.json", o);
}

void SystemInfo::clear() {
	log(3, L"🔈system clear");
}

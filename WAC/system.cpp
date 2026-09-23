/*! \file
 *  \brief Offline reading of the system information (see system.h).
 */
#include "system.h"

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

//! Converts a Unix time (seconds since 1970, UTC) to a FILETIME.
FILETIME unixToFiletime(unsigned long long seconds) {
	const unsigned long long OFFSET_1601_1970 = 11644473600ULL;
	const unsigned long long cent_ns = (seconds + OFFSET_1601_1970) * 10000000ULL;
	FILETIME ft = { (DWORD)(cent_ns & 0xFFFFFFFFULL), (DWORD)(cent_ns >> 32) };
	return ft;
}

} // namespace

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
			    && installDate != 0)
				installDateUtc = unixToFiletime(installDate);
		}

		// Unique identifier of the installation: serves to correlate artefacts coming
		// from different machines (telemetry, application logs).
		log(3, L"🔈getRegSzValue MachineGuid");
		getRegSzValue(conf.Software, L"Microsoft\\Cryptography", L"MachineGuid", &machineGuid);

		log(2, L"❇️OS : " + osName + L" " + version);
	}
	else
		log(2, L"🔥SOFTWARE hive unavailable: installation information not read");

	/*******************************************************************
	* 3. Instant of the collection — measured live, without a trace
	*******************************************************************/
	log(3, L"🔈GetSystemTime");
	GetSystemTime(&localDateTimeUtc);
	TIME_ZONE_INFORMATION timezone = { 0 };
	log(3, L"🔈GetTimeZoneInformation");
	if (GetTimeZoneInformation(&timezone) != TIME_ZONE_ID_INVALID) {
		log(3, L"🔈SystemTimeToTzSpecificLocalTime");
		SystemTimeToTzSpecificLocalTime(&timezone, &localDateTimeUtc, &localDateTime);
	}
	else
		log(2, L"🔥GetTimeZoneInformation", TIME_ZONE_ID_UNKNOWN);

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
	uptimeSeconds = uptimeMs / 1000ULL;
	FILETIME nowUtc = { 0, 0 };
	SystemTimeToFileTime(&localDateTimeUtc, &nowUtc);
	const ULONGLONG now100ns = ((ULONGLONG)nowUtc.dwHighDateTime << 32)
	                                | nowUtc.dwLowDateTime;
	ULONGLONG boot100ns = 0;
	{
		struct TimeOfDay {                     // SYSTEM_TIMEOFDAY_INFORMATION
			LARGE_INTEGER BootTime, CurrentTime, TimeZoneBias;
			ULONG TimeZoneId, Reserved;
			ULONGLONG BootTimeBias, SleepTimeBias;
		} hdj = {};
		typedef LONG (WINAPI *NtQsiFn)(ULONG, PVOID, ULONG, PULONG);
		const NtQsiFn ntQsi = reinterpret_cast<NtQsiFn>(
			GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
		ULONG returned = 0;
		log(3, L"🔈NtQuerySystemInformation SystemTimeOfDayInformation");
		if (ntQsi && ntQsi(3 /*SystemTimeOfDayInformation*/, &hdj, sizeof(hdj), &returned) >= 0
		    && hdj.BootTime.QuadPart > (LONGLONG)hdj.BootTimeBias) {
			boot100ns = (ULONGLONG)hdj.BootTime.QuadPart - hdj.BootTimeBias;
			clockCorrection100ns = (long long)hdj.BootTimeBias;
			bootFromKernel = true;
		}
		else
			log(2, L"🔥NtQuerySystemInformation: boot time estimated through GetTickCount64");
	}
	if (!bootFromKernel && now100ns > uptimeMs * 10000ULL)
		boot100ns = now100ns - uptimeMs * 10000ULL;
	if (boot100ns) {
		FILETIME bootUtc = { (DWORD)(boot100ns & 0xFFFFFFFFULL), (DWORD)(boot100ns >> 32) };
		FileTimeToSystemTime(&bootUtc, &lastBootUpTimeUtc);
		bootFraction100ns = (long)(boot100ns % 10000000ULL);
		FILETIME bootLocal = { 0, 0 };
		if (utcToSuspectLocal(bootUtc, &bootLocal))
			FileTimeToSystemTime(&bootLocal, &lastBootUpTime);
		log(2, L"❇️Last boot (UTC) : " + timeToIso8601(lastBootUpTimeUtc, true, bootFraction100ns));
	}
	else
		log(2, L"🔥Uptime inconsistent with the system time: boot time not computed");

	return ERROR_SUCCESS;
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
	addIfSet(o, L"InstallDate",            utcTimeToIso8601Local(installDateUtc));
	addIfSet(o, L"InstallDateUtc",         timeToIso8601Utc(installDateUtc));

	o.add(L"LocalDateTime",     Json::str(timeToIso8601(localDateTime, false)));
	o.add(L"LocalDateTimeUtc",  Json::str(timeToIso8601(localDateTimeUtc, true)));
	addIfSet(o, L"LastBootUpTime",    timeToIso8601(lastBootUpTime, false, bootFraction100ns));
	addIfSet(o, L"LastBootUpTimeUtc", timeToIso8601(lastBootUpTimeUtc, true, bootFraction100ns));
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
		/* Fallback: the running machine. Right in a live collection, wrong on an
		   image mounted elsewhere — hence the explicit mention. */
		TIME_ZONE_INFORMATION tz = { 0 };
		const DWORD r = GetTimeZoneInformation(&tz);
		if (r != TIME_ZONE_ID_INVALID) {
			const bool wasSummer = (r == TIME_ZONE_ID_DAYLIGHT);
			o.add(L"CurrentTimeZoneCaption",
			      Json::str(wasSummer ? tz.DaylightName : tz.StandardName));
			o.add(L"CurrentBias",      Json::num((long long)(tz.Bias
			                           + (wasSummer ? tz.DaylightBias : tz.StandardBias))));
			o.add(L"DaylightInEffect", Json::boolean(wasSummer));
		}
		o.add(L"TimeZoneSource", Json::str(L"running machine (SYSTEM hive unreadable) "
		                                   L"— only valid if the collection is live"));
	}

	/* ANSI code page used to decode the non-Unicode text of the artefacts,
	   and where it comes from — as for the time zone. */
	if (conf.ansiCodePage) {
		o.add(L"AnsiCodePage",       Json::num((unsigned long long)conf.ansiCodePage));
		o.add(L"AnsiCodePageSource", Json::str(L"SYSTEM hive of the examined machine"));
	}
	else {
		o.add(L"AnsiCodePage",       Json::num((unsigned long long)GetACP()));
		o.add(L"AnsiCodePageSource", Json::str(L"running machine (SYSTEM hive unreadable) "
		                                       L"— only valid if the collection is live"));
	}

	return writeJsonFile("OperatingSystem.json", o);
}

void SystemInfo::clear() {
	log(3, L"🔈system clear");
}

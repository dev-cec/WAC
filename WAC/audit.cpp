/*! \file
 *  \brief Implementation of the investigation log (see audit.h).
 */
#include "audit.h"
#include <vector>
#include "tools.h"

namespace Footprint {
const wchar_t* VOLUME_BRUT  = L"Raw reading of the volume (\\\\.\\C:): no file access, "
                              L"hence no timestamp of the target changed. An object-access audit, "
                              L"if it is enabled, may log the opening of the volume.";
const wchar_t* HIVE_COPY  = L"Opening of a hive COPIED onto the collection medium: "
                              L"the original hive is left untouched.";
const wchar_t* FILE_COPY = L"Reading of an extracted artefact file (a copy on the collection "
                              L"medium): no access to the original, no timestamp changed, "
                              L"no service of the examined system solicited.";
const wchar_t* HIVE_PATCH  = L"Change of 8 bytes in the base block of a COPIED hive "
                              L"(alignment of the sequence numbers). The original is not "
                              L"modified; the fingerprint before the patch is recorded.";
const wchar_t* HIVE_REPLAY  = L"Application of the transaction logs to the COPIED hive, "
                              L"never to the original one. The original content of every replaced page "
                              L"is kept in an undo journal: the raw copy stays "
                              L"reconstructible a l'octet.";
const wchar_t* SCM          = L"A single read-only enumeration of the service manager "
                              L"(EnumServicesStatusExW), to read the current state. No "
                              L"handle opened service by service: the configuration comes "
                              L"from the copied SYSTEM hive.";
const wchar_t* PROCESSES    = L"Enumeration of the processes: opening of process and token "
                              L"handles (auditable if the policy provides for it).";
const wchar_t* SESSIONS     = L"Query of the open sessions (LSA / Terminal Services): "
                              L"solicits LSASS, without modifying any artefact.";
const wchar_t* USB_WRITE = L"Write to the collection medium only. No write "
                              L"to the examined system.";
} // namespace Footprint

namespace {

//! One recorded operation.
struct Operation {
	unsigned     sequence = 0;
	std::wstring timestampUtc;
	std::wstring timestampLocal;
	std::wstring operation;
	std::wstring target;
	std::wstring result;      //!< "OK", or the code and its message
	std::wstring footprint;
};

std::vector<Operation> g_operations;
unsigned     g_sequence      = 0;
std::wstring g_startUtc, g_startLocal;
FILETIME     g_start         = { 0, 0 };
std::wstring g_commandLine;
std::wstring g_machine, g_user, g_sid, g_timeZone;
long         g_biasMinutes  = 0;
bool         g_elevated         = false;

/*! Current timestamp, in UTC and in the suspect's local time: the same time
 *  zone as every other local date of the collection (the running machine's
 *  until the suspect's SYSTEM hive is read). */
void now(std::wstring& utc, std::wstring& local, FILETIME* nowFiletime = nullptr) {
	FILETIME ft = { 0, 0 };
	GetSystemTimeAsFileTime(&ft);
	utc = timeToIso8601Utc(ft);
	local = utcTimeToIso8601Local(ft);
	if (nowFiletime) *nowFiletime = ft;
}

//! Context of the machine and of the operator at collection time.
void readContext() {
	wchar_t buffer[512] = L"";
	DWORD size = 512;
	if (GetComputerNameW(buffer, &size)) g_machine = buffer;

	size = 512;
	if (GetUserNameW(buffer, &size)) g_user = buffer;

	// SID of the account WAC runs as: identifies the operator without ambiguity,
	// even if the account name has changed since.
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		DWORD required = 0;
		GetTokenInformation(token, TokenUser, NULL, 0, &required);
		if (required) {
			std::vector<BYTE> sidBuffer(required);
			if (GetTokenInformation(token, TokenUser, sidBuffer.data(), required, &required)) {
				PTOKEN_USER tu = reinterpret_cast<PTOKEN_USER>(sidBuffer.data());
				// The SID lies inside the buffer: it bounds the read.
				const BYTE* sid = static_cast<const BYTE*>(tu->User.Sid);
				if (sid >= sidBuffer.data() && sid < sidBuffer.data() + sidBuffer.size())
					g_sid = sidToText(sid, (size_t)(sidBuffer.data() + sidBuffer.size() - sid));
			}
		}
		TOKEN_ELEVATION elevation = { 0 };
		DWORD length = 0;
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length))
			g_elevated = elevation.TokenIsElevated != 0;
		CloseHandle(token);
	}

	// Time zone of the EXAMINED MACHINE: indispensable to reinterpret the local
	// dates of the artefacts (the suspect's time zone, not the analyst's).
	TIME_ZONE_INFORMATION tz = { 0 };
	const DWORD type = GetTimeZoneInformation(&tz);
	if (type != TIME_ZONE_ID_INVALID) {
		g_timeZone = (type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightName : tz.StandardName;
		// Bias is in minutes to ADD to the local time to obtain UTC.
		g_biasMinutes = tz.Bias + ((type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightBias : tz.StandardBias);
	}
}

} // namespace

void auditInit(const std::vector<std::wstring>& args) {
	g_operations.clear();
	g_sequence = 0;
	now(g_startUtc, g_startLocal, &g_start);

	g_commandLine.clear();
	for (size_t i = 0; i < args.size(); ++i) {
		if (i) g_commandLine += L" ";
		g_commandLine += args[i];
	}

	readContext();
}

void auditRecord(const std::wstring& operation, const std::wstring& target,
                 HRESULT result, const wchar_t* footprint) {
	Operation o;
	o.sequence = ++g_sequence;
	now(o.timestampUtc, o.timestampLocal);
	o.operation = operation;
	o.target     = target;
	/* S_FALSE (1) means "succeeded, but only partly" — typically hives that are
	   absent and tolerated by the extraction. `getErrorMessage()` translates it
	   as the Win32 code 1, "Incorrect function", which had a partial success
	   read as a breakdown in the audit log. In a piece of evidence, a badly
	   qualified result is worth less than no result. */
	if (result == ERROR_SUCCESS)
		o.result = L"OK";
	else if (result == S_FALSE)
		o.result = L"PARTIAL (see the collection log for the detail)";
	else
		o.result = L"0x" + to_hex(result) + L" " + getErrorMessage(result);
	o.footprint = footprint ? footprint : L"";
	g_operations.push_back(std::move(o));
}

Json auditContext() {
	Json root = Json::obj();

	Json tool = Json::obj();
	tool.add(L"Name",        Json::str(L"WAC"));
	tool.add(L"CommandLine", Json::str(g_commandLine));
	tool.add(L"BuildDate",   Json::str(decodeText(__DATE__) + L" " + decodeText(__TIME__)));
	root.add(L"Tool", std::move(tool));

	Json host = Json::obj();
	host.add(L"ComputerName", Json::str(g_machine));
	host.add(L"SystemDrive",  Json::str(conf.systemDrive));

	/* TWO time zones, and that is deliberate.
	   - SuspectTimeZone: read in the examined SYSTEM hive. It is THE one used to
	   format the artefacts' local times, and therefore the only valid
	   reference to interpret a local date.
	   - CollectionHostTimeZone: that of the machine that ran WAC.
	   In a live collection the two coincide. A DIVERGENCE is a signal: an image
	   analysed on another machine, or a time zone changed since the collection —
	   in both cases the analyst must know. */
	Json suspect = Json::obj();
	if (conf.timeZone.valid) {
		suspect.add(L"KeyName",      Json::str(conf.timeZone.keyName));
		suspect.add(L"StandardName", Json::str(conf.timeZone.standardName));
		suspect.add(L"DaylightName", Json::str(conf.timeZone.daylightName));
		// Minutes to ADD to UTC to obtain the local time: +120 = UTC+02:00.
		// The sign is verifiable in this very file (StartLocal = StartUtc + offset).
		suspect.add(L"UtcOffsetMinutes", Json::num((long long)-conf.timeZone.activeBiasMinutes));
		suspect.add(L"Source", Json::str(L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"));
	}
	else {
		suspect.add(L"Source", Json::str(L"not read: fallback on the collecting machine's time zone"));
	}
	host.add(L"SuspectTimeZone", std::move(suspect));

	Json collector = Json::obj();
	collector.add(L"TimeZone",         Json::str(g_timeZone));
	collector.add(L"UtcOffsetMinutes", Json::num((long long)-g_biasMinutes));
	host.add(L"CollectionHostTimeZone", std::move(collector));

	if (conf.timeZone.valid && conf.timeZone.activeBiasMinutes != g_biasMinutes)
		host.add(L"TimeZoneMismatch", Json::boolean(true));

	root.add(L"Host", std::move(host));

	Json operator_ = Json::obj();
	operator_.add(L"User",     Json::str(g_user));
	operator_.add(L"Sid",      Json::str(g_sid));
	operator_.add(L"Elevated", Json::boolean(g_elevated));
	root.add(L"Operator", std::move(operator_));

	return root;
}

std::wstring auditStartUtc()   { return g_startUtc; }
std::wstring auditStartLocal() { return g_startLocal; }

HRESULT auditWrite() {
	std::wstring finUtc, finLocal;
	FILETIME end = { 0, 0 };
	now(finUtc, finLocal, &end);

	const ULONGLONG d = ((ULONGLONG)g_start.dwHighDateTime << 32) | g_start.dwLowDateTime;
	const ULONGLONG f = ((ULONGLONG)end.dwHighDateTime << 32) | end.dwLowDateTime;
	const ULONGLONG duration = (f > d) ? (f - d) / 10000000ULL : 0ULL;   // 100 ns -> s

	// The SAME context as the exhibit manifest: one single construction, so that
	// two documents of the same collection cannot contradict each other.
	Json root = auditContext();

	Json collection = Json::obj();
	collection.add(L"StartUtc",        Json::str(g_startUtc));
	collection.add(L"StartLocal",      Json::str(g_startLocal));
	collection.add(L"EndUtc",          Json::str(finUtc));
	collection.add(L"EndLocal",        Json::str(finLocal));
	collection.add(L"DurationSeconds", Json::num((unsigned long long)duration));
	collection.add(L"OperationCount",  Json::num((unsigned long long)g_operations.size()));
	root.add(L"Collection", std::move(collection));

	Json operations = Json::arr();
	for (const Operation& o : g_operations) {
		Json j = Json::obj();
		j.add(L"Seq",            Json::num((unsigned long long)o.sequence));
		j.add(L"TimestampUtc",   Json::str(o.timestampUtc));
		j.add(L"TimestampLocal", Json::str(o.timestampLocal));
		j.add(L"Operation",      Json::str(o.operation));
		j.add(L"Target",         Json::str(o.target));
		j.add(L"Result",         Json::str(o.result));
		j.add(L"Footprint",      Json::str(o.footprint));
		operations.push(std::move(j));
	}
	root.add(L"Operations", std::move(operations));

	return writeJsonFile("investigation.json", root);
}

/*  audit.cpp — voir audit.h. */
#include "audit.h"
#include <vector>
#include <sddl.h>
#include "tools.h"

namespace Footprint {
const wchar_t* VOLUME_BRUT  = L"Lecture brute du volume (\\\\.\\C:) : aucun acces fichier, "
                              L"donc aucun horodatage de la cible modifie. Un audit d'acces aux "
                              L"objets, s'il est actif, peut journaliser l'ouverture du volume.";
const wchar_t* HIVE_COPY  = L"Ouverture d'une ruche COPIEE sur le support de collecte : "
                              L"la ruche d'origine n'est pas touchee.";
const wchar_t* FILE_COPY = L"Lecture d'un fichier d'artefact extrait (copie sur le support "
                              L"de collecte) : aucun acces a l'original, aucun horodatage modifie, "
                              L"aucun service du systeme examine sollicite.";
const wchar_t* HIVE_PATCH  = L"Modification de 8 octets du bloc de base d'une ruche COPIEE "
                              L"(alignement des numeros de sequence). L'original n'est pas "
                              L"modifie ; empreinte avant patch consignee.";
const wchar_t* HIVE_REPLAY  = L"Application des journaux de transaction a la ruche COPIEE, "
                              L"jamais a l'originale. Le contenu d'origine de chaque page remplacee "
                              L"est conserve dans un journal d'annulation : la copie brute reste "
                              L"reconstructible a l'octet.";
const wchar_t* SCM          = L"Une seule enumeration du gestionnaire de services, en lecture "
                              L"(EnumServicesStatusExW), pour relever l'etat courant. Aucun "
                              L"handle ouvert service par service : la configuration provient "
                              L"de la ruche SYSTEM copiee.";
const wchar_t* PROCESSES    = L"Enumeration des processus : ouverture de handles de processus "
                              L"et de jetons (auditable si la politique le prevoit).";
const wchar_t* SESSIONS     = L"Interrogation des sessions ouvertes (LSA / Terminal Services) : "
                              L"sollicite LSASS, sans modification d'artefact.";
const wchar_t* USB_WRITE = L"Ecriture sur le support de collecte uniquement. Aucune ecriture "
                              L"sur le systeme examine.";
} // namespace Footprint

namespace {

//! Une opération consignée.
struct Operation {
	unsigned     sequence = 0;
	std::wstring timestampUtc;
	std::wstring timestampLocal;
	std::wstring operation;
	std::wstring target;
	std::wstring result;      //!< "OK" ou le code et son message
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

//! Horodatage courant, en UTC et en heure locale.
void now(std::wstring& utc, std::wstring& local, FILETIME* brut = nullptr) {
	SYSTEMTIME stUtc = { 0 };
	GetSystemTime(&stUtc);
	utc = timeToIso8601(stUtc, true);

	SYSTEMTIME stLocal = { 0 };
	GetLocalTime(&stLocal);
	local = timeToIso8601(stLocal, false);

	if (brut) SystemTimeToFileTime(&stUtc, brut);
}

//! Contexte de la machine et de l'opérateur au moment de la collecte.
void readContext() {
	wchar_t buffer[512] = L"";
	DWORD size = 512;
	if (GetComputerNameW(buffer, &size)) g_machine = buffer;

	size = 512;
	if (GetUserNameW(buffer, &size)) g_user = buffer;

	// SID du compte sous lequel WAC s'execute : identifie l'operateur sans
	// ambiguite, meme si le nom de compte a change depuis.
	HANDLE token = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		DWORD required = 0;
		GetTokenInformation(token, TokenUser, NULL, 0, &required);
		if (required) {
			std::vector<BYTE> sidBuffer(required);
			if (GetTokenInformation(token, TokenUser, sidBuffer.data(), required, &required)) {
				LPWSTR text = nullptr;
				PTOKEN_USER tu = reinterpret_cast<PTOKEN_USER>(sidBuffer.data());
				if (ConvertSidToStringSidW(tu->User.Sid, &text)) {
					g_sid = text;
					LocalFree(text);
				}
			}
		}
		TOKEN_ELEVATION elevation = { 0 };
		DWORD length = 0;
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length))
			g_elevated = elevation.TokenIsElevated != 0;
		CloseHandle(token);
	}

	// Fuseau de la MACHINE EXAMINEE : indispensable pour reinterpreter les dates
	// locales des artefacts ( — le fuseau du suspect, pas celui de
	// l'analyste).
	TIME_ZONE_INFORMATION tz = { 0 };
	const DWORD type = GetTimeZoneInformation(&tz);
	if (type != TIME_ZONE_ID_INVALID) {
		g_timeZone = (type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightName : tz.StandardName;
		// Bias est en minutes A AJOUTER a l'heure locale pour obtenir l'UTC.
		g_biasMinutes = tz.Bias + ((type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightBias : tz.StandardBias);
	}
}

} // namespace

void auditInit(int argc, char* argv[]) {
	g_operations.clear();
	g_sequence = 0;
	now(g_startUtc, g_startLocal, &g_start);

	g_commandLine.clear();
	for (int i = 0; i < argc; ++i) {
		if (i) g_commandLine += L" ";
		g_commandLine += string_to_wstring(argv[i]);
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
	/* S_FALSE (1) signifie « réussi, mais partiellement » — typiquement des
	   ruches absentes tolérées par l'extraction. `getErrorMessage()` le traduit
	   comme le code Win32 1, « Fonction incorrecte », ce qui faisait lire un
	   succès partiel comme une panne dans le journal d'audit. Dans une pièce
	   d'enquête, un résultat mal qualifié vaut moins que pas de résultat. */
	if (result == ERROR_SUCCESS)
		o.result = L"OK";
	else if (result == S_FALSE)
		o.result = L"PARTIEL (voir le journal de collecte pour le détail)";
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
	tool.add(L"BuildDate",   Json::str(string_to_wstring(__DATE__) + L" " + string_to_wstring(__TIME__)));
	root.add(L"Tool", std::move(tool));

	Json host = Json::obj();
	host.add(L"ComputerName", Json::str(g_machine));
	host.add(L"SystemDrive",  Json::str(conf.systemDrive));

	/* DEUX fuseaux, et c'est voulu.
	   - SuspectTimeZone : releve dans la ruche SYSTEM examinee. C'est LUI qui sert
	     a formater les heures locales des artefacts, et donc la seule reference
	     valable pour interpreter une date locale.
	   - CollectionHostTimeZone : celui de la machine qui a execute WAC.
	   En collecte live les deux coincident. Une DIVERGENCE est un signal : image
	   analysee sur une autre machine, ou fuseau modifie depuis la collecte — dans
	   les deux cas l'analyste doit le savoir. */
	Json suspect = Json::obj();
	if (conf.timeZone.valid) {
		suspect.add(L"KeyName",      Json::str(conf.timeZone.keyName));
		suspect.add(L"StandardName", Json::str(conf.timeZone.standardName));
		suspect.add(L"DaylightName", Json::str(conf.timeZone.daylightName));
		// Minutes a AJOUTER a l'UTC pour obtenir l'heure locale : +120 = UTC+02:00.
		// Sens verifiable dans ce fichier meme (StartLocal = StartUtc + offset).
		suspect.add(L"UtcOffsetMinutes", Json::num((long long)-conf.timeZone.activeBiasMinutes));
		suspect.add(L"Source", Json::str(L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"));
	}
	else {
		suspect.add(L"Source", Json::str(L"non relevé : repli sur le fuseau de la machine de collecte"));
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

	// MEME contexte que le manifeste de consigne : une seule construction, pour
	// que deux documents de la meme collecte ne puissent pas se contredire.
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

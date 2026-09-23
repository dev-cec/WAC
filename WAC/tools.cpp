#include <cstdio>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <array>
#include <map>
#include <windows.h>
#include <ShellAPI.h> 
#include <stdio.h>
#include <regex>
#include <sddl.h>
#include "tools.h"
#include <filesystem>

/****************************************************
*                   FORMAT DE DONNEES               *
*****************************************************/


FatDateTime::FatDateTime(unsigned int _i) {

	i = _i;
	date = (uint16_t)(_i & 0x0ffffL);
	time = (uint16_t)(_i >> 16);
}


SYSTEMTIME FatDateTime::toSystemTime() {

	/* The year value is stored in bits 9 - 15 of the date (7 bits)
 * A year value of 0 represents 1980
 */
	SYSTEMTIME date_time_values = { 0 };
	date_time_values.wYear = (uint16_t)(1980 + ((date >> 9) & 0x7f));

	/* The month value is stored in bits 5 - 8 of the date (4 bits)
	 * A month value of 1 represents January
	 */
	date_time_values.wMonth = (uint8_t)((date >> 5) & 0x0f);

	/* The day value is stored in bits 0 - 4 of the date (5 bits)
	 */
	date_time_values.wDay = (uint8_t)(date & 0x1f);

	/* The hours value is stored in bits 11 - 15 of the time (5 bits)
	 */
	date_time_values.wHour = (uint8_t)((time >> 11) & 0x1f);

	/* The minutes value is stored in bits 5 - 10 of the time (6 bits)
	 */
	date_time_values.wMinute = (uint8_t)((time >> 5) & 0x3f);

	/* The seconds value is stored in bits 0 - 4 of the time (5 bits)
	 * The seconds are stored as 2 second intervals
	 */
	date_time_values.wSecond = (uint8_t)(time & 0x1f) * 2;

	date_time_values.wMilliseconds = 0;
	return date_time_values;
}

FILETIME FatDateTime::toFileTime() {

	FILETIME f;
	if (i != 0) {
		log(3, L"🔈toSystemTime s");
		const SYSTEMTIME s = toSystemTime();
		log(3, L"🔈SystemTimeToFileTime f");
		SystemTimeToFileTime(&s, &f);
	}
	else
		f = { 0 };
	return f;
}

/****************************************************
*                   AFFICHAGE                       *
*****************************************************/

namespace {
//! Vrai si stdout est une console : sinon la progression est inutile et bruyante.
bool outputIsConsole() {
	static const bool console =
		GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR;
	return console;
}
bool g_progressRunning = false;
std::wstring g_currentStep;          //!< dernier libellé posé par printStep
} // namespace

void printStep(const std::wstring& label) {
	g_currentStep = label;
	wprintf(L"%ls", label.c_str());
}

void printProgress(const std::wstring& label, unsigned long long done,
                   unsigned long long total, const wchar_t* unit) {
	if (!outputIsConsole()) return;

	/* Limitation par le TEMPS, et non par le nombre d'éléments.
	 * Un pas fixe ne peut pas convenir aux deux extrêmes rencontrés : 38
	 * shellbags dont chacun prend des secondes (un pas de 50 ne se déclenchait
	 * jamais, d'où une impression de blocage) et 3000 entrées amcache qui
	 * défilent instantanément (l'affichage coûtait alors plus que le travail).
	 * Un rafraîchissement toutes les 150 ms reste fluide à l'œil quel que soit
	 * le rythme. Le dernier appel (fait == total) passe toujours, pour que la
	 * ligne finisse sur la valeur exacte. */
	static ULONGLONG lastDisplay = 0;
	const ULONGLONG now = GetTickCount64();
	const bool last = (total > 0 && done >= total);
	if (!last && now - lastDisplay < 150) return;
	lastDisplay = now;

	// Le libelle est tronque pour que la ligne ne depasse pas et ne provoque pas
	// de retour a la ligne, qui casserait la reecriture sur place.
	std::wstring court = label;
	if (court.size() > 40) court = L"..." + court.substr(court.size() - 37);

	if (total > 0)
		wprintf(L"\r   %-40ls %llu/%llu %ls (%llu%%)   ", court.c_str(), done, total,
		        unit, (unsigned long long)(done * 100ULL / total));
	else
		wprintf(L"\r   %-40ls %llu %ls   ", court.c_str(), done, unit);
	fflush(stdout);
	g_progressRunning = true;
}

void printProgressEnd() {
	if (!outputIsConsole() || !g_progressRunning) return;
	// Efface la ligne de progression, puis remet le libellé de l'étape : sans lui
	// le « OK » qui suit apparaîtrait seul, sans dire à quoi il se rapporte.
	wprintf(L"\r%-100ls\r", L"");
	if (!g_currentStep.empty()) wprintf(L"%ls", g_currentStep.c_str());
	fflush(stdout);
	g_progressRunning = false;
}

void printSuccess() {
	// Restaure le libelle d'etape si une progression l'a efface, pour que le
	// « OK » reste rattache a son etape.
	printProgressEnd();
	SetConsoleTextAttribute(conf.hConsole, 10);
	wprintf(L"OK\n");
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printProgressStep(const std::wstring& artefact, unsigned long long done,
                       unsigned long long total) {
	/* La limitation de fréquence est assurée par printProgress (par le temps) :
	   elle vaut pour tous les rythmes, du shellbag de plusieurs secondes aux
	   milliers d'entrées amcache instantanées.
	   Unité en ASCII pur, sans accent : la console est en CP_UTF8, mais wprintf
	   convertit les wchar_t selon la locale C du programme, qui ne l'est pas — un
	   caractère accentué y ressortirait en idéogrammes. */
	printProgress(artefact, done, total, L"elem");
}

void printError(std::wstring errorText) {
	// Comme printSuccess : restaure le libelle d'etape avant d'ecrire l'erreur.
	printProgressEnd();
	SetConsoleTextAttribute(conf.hConsole, 12);
	WriteConsoleW(conf.hConsole, errorText.c_str(), errorText.length(), NULL, NULL);
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printError(HRESULT  hresult) {
	
	std::wstring errorText = getErrorMessage(hresult).data();
	printError(errorText);
}

std::wstring getErrorMessage(HRESULT hresult)
{
	//used to log, so no log to this call function
	LPWSTR errorText = NULL;
	FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		hresult,
		LANG_SYSTEM_DEFAULT,
		//MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), 
		(LPWSTR)&errorText,
		0,
		NULL);
	std::wstring result(errorText);
	result.erase(std::remove(result.begin(), result.end(), '\r'), result.cend()); // pas de retour à la ligne
	result.erase(std::remove(result.begin(), result.end(), '\n'), result.cend()); // pas de retour à la ligne

	return result;
}


void log(int loglevel, std::wstring message) {
	if (conf.loglevel >= loglevel && conf.loglevel > 0) {
		conf.log.open(conf.name + ".log", std::ios::app);
		conf.log << tab(loglevel) << ansi_to_utf8(message) << std::endl;
		conf.log.flush();
		conf.log.close();
	}
}

void log(int loglevel, std::wstring message, HRESULT result) {
	log(loglevel, message + L" : " + getErrorMessage(result));
}

std::string ansi_to_utf8(std::string in)
{
	// 
	//used to log, so no log to this call function

	int size = MultiByteToWideChar(CP_ACP, WC_COMPOSITECHECK || WC_DEFAULTCHAR, in.c_str(),
		in.length(), nullptr, 0);
	std::wstring utf16_str(size, '\0');

	MultiByteToWideChar(CP_ACP, WC_COMPOSITECHECK || WC_DEFAULTCHAR, in.c_str(),
		in.length(), &utf16_str[0], size);

	int utf8_size = WideCharToMultiByte(CP_UTF8, 0, utf16_str.c_str(),
		utf16_str.length(), nullptr, 0,
		nullptr, nullptr);
	std::string utf8_str(utf8_size, '\0');

	WideCharToMultiByte(CP_UTF8, 0, utf16_str.c_str(),
		utf16_str.length(), &utf8_str[0], utf8_size,
		nullptr, nullptr);
	return utf8_str;
}

std::wstring ansi_to_utf8(std::wstring in)
{
	//used to log, so no log to this call function

	int utf8_size = WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
		in.length(), nullptr, 0,
		nullptr, nullptr);
	std::string utf8_str(utf8_size, '\0');

	WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
		in.length(), &utf8_str[0], utf8_size,
		nullptr, nullptr);

	return string_to_wstring(utf8_str);
}

void dump(LPBYTE buffer, int start, int end) {

	for (int x = start; x <= end; x++)
		wprintf(L"%02X ",static_cast<int>(buffer[x]));
	wprintf(L"\n");
}

std::wstring dump_wstring(LPBYTE buffer, int start, int length) {
	// Borne EXCLUSIVE : « longueur » octets depuis « start » (cf. tools.h).
	if (!buffer || length <= 0) return L"";
	std::wstringstream ss;
	for (int x = start; x < start + length; x++)
		ss << std::setw(2) << std::setfill(L'0') << std::hex
		   << static_cast<int>(buffer[x]) << L" ";
	return ss.str();
}
/****************************************************
*                     CHAINES                       *
*****************************************************/

std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement)
{
	if (src.length() > 0) {
		size_t pos = 0;
		while ((pos = src.find(search, pos)) != std::wstring::npos) {
			src.replace(pos, search.length(), replacement);
			pos += replacement.length();
		}
	}
	return src;
}

std::wstring ROT13(std::wstring source)
{

	std::wstring transformed;
	for (size_t i = 0; i < source.length(); ++i) {
		// a-z -> n-m
		if (97 <= source[i] && source[i] <= 122) {
			transformed.append(1, (source[i] - 97 + 13) % 26 + 97);
		}

		// A-Z -> N-M
		else if (65 <= source[i] && source[i] <= 90) {
			transformed.append(1, (source[i] - 65 + 13) % 26 + 65);
		}

		// PAS alpha
		else {
			transformed.append(1, source[i]);
		}
	}
	return transformed;
}


std::string decodeURIComponent(std::string encoded) {

	std::string decoded = encoded;
	std::smatch sm;
	std::string haystack;

	int dynamicLength = decoded.size() - 2;

	if (decoded.size() < 3) return decoded;

	for (int i = 0; i < dynamicLength; i++)
	{

		haystack = decoded.substr(i, 3);

		if (std::regex_match(haystack, sm, std::regex("%[0-9A-F]{2}")))
		{
			haystack = haystack.replace(0, 1, "0x");
			std::string rc = { (char)std::stoi(haystack, nullptr, 16) };
			decoded = decoded.replace(decoded.begin() + i, decoded.begin() + i + 3, rc);
		}

		dynamicLength = decoded.size() - 2;

	}

	return decoded;
}

std::wstring to_hex(long long i) {

	std::wstringstream ss;
	ss << std::setw(2) << std::setfill(L'0') << std::hex << i;
	return ss.str();
}

std::wstring tab(int i) {
	//used to log, so no log to this call function
	std::wstring result = L"";
	for (int x = 0; x < i; x++)
		result += L"\t";
	return result;
}

/****************************************************
*                   CONVERSION                      *
*****************************************************/

std::wstring getNameFromSid(std::wstring _sid) {
	/* CORRECTIONS et MISE EN CACHE.
	 *
	 * Lenteur : LookupAccountSidW(NULL, …) interroge le contrôleur de domaine
	 * quand le SID n'est pas résoluble localement, avec délai réseau à la clé.
	 * La fonction était appelée pour CHAQUE shellbag, MRU, userassist et
	 * processus, alors qu'un même SID revient des centaines de fois — d'où une
	 * collecte qui semblait figée. Le résultat est donc mémorisé par SID.
	 * Effet de bord utile : autant de sollicitations réseau en moins, donc
	 * autant de traces en moins.
	 *
	 * Trois défauts corrigés au passage :
	 *  - le pointeur alloué par ConvertStringSidToSidW n'était jamais libéré ;
	 *  - la MÊME variable `taille` servait pour le nom ET pour le domaine, alors
	 *    que l'API écrit dans les deux : la seconde écriture écrasait la première ;
	 *  - le retour n'était pas vérifié, si bien qu'un échec faisait lire un
	 *    tampon non initialisé.
	 */
	if (_sid.empty()) return L"";

	static std::map<std::wstring, std::wstring> cache;
	const auto found = cache.find(_sid);
	if (found != cache.end()) return found->second;

	std::wstring name;
	PSID pSID = NULL;
	log(3, L"🔈ConvertStringSidToSidW");
	if (ConvertStringSidToSidW(_sid.c_str(), &pSID)) {
		wchar_t lpName[256] = L"";
		wchar_t lpDomain[256] = L"";
		DWORD nameSize = 256, domainSize = 256;   // deux tailles distinctes
		SID_NAME_USE typeSid = SidTypeUnknown;
		log(3, L"🔈LookupAccountSidW");
		if (LookupAccountSidW(NULL, pSID, lpName, &nameSize,
		                      lpDomain, &domainSize, &typeSid))
			name = lpName;
		else
			log(3, L"🔈LookupAccountSidW sans correspondance", GetLastError());
		LocalFree(pSID);                              // alloue par ConvertStringSidToSidW
	}

	// Mémorisé même vide : un SID non résoluble le restera, inutile d'attendre
	// une nouvelle fois le délai réseau à chaque occurrence.
	cache.emplace(_sid, name);
	return name;
}

std::wstring luid_to_wstring(LUID luid) {
	/* CORRECTION : un LUID fait 64 bits (LowPart ULONG + HighPart LONG), mais le
	   calcul se faisait sur un ULONG de 32 bits. Decaler de 32 un type de 32 bits
	   est un comportement indefini, et HighPart etait perdu : deux LUID ne
	   differant que par leur partie haute rendaient la meme valeur. */
	const ULONGLONG value = ((ULONGLONG)(ULONG)luid.HighPart << 32) | (ULONGLONG)luid.LowPart;
	return std::to_wstring(value);
}

std::wstring bool_to_wstring(bool b)
{

	if (b) return L"true";
	else return L"false";
}

FILETIME timet_to_fileTime(time_t t)
{

	FILETIME ft = { 0 };
	LONGLONG time_value = Int32x32To64(t, 10000000) + 116444736000000000;
	ft.dwLowDateTime = (DWORD)time_value;
	ft.dwHighDateTime = time_value >> 32;
	return ft;
}

FILETIME wstring_to_filetime(std::wstring input) {

	std::istringstream istr(wstring_to_string(input));
	SYSTEMTIME st = { 0 };
	FILETIME ft = { 0 };
	istr >> st.wMonth;
	istr.ignore(1, '/');
	istr >> st.wDay;
	istr.ignore(1, '/');
	istr >> st.wYear;
	istr.ignore(1, ' ');
	istr >> st.wHour;
	istr.ignore(1, ':');
	istr >> st.wMinute;
	istr.ignore(1, ':');
	istr >> st.wSecond;
	st.wMilliseconds = 0;
	log(3, L"🔈SystemTimeToFileTime ft");
	SystemTimeToFileTime(&st, &ft);
	return ft;
}

std::wstring time_to_wstring(const SYSTEMTIME systemtime)
{

	std::wstring result = std::to_wstring(systemtime.wDay) + L"/" + std::to_wstring(systemtime.wMonth) + L"/" + std::to_wstring(systemtime.wYear)
		+ L" " + std::to_wstring(systemtime.wHour) + L"h" + std::to_wstring(systemtime.wMinute) + L"m" + std::to_wstring(systemtime.wSecond) + L"s";
	if (result == L"1/1/1601 0h0m0s")
		return L"";
	else
		return result;
}

std::wstring time_to_wstring(const FILETIME filetime, bool convertUtc) {

	SYSTEMTIME systemtime;
	if (convertUtc) {
		FILETIME utc;
		log(3, L"🔈LocalFileTimeToFileTime utc");
		LocalFileTimeToFileTime(&filetime, &utc);
		log(3, L"🔈FileTimeToSystemTime systemtime");
		FileTimeToSystemTime(&utc, &systemtime); //conversion filetime to systemtime
	}
	else {
		log(3, L"🔈FileTimeToSystemTime systemtime");
		FileTimeToSystemTime(&filetime, &systemtime); //conversion filetime to systemtime
		log(3, L"🔈timeToIso8601 systemtime");
	}
	return time_to_wstring(systemtime);

}

///////////////////////////////////////////////////////
// Horodatages ISO 8601 — voir tools.h pour la justification
///////////////////////////////////////////////////////
namespace {

//! Deux chiffres, zéro devant : "07", "15".
void twoDigits(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! Quatre chiffres : "2026".
void fourDigits(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 1000) % 10);
	out += (wchar_t)(L'0' + (v / 100) % 10);
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! Vrai si le FILETIME est nul (époque 1601) : pas une date, une absence de date.
bool nullDate(const FILETIME& ft) {
	return ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0;
}

//! Décalage de la machine d'EXÉCUTION (repli quand la ruche n'est pas lisible).
long machineBiasMinutes() {
	TIME_ZONE_INFORMATION tz = { 0 };
	const DWORD type = GetTimeZoneInformation(&tz);
	if (type == TIME_ZONE_ID_INVALID) return 0;
	// Bias est en minutes à AJOUTER à l'heure locale pour obtenir l'UTC.
	return tz.Bias + ((type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightBias : tz.StandardBias);
}

} // namespace

std::wstring localUtcOffsetString() {
	/* Pas de cache : la valeur change en cours d'exécution, au moment où la ruche
	   SYSTEM du suspect devient lisible. Un cache figerait le décalage de la
	   machine d'exécution pour toute la collecte. */
	const long bias = conf.timeZone.valid ? conf.timeZone.activeBiasMinutes
	                                       : machineBiasMinutes();
	const long minutes = -bias;          // minutes à ajouter à l'UTC pour l'heure locale
	std::wstring s;
	s += (minutes < 0) ? L'-' : L'+';
	const long absolute = (minutes < 0) ? -minutes : minutes;
	twoDigits(s, (unsigned)(absolute / 60));
	s += L':';
	twoDigits(s, (unsigned)(absolute % 60));
	return s;
}

namespace {

/*! Développe les variables d'environnement d'un `ProfileImagePath`, SANS
 *  interroger l'environnement du processus.
 *
 *  POURQUOI PAS `ExpandEnvironmentStringsW`. Cette fonction lit l'environnement
 *  du processus COURANT. Tant que la valeur venait du registre vivant, cela
 *  coïncidait avec la machine examinée ; lue hors ligne dans une ruche copiée,
 *  la valeur appartient à une autre installation que celle qui exécute WAC, et
 *  développer avec l'environnement local deviendrait une supposition.
 *
 *  `ProfileImagePath` est un REG_EXPAND_SZ, et vaut littéralement
 *  « %systemroot%\\system32\\config\\systemprofile » pour les comptes de
 *  service. Sans développement, le chemin ne désigne aucun fichier et
 *  l'extraction brute de leur ntuser.dat échoue en silence — ce qui s'observait
 *  comme une extraction « partielle » sans cause apparente. */
std::wstring expandProfilePath(const std::wstring& brut) {
	if (brut.find(L'%') == std::wstring::npos) return brut;
	const std::wstring expanded = normalizeFilePath(brut);
	if (expanded.empty()) {
		log(2, L"🔥ProfileImagePath : variable non reconnue dans " + brut);
		return brut;
	}
	return expanded;
}

} // namespace

HRESULT loadProfileList() {
	if (!conf.Software) {
		log(2, L"🔥Ruche SOFTWARE indisponible : profils utilisateurs non releves",
		    ERROR_INVALID_HANDLE);
		return ERROR_INVALID_HANDLE;
	}

	PCWSTR KEY = L"Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	ORHKEY hKey = NULL;
	log(3, L"🔈OROpenKey Software\\...\\ProfileList");
	HRESULT hresult = OROpenKey(conf.Software, KEY, &hKey);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥OROpenKey Software\\...\\ProfileList", hresult);
		return hresult;
	}

	DWORD nSubKeys = 0;
	log(3, L"🔈ORQueryInfoKey ProfileList");
	hresult = ORQueryInfoKey(hKey, NULL, NULL, &nSubKeys, NULL, NULL, NULL,
	                         NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey ProfileList", hresult);
		ORCloseKey(hKey);
		return hresult;
	}

	for (DWORD i = 0; i < nSubKeys; ++i) {
		WCHAR sid[MAX_KEY_NAME] = L"";
		DWORD size = MAX_KEY_NAME;
		log(3, L"🔈OREnumKey ProfileList " + std::to_wstring(i));
		if (OREnumKey(hKey, i, sid, &size, NULL, NULL, NULL) != ERROR_SUCCESS)
			continue;

		std::wstring path;
		if (getRegSzValue(hKey, sid, L"ProfileImagePath", &path) != ERROR_SUCCESS)
			continue;

		const std::wstring expanded = expandProfilePath(path);
		if (expanded != path)
			log(2, L"❇️Profil developpe : " + path + L" -> " + expanded);
		if (expanded.empty()) continue;

		conf.profiles.push_back({ sid, expanded });
		log(2, L"❇️Profil : " + std::wstring(sid) + L" -> " + expanded);
	}
	ORCloseKey(hKey);
	log(2, L"❇️" + std::to_wstring(conf.profiles.size()) + L" profils utilisateurs releves");
	return conf.profiles.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

std::wstring volumeOfPath(const std::wstring& absolute) {
	if (absolute.size() >= 2 && absolute[1] == L':')
		return std::wstring(1, (wchar_t)towupper(absolute[0]));
	// Chemin deja relatif a une racine : il appartient au volume systeme.
	return conf.systemDrive.substr(0, 1);
}

std::wstring pathRelativeToVolume(const std::wstring& absolute) {
	if (absolute.size() >= 2 && absolute[1] == L':') return absolute.substr(2);
	return absolute;
}

/*! Résout le chemin d'un fichier désigné par `ImagePath` ou `ServiceDll`.
*
*  La ruche stocke des formes hétérogènes, qu'aucune API ne normalise hors ligne :
*    - `\SystemRoot\System32\drivers\x.sys`  (préfixe noyau)
*    - `\??\C:\dossier\x.exe`                 (chemin objet NT)
*    - `system32\svchost.exe -k netsvcs`      (relatif à %SystemRoot%)
*    - `"C:\Program Files\App\x.exe" /service`(guillemets + arguments)
*
*  CE QUI ÉTAIT FAUX. La version d'origine coupait sur la première occurrence de
*  « -» ou « /», y compris à l'intérieur du chemin : un binaire installé dans un
*  dossier contenant un tiret voyait son chemin tronqué, et son MD5 n'était donc
*  jamais calculé. Ici, la coupure se fait APRÈS l'extension du fichier, qui est
*  le seul repère fiable de la fin du chemin.
*/
std::wstring normalizeFilePath(std::wstring path) {
	// Espaces et guillemets d'encadrement : présents dans Shimcache et Amcache.
	while (!path.empty() && (path.front() == L' ' || path.front() == L'"')) path.erase(0, 1);
	while (!path.empty() && (path.back() == L' ' || path.back() == L'"')) path.pop_back();
	if (path.empty()) return L"";

	std::wstring low = toLower(path);
	// Préfixes objet NT : « \??\C:\… » (Shimcache, ImagePath), « \\?\C:\… ».
	if (low.compare(0, 4, L"\\??\\") == 0 || low.compare(0, 4, L"\\\\?\\") == 0) {
		if (low.compare(4, 4, L"unc\\") == 0) return L"";   // partage réseau
		path.erase(0, 4);
		low.erase(0, 4);
	}
	// Préfixe noyau.
	if (low.compare(0, 12, L"\\systemroot\\") == 0)
		return conf.systemDrive + L"\\Windows\\" + path.substr(12);

	/* VARIABLES, développées depuis le lecteur système DÉTECTÉ et jamais depuis
	   l'environnement du processus : la valeur appartient à l'installation
	   examinée, pas à celle qui exécute WAC (et WAC tourne en SYSTEM, dont
	   l'environnement ne dit rien des utilisateurs).
	   `%windir%` est synonyme de `%systemroot%` ; ne pas le traiter donnait des
	   chemins du genre « C:\Windows\%windir%\system32\ncsi.dll ».
	   Les variables PROPRES À UN UTILISATEUR (%APPDATA%, %LOCALAPPDATA%,
	   %USERPROFILE%…) ne sont pas développées : le compte n'est pas connu ici,
	   et deviner rendrait l'empreinte d'un autre fichier que celui désigné. */
	if (!path.empty() && path.front() == L'%') {
		const size_t end = path.find(L'%', 1);
		if (end == std::wstring::npos) return L"";
		const std::wstring var = low.substr(1, end - 1);
		const std::wstring d = conf.systemDrive;
		static const std::map<std::wstring, std::wstring> known = {
			{ L"systemroot", L"\\Windows" },               { L"windir", L"\\Windows" },
			{ L"systemdrive", L"" },
			{ L"programfiles", L"\\Program Files" },       { L"programw6432", L"\\Program Files" },
			{ L"programfiles(x86)", L"\\Program Files (x86)" },
			{ L"commonprogramfiles", L"\\Program Files\\Common Files" },
			{ L"commonprogramw6432", L"\\Program Files\\Common Files" },
			{ L"commonprogramfiles(x86)", L"\\Program Files (x86)\\Common Files" },
			{ L"programdata", L"\\ProgramData" },          { L"allusersprofile", L"\\ProgramData" },
			{ L"public", L"\\Users\\Public" },
		};
		const auto it = known.find(var);
		if (it == known.end()) return L"";
		path = d + it->second + path.substr(end + 1);
	}
	if (path.size() < 3 || path[1] != L':' || path[2] != L'\\') return L"";
	path[0] = (wchar_t)towupper(path[0]);
	return path;
}

std::wstring binaryPath(std::wstring imagePath) {
	if (imagePath.empty()) return L"";

	// Chemin entre guillemets : il se termine au guillemet fermant.
	if (imagePath.front() == L'"') {
		const size_t end = imagePath.find(L'"', 1);
		imagePath = (end == std::wstring::npos) ? imagePath.substr(1)
		                                        : imagePath.substr(1, end - 1);
	}
	else {
		/* Sans guillemets, la fin du chemin se repère à l'extension. On prend la
		   PREMIÈRE extension rencontrée : ce qui suit est une option. */
		const std::wstring low = toLower(imagePath);
		size_t end = std::wstring::npos;
		for (PCWSTR ext : { L".exe", L".sys", L".dll" }) {
			const size_t p = low.find(ext);
			if (p != std::wstring::npos && (end == std::wstring::npos || p < end))
				end = p + 4;
		}
		if (end != std::wstring::npos) imagePath = imagePath.substr(0, end);
	}

	// Préfixes noyau, objet NT et variables : la règle commune.
	{
		const std::wstring normalized = normalizeFilePath(imagePath);
		if (!normalized.empty()) return normalized;
		if (imagePath.find(L'%') != std::wstring::npos) return L"";   // variable inconnue
	}

	/* Chemin relatif : il l'est à %SystemRoot%, pas au répertoire courant.
	   Un service dont ImagePath vaut « system32\\x.exe » désigne donc
	   C:\\Windows\\system32\\x.exe. */
	if (imagePath.size() < 2 || imagePath[1] != L':') {
		if (!imagePath.empty() && imagePath.front() == L'\\')
			return L"";   // \Driver\..., \FileSystem\... : objet noyau, pas un fichier
		imagePath = conf.systemDrive + L"\\Windows\\" + imagePath;
	}
	return imagePath;
}

std::wstring pathUnder(const std::wstring& root, const std::wstring& absolute) {
	const std::wstring volume   = volumeOfPath(absolute);
	const std::wstring relative  = pathRelativeToVolume(absolute);
	const std::wstring system_  = conf.systemDrive.substr(0, 1);
	if (toLower(volume) == toLower(system_))
		return root + relative;                   // cas courant : rien ne change
	// Volume secondaire : sous-dossier dedie, pour ne pas ecraser une copie
	// homonyme venant d'un autre disque.
	return root + L"\\_volume_" + volume + relative;
}

std::wstring extractedPath(const std::wstring& absolute) {
	return pathUnder(conf.mountpoint, absolute);
}

std::wstring originalPath(const std::wstring& extracted) {
	std::wstring rest = replaceAll(extracted, conf.mountpoint, L"");
	// « \_volume_D\... » : le fichier venait d'un autre disque que Windows.
	const std::wstring mark = L"\\_volume_";
	if (rest.compare(0, mark.size(), mark) == 0
	    && rest.size() > mark.size()) {
		const wchar_t letter = rest[mark.size()];
		return std::wstring(1, letter) + L":" + rest.substr(mark.size() + 1);
	}
	return conf.systemDrive + rest;
}

void loadSystemDrive() {
	/* GetSystemDirectoryW rend "X:\Windows\System32" : les deux premiers
	   caractères donnent le lecteur. Préféré à la variable d'environnement
	   %SystemDrive%, qui peut être altérée par le processus appelant. */
	wchar_t buffer[MAX_PATH] = L"";
	const UINT n = GetSystemDirectoryW(buffer, MAX_PATH);
	if (n >= 2 && buffer[1] == L':') {
		conf.systemDrive = std::wstring(buffer, 2);
		log(2, L"❇️Lecteur systeme : " + conf.systemDrive);
	}
	else {
		log(2, L"🔥GetSystemDirectoryW : lecteur systeme non determine, "
		       L"repli sur " + conf.systemDrive, GetLastError());
	}
}

HRESULT loadSuspectTimeZone() {
	conf.timeZone = TimeZoneInfo{};       // repart d'un état propre
	if (!conf.CurrentControlSet) return ERROR_INVALID_HANDLE;

	PCWSTR key = L"Control\\TimeZoneInformation";
	DWORD activeBias = 0;
	log(3, L"🔈getRegDwordValue ActiveTimeBias");
	HRESULT hresult = getRegDwordValue(conf.CurrentControlSet, key, L"ActiveTimeBias", &activeBias);
	if (hresult != ERROR_SUCCESS) {
		/* ActiveTimeBias absent : on recompose Bias + biais saisonnier. On ne
		   peut pas savoir lequel des deux s'appliquait au moment de chaque
		   artefact, donc on prend Bias seul et on le signale. */
		DWORD bias = 0;
		log(3, L"🔈getRegDwordValue Bias");
		hresult = getRegDwordValue(conf.CurrentControlSet, key, L"Bias", &bias);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥Fuseau du suspect illisible dans la ruche SYSTEM", hresult);
			return hresult;
		}
		activeBias = bias;
		log(2, L"🔥ActiveTimeBias absent : Bias seul utilise (heure d'ete non prise en compte)");
	}

	// ActiveTimeBias/Bias sont des DWORD mais portent un entier SIGNE en minutes.
	conf.timeZone.activeBiasMinutes = (long)(int32_t)activeBias;

	/* Heure d'été active ou non. Non stockée telle quelle : elle se DÉDUIT de
	   l'écart entre ActiveTimeBias (décalage réellement appliqué) et Bias
	   (décalage hors saison). Si les deux diffèrent, le biais saisonnier
	   s'appliquait au moment de la collecte. */
	DWORD biasStandard = 0;
	if (getRegDwordValue(conf.CurrentControlSet, key, L"Bias", &biasStandard) == ERROR_SUCCESS) {
		conf.timeZone.standardBiasMinutes = (long)(int32_t)biasStandard;
		conf.timeZone.daylightInEffect =
			(conf.timeZone.activeBiasMinutes != conf.timeZone.standardBiasMinutes);
	}
	else
		conf.timeZone.standardBiasMinutes = conf.timeZone.activeBiasMinutes;

	getRegSzValue(conf.CurrentControlSet, key, L"TimeZoneKeyName", &conf.timeZone.keyName);
	getRegSzValue(conf.CurrentControlSet, key, L"StandardName",    &conf.timeZone.standardName);
	getRegSzValue(conf.CurrentControlSet, key, L"DaylightName",    &conf.timeZone.daylightName);
	conf.timeZone.fromHive = true;
	conf.timeZone.valid    = true;

	log(2, L"❇️Fuseau du suspect (ruche SYSTEM) : " + conf.timeZone.keyName
	     + L", UTC" + localUtcOffsetString());
	return ERROR_SUCCESS;
}

std::wstring timeToIso8601(const SYSTEMTIME& st, bool utc, long fraction100ns) {
	if (st.wYear <= 1601) return L"";        // date nulle : chaîne vide, pas 1601
	std::wstring s;
	s.reserve(33);
	fourDigits(s, st.wYear);   s += L'-';
	twoDigits(s, st.wMonth);    s += L'-';
	twoDigits(s, st.wDay);      s += L'T';
	twoDigits(s, st.wHour);     s += L':';
	twoDigits(s, st.wMinute);   s += L':';
	twoDigits(s, st.wSecond);
	/*  La fraction s'écrit ICI, entre les secondes et le suffixe de fuseau.
	    L'insérer après coup obligeait à retrouver la fin des secondes dans la
	    chaîne finie : sur la variante locale, dont le suffixe « +02:00 » se
	    termine par des chiffres, la recherche s'arrêtait aussitôt et la fraction
	    atterrissait APRÈS le décalage horaire. */
	if (fraction100ns >= 0) {
		s += L'.';
		for (int p = 6; p >= 0; --p) {
			long divisor = 1;
			for (int k = 0; k < p; ++k) divisor *= 10;
			s += (wchar_t)(L'0' + ((fraction100ns / divisor) % 10));
		}
	}
	if (utc) s += L'Z';
	else     s += localUtcOffsetString();
	return s;
}

/*  PRÉCISION INFRA-SECONDE.
 *
 *  Un FILETIME compte les intervalles de 100 nanosecondes : sa résolution est
 *  dix millions de fois plus fine que la seconde. Passer par un SYSTEMTIME, qui
 *  plafonne à la milliseconde, en perdait quatre chiffres — et le formatage à la
 *  seconde en perdait sept.
 *
 *  POURQUOI CELA COMPTE. Corréler des artefacts, c'est les ORDONNER. Deux
 *  événements d'une même seconde — une création de processus et la connexion
 *  réseau qu'il ouvre, un fichier écrit puis exécuté — deviennent
 *  indiscernables si l'horodatage est arrondi, et l'ordre est précisément ce
 *  qu'on cherche à établir. Windows lui-même écrit sept chiffres dans le XML de
 *  ses journaux.
 *
 *  La fraction est prise sur le FILETIME et non sur le SYSTEMTIME : c'est la
 *  seule source qui la porte.
 */
namespace {

//! Fraction de seconde d'un FILETIME, en centaines de nanosecondes (0..9999999).
long fraction100ns(const FILETIME& ft) {
	const ULONGLONG v = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	return (long)(v % 10000000ULL);
}

} // namespace

std::wstring timeToIso8601Utc(const FILETIME& filetime) {
	if (nullDate(filetime)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&filetime, &st)) return L"";
	return timeToIso8601(st, true, fraction100ns(filetime));
}

std::wstring timeToIso8601Local(const FILETIME& filetime) {
	if (nullDate(filetime)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&filetime, &st)) return L"";
	return timeToIso8601(st, false, fraction100ns(filetime));
}

bool utcToSuspectLocal(const FILETIME& filetimeUtc, FILETIME* filetimeLocal) {
	if (!filetimeLocal) return false;
	*filetimeLocal = FILETIME{ 0, 0 };
	if (nullDate(filetimeUtc)) return false;
	/* Le biais est en minutes à AJOUTER à l'heure locale pour obtenir l'UTC
	   (convention de la ruche) : l'heure locale s'obtient donc en le
	   RETRANCHANT de l'UTC. Même source que localUtcOffsetString(), afin que la
	   valeur et son étiquette parlent du même fuseau. */
	const long bias = conf.timeZone.valid ? conf.timeZone.activeBiasMinutes
	                                       : machineBiasMinutes();
	const ULONGLONG utc100ns = ((ULONGLONG)filetimeUtc.dwHighDateTime << 32)
	                         | filetimeUtc.dwLowDateTime;
	const long long offset100ns = (long long)bias * 60LL * 10000000LL;
	if ((long long)utc100ns < offset100ns) return false;   // sous l'epoque : aberrant
	const ULONGLONG local100ns = (ULONGLONG)((long long)utc100ns - offset100ns);
	filetimeLocal->dwLowDateTime  = (DWORD)(local100ns & 0xFFFFFFFFULL);
	filetimeLocal->dwHighDateTime = (DWORD)(local100ns >> 32);
	return true;
}

std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc) {
	FILETIME local = { 0, 0 };
	if (!utcToSuspectLocal(filetimeUtc, &local)) return L"";
	return timeToIso8601Local(local);
}

std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal) {
	if (nullDate(filetimeLocal)) return L"";
	FILETIME utc = { 0, 0 };
	if (!LocalFileTimeToFileTime(&filetimeLocal, &utc)) return L"";
	return timeToIso8601Utc(utc);
}

std::wstring string_to_wstring(const std::string& str)
{
	//used to log, so no log to this call function
	std::wstring wstr;
	size_t size;
	wstr.resize(str.length());
	mbstowcs_s(&size, &wstr[0], wstr.size() + 1, str.c_str(), str.size());
	return wstr;
}

bool estReferenceMui(const std::wstring& value) {
	/* Forme reconnue : « @<fichier>,-<id> ». Le « @ » initial seul ne suffit
	   pas : certaines descriptions commencent par une arobase sans être des
	   références. La virgule suivie du signe moins est le marqueur fiable. */
	if (value.size() < 4 || value.front() != L'@') return false;
	const size_t virgule = value.rfind(L',');
	return virgule != std::wstring::npos
	    && virgule + 1 < value.size()
	    && value[virgule + 1] == L'-';
}

std::wstring toLower(std::wstring s) {
	for (wchar_t& c : s) c = (wchar_t)towlower(c);
	return s;
}

std::string wstring_to_string(const std::wstring& wstr)
{

	std::string str;
	size_t size;
	str.resize(wstr.length());
	wcstombs_s(&size, &str[0], str.size() + 1, wstr.c_str(), wstr.size());
	return str;
}

std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size)
{

	std::vector<std::wstring> out;
	wchar_t* d = (wchar_t*)data;
	size_t pos = 0;

	while (pos < (size_t)size / sizeof(wchar_t))
	{

		std::wstring ws = std::wstring(d).data();
		pos += ws.length() + 1;//position du premier caractère de la chaîne suivante après le \0 de fin de chaîne de la suivante
		d += ws.length() + 1;
		if (!ws.empty()) {
			out.push_back(ws);
		}
	}

	return out;
}

std::wstring guid_to_wstring(GUID guid) {
	OLECHAR* result;
	log(3, L"🔈tringFromCLSID result");
	HRESULT hresult = StringFromCLSID(guid, &result);
	if (hresult == ERROR_SUCCESS)
		return std::wstring(result);
	else
		return L"";

}


/****************************************************
*                   REGISTRY                        *
*****************************************************/

// Lire une donnée au format binaire en base de données
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, LPBYTE* bytes, DWORD* size)
{
	//Attention octets doit être suffisamment grand pour accepter les données LPBYTE octets = new BYTE[MAX_DATA]; si la taille n'est pas connue
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD valueType = 0;
	HRESULT hresult = 0;
	if (*bytes != NULL)
		delete[] * bytes; // on supprime tout buffer passé en paramètre pour ne pas avoir de memory leak;
	do {
		*bytes = new BYTE[*size];
		memset(*bytes, 0, *size);
		log(3, L"🔈ORGetValue");
		hresult = ORGetValue(key, subKey, valueName, &valueType, *bytes, size); //lecture des données
	} while (hresult == ERROR_MORE_DATA);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue", hresult);
	}

	return hresult;
}


// Lire une valeur booléenne en base de registre
HRESULT getRegboolValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, bool* value)
{
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD size = 0;
	LPBYTE bytes = NULL;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, subKey, valueName, &bytes, &size);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		*value = (bool)bytes[0];
	}
	delete[] bytes;
	return hresult;
}

// Lit une valeur FILETIME en base de registre
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, FILETIME* filetime)
{
	//les REG_FILETIME  sont stockées sous forme de bytes
	// leur type est soit REG_BINARY soi REG_FILETIME(16) 
	DWORD size = 0;
	LPBYTE data = new BYTE[size + 2];
	HRESULT hresult = 0;

	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, subKey, valueName, &data, &size);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		FILETIME temp = { 0 };
		temp = *reinterpret_cast<FILETIME*>(data);
		*filetime = temp;
	}

	delete[] data;
	return hresult;
}

// Lire une chaîne de caractère en base de registre
// S'assure que la chaîne est printable et se termine par \0. Si un caractère n'est pas imprimable il est remplacé par ?
HRESULT getRegDwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, DWORD* pdword)
{
	DWORD size = 0;
	LPBYTE data = NULL;
	log(3, L"🔈getRegBinaryValue");
	HRESULT hresult = getRegBinaryValue(key, subKey, valueName, &data, &size);
	if (hresult != ERROR_SUCCESS) return hresult;
	// Une valeur plus courte que 4 octets n'est pas un DWORD exploitable.
	if (size < sizeof(DWORD)) { delete[] data; return ERROR_INVALID_DATA; }
	*pdword = *reinterpret_cast<DWORD*>(data);
	delete[] data;
	return ERROR_SUCCESS;
}

HRESULT getRegQwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, unsigned long long* pqword)
{
	DWORD size = 0;
	LPBYTE data = NULL;
	log(3, L"🔈getRegBinaryValue");
	HRESULT hresult = getRegBinaryValue(key, subKey, valueName, &data, &size);
	if (hresult != ERROR_SUCCESS) return hresult;
	// Une valeur plus courte que 8 octets n'est pas un QWORD exploitable.
	if (size < sizeof(unsigned long long)) { delete[] data; return ERROR_INVALID_DATA; }
	memcpy(pqword, data, sizeof(unsigned long long));
	delete[] data;
	return ERROR_SUCCESS;
}

HRESULT getRegSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::wstring* ws)
{
	//les REG_SZ sont stockées sous forme de wchar_t = 16 bit par caractère
	DWORD size = 0;
	LPWSTR data = NULL;
	size_t nbChar = 0;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, subKey, valueName, (LPBYTE*)&data, &size);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
		return hresult;
	}
	else {
		nbChar = size / sizeof(wchar_t);
		*ws = std::wstring(data, data + nbChar).data();
	}
	delete[] data;
	return hresult;
}

// Lit une valeur multi chaîne en base de registre. Chaque chaîne se termine par \0
// Les caractères non imprimable sont remplacés par ?
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::vector<std::wstring>* out)
{
	//les REG_MULTI_SZ sont stockées sous forme de wchar_t = 16 bit par caractère et d'un succession de chaîne séparées par \0 et à la fin \0\0
	DWORD size = 0;
	wchar_t* data = NULL;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, subKey, valueName, (LPBYTE*)&data, &size);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
		return hresult;
	}
	else {
		/* CE QUI ÉTAIT FAUX. La boucle relisait `donnees` à chaque tour sans
		   jamais avancer le pointeur : seul le compteur de position progressait.
		   Toute valeur REG_MULTI_SZ ressortait donc comme sa PREMIÈRE chaîne,
		   répétée autant de fois qu'il y avait de caractères à parcourir —
		   observé sur `DependOnService` (« RPCSS » cinq fois) et sur
		   `HardwareId` des périphériques USB.

		   La borne est désormais calculée sur le tampon, sans faire confiance à
		   un éventuel \0 final : une valeur tronquée dans la ruche ferait sinon
		   lire au-delà. */
		const size_t nbCar = size / sizeof(wchar_t);
		size_t pos = 0;
		while (pos < nbCar) {
			size_t end = pos;
			while (end < nbCar && data[end] != L'\0') ++end;
			if (end > pos) out->push_back(std::wstring(data + pos, end - pos));
			if (end >= nbCar) break;          // tampon epuise
			pos = end + 1;                    // apres le \0 separateur
			if (pos < nbCar && data[pos] == L'\0') break;   // \0\0 = fin de liste
		}
	}
	delete[] data;
	return ERROR_SUCCESS;
}

std::wstring getVolumeLetter(std::wstring searchSerial) {
	/*  RÉÉCRITE (2026-09-15). La version d'origine cumulait :
	 *    - `return Names;` alors que `Names` valait NULL et que la fonction rend
	 *      un `std::wstring` : construire une chaîne depuis un pointeur nul est
	 *      un comportement indéfini, sur le chemin même de l'échec ;
	 *    - le `return` du milieu de boucle abandonnait le tampon `Names` ET le
	 *      handle de recherche de volumes, jamais fermé ;
	 *    - `while (Success == ERROR_MORE_DATA)` comparait un BOOL (0 ou 1) au
	 *      code 234 : la condition était TOUJOURS fausse, donc la boucle de
	 *      redimensionnement du tampon ne s'exécutait jamais. Si le tampon
	 *      initial ne suffisait pas, on construisait la chaîne à partir de
	 *      mémoire non initialisée.
	 *  Le tampon est désormais un vecteur, le handle fermé sur tous les chemins,
	 *  et le redimensionnement testé correctement.
	 */
	WCHAR volume[MAX_PATH + 1] = L"";
	log(3, L"🔈FindFirstVolumeW");
	HANDLE recherche = FindFirstVolumeW(volume, ARRAYSIZE(volume));
	if (recherche == INVALID_HANDLE_VALUE) {
		log(2, L"🔥FindFirstVolumeW", GetLastError());
		return L"";
	}

	std::wstring found;
	do {
		// Points de montage du volume. Le tampon est agrandi tant que l'API le
		// demande, ce que le test d'origine ne faisait jamais.
		std::vector<wchar_t> paths(MAX_PATH);
		DWORD nbCar = (DWORD)paths.size();
		BOOL ok = FALSE;
		for (int attempt = 0; attempt < 3; ++attempt) {
			log(3, L"🔈GetVolumePathNamesForVolumeNameW");
			ok = GetVolumePathNamesForVolumeNameW(volume, paths.data(),
			                                      (DWORD)paths.size(), &nbCar);
			if (ok || GetLastError() != ERROR_MORE_DATA) break;
			paths.assign(nbCar ? nbCar : paths.size() * 2, L'\0');
		}
		if (!ok) {
			log(2, L"🔥GetVolumePathNamesForVolumeNameW " + std::wstring(volume),
			    GetLastError());
		}
		else {
			DWORD serialNumber = 0;
			log(3, L"🔈GetVolumeInformationW");
			/* Le resultat etait ignore. Sur un volume sans media (lecteur de
			   carte vide, lecteur optique), l'appel echoue et numeroSerie reste
			   a zero : on comparait alors un numero de serie nul, si bien qu'une
			   recherche de « 0 » aurait designe un volume au hasard. */
			if (!GetVolumeInformationW(volume, NULL, NULL, &serialNumber,
			                           NULL, NULL, NULL, NULL)) {
				log(2, L"🔥GetVolumeInformationW " + std::wstring(volume),
				    GetLastError());
			}
			else {
				/* %08X, en majuscules et sur huit chiffres : c'est la forme
				   canonique du numero de serie et, surtout, celle que produit
				   l'appelant (cf. prefetchs.cpp). Un flux `std::hex` sans
				   largeur imposee rendait « a1b2c3d » la ou l'autre cote
				   attendait « 0A1B2C3D » : la comparaison echouait alors en
				   silence sur tout volume dont le premier octet est < 0x10. */
				wchar_t hexa[9] = L"";
				swprintf(hexa, 9, L"%08X", serialNumber);
				if (std::wstring(hexa) == searchSerial) {
					// Premier point de montage, chaine terminee par un zero.
					const std::wstring path(paths.data());
					// On ne garde que « C: », sans la barre oblique inverse.
					found = replaceAll(path, L"\\", L"");
					break;
				}
			}
		}
		log(3, L"🔈FindNextVolumeW");
	} while (FindNextVolumeW(recherche, volume, ARRAYSIZE(volume)));

	log(3, L"🔈FindVolumeClose");
	FindVolumeClose(recherche);   // ferme sur TOUS les chemins, y compris le succes
	return found;
}

HRESULT writeJsonFile(const std::string& name, const Json& value) {
	std::error_code ec;
	std::filesystem::create_directories(conf._outputDir, ec); // pas d'erreur si présent
	std::wofstream f;
	f.open(conf._outputDir + "/" + name);
	if (!f) {
		log(2, L"🔥Ouverture du fichier de sortie impossible : " + string_to_wstring(name));
		return E_FAIL;
	}
	f << ansi_to_utf8(value.dump(0));
	f.close();
	return ERROR_SUCCESS;
}

JsonArrayWriter::JsonArrayWriter(const std::string& name) : name_(name) {
	std::error_code ec;
	std::filesystem::create_directories(conf._outputDir, ec);  // pas d'erreur si présent
	f_.open(conf._outputDir + "/" + name);
	if (!f_) {
		log(2, L"🔥Ouverture du fichier de sortie impossible : " + string_to_wstring(name));
		return;
	}
	open_ = true;
	f_ << L"[";
}

void JsonArrayWriter::add(const Json& element) {
	if (!open_ || closed_) return;
	// La virgule précède l'élément : on ne sait pas, en écrivant, s'il en
	// viendra d'autres — c'est ce qui évite la virgule finale sans relecture.
	f_ << (written_ ? L",\n\t" : L"\n\t");
	f_ << ansi_to_utf8(element.dump(1));
	++written_;
}

HRESULT JsonArrayWriter::close() {
	if (!open_ || closed_) return open_ ? ERROR_SUCCESS : E_FAIL;
	closed_ = true;
	if (written_) f_ << L"\n";
	f_ << L"]";
	const bool good = f_.good();
	f_.close();
	if (!good) {
		log(2, L"🔥Ecriture incomplete : " + string_to_wstring(name_));
		return E_FAIL;
	}
	return ERROR_SUCCESS;
}

JsonArrayWriter::~JsonArrayWriter() {
	// Sans cela, un retour anticipé laisserait un tableau JSON non refermé :
	// un fichier invalide se lit comme « rien collecté », pas comme une erreur.
	close();
}

HRESULT writeNotCollected(const std::string& name, const std::wstring& artefact,
                          HRESULT result) {
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"NotCollected"));
	o.add(L"Error",            Json::str(L"0x" + to_hex(result) + L" " + getErrorMessage(result)));
	// Sans cette precision, un tableau vide et une lecture en echec se lisent de
	// la meme facon : « aucune trace ».
	o.add(L"Note",             Json::str(L"La lecture de cet artefact a échoué : "
	                                     L"l'absence de données ci-dessus ne signifie PAS "
	                                     L"qu'aucune trace n'existe sur le système."));
	return writeJsonFile(name, o);
}

//! Minuscules ASCII : suffisant pour des extensions de fichiers.
static std::wstring toLowerAscii(std::wstring s) {
	for (wchar_t& c : s) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
	return s;
}

std::vector<std::filesystem::path> listFilesByExtension(const std::filesystem::path& directory,
	const std::vector<std::wstring>& extensions) {
	std::vector<std::filesystem::path> results;
	std::error_code ec;
	std::filesystem::directory_iterator it(directory, ec);
	if (ec) {                                    // absent ou illisible : cas nominal
		log(4, L"🔈Repertoire non parcouru : " + directory.wstring());
		return results;
	}
	std::vector<std::wstring> expectedExtensions;   // abaissees une seule fois
	expectedExtensions.reserve(extensions.size());
	for (const std::wstring& e : extensions) expectedExtensions.push_back(toLowerAscii(e));

	for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
		if (ec) {                                // parcours interrompu : on garde l'acquis
			log(2, L"🔥Parcours interrompu : " + directory.wstring());
			break;
		}
		std::error_code fileWriter;
		if (!it->is_regular_file(fileWriter) || fileWriter) continue;
		const std::wstring ext = toLowerAscii(it->path().extension().wstring());
		for (const std::wstring& wanted : expectedExtensions) {
			if (ext == wanted) { results.push_back(it->path()); break; }
		}
	}
	return results;
}

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
bool sortieEstConsole() {
	static const bool console =
		GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR;
	return console;
}
bool g_progressionEnCours = false;
std::wstring g_etapeCourante;          //!< dernier libellé posé par printStep
} // namespace

void printStep(const std::wstring& libelle) {
	g_etapeCourante = libelle;
	wprintf(L"%ls", libelle.c_str());
}

void printProgress(const std::wstring& libelle, unsigned long long fait,
                   unsigned long long total, const wchar_t* unite) {
	if (!sortieEstConsole()) return;

	/* Limitation par le TEMPS, et non par le nombre d'éléments.
	 * Un pas fixe ne peut pas convenir aux deux extrêmes rencontrés : 38
	 * shellbags dont chacun prend des secondes (un pas de 50 ne se déclenchait
	 * jamais, d'où une impression de blocage) et 3000 entrées amcache qui
	 * défilent instantanément (l'affichage coûtait alors plus que le travail).
	 * Un rafraîchissement toutes les 150 ms reste fluide à l'œil quel que soit
	 * le rythme. Le dernier appel (fait == total) passe toujours, pour que la
	 * ligne finisse sur la valeur exacte. */
	static ULONGLONG dernierAffichage = 0;
	const ULONGLONG maintenant = GetTickCount64();
	const bool dernier = (total > 0 && fait >= total);
	if (!dernier && maintenant - dernierAffichage < 150) return;
	dernierAffichage = maintenant;

	// Le libelle est tronque pour que la ligne ne depasse pas et ne provoque pas
	// de retour a la ligne, qui casserait la reecriture sur place.
	std::wstring court = libelle;
	if (court.size() > 40) court = L"..." + court.substr(court.size() - 37);

	if (total > 0)
		wprintf(L"\r   %-40ls %llu/%llu %ls (%llu%%)   ", court.c_str(), fait, total,
		        unite, (unsigned long long)(fait * 100ULL / total));
	else
		wprintf(L"\r   %-40ls %llu %ls   ", court.c_str(), fait, unite);
	fflush(stdout);
	g_progressionEnCours = true;
}

void printProgressEnd() {
	if (!sortieEstConsole() || !g_progressionEnCours) return;
	// Efface la ligne de progression, puis remet le libellé de l'étape : sans lui
	// le « OK » qui suit apparaîtrait seul, sans dire à quoi il se rapporte.
	wprintf(L"\r%-100ls\r", L"");
	if (!g_etapeCourante.empty()) wprintf(L"%ls", g_etapeCourante.c_str());
	fflush(stdout);
	g_progressionEnCours = false;
}

void printSuccess() {
	// Restaure le libelle d'etape si une progression l'a efface, pour que le
	// « OK » reste rattache a son etape.
	printProgressEnd();
	SetConsoleTextAttribute(conf.hConsole, 10);
	wprintf(L"OK\n");
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printProgressStep(const std::wstring& artefact, unsigned long long fait,
                       unsigned long long total) {
	/* La limitation de fréquence est assurée par printProgress (par le temps) :
	   elle vaut pour tous les rythmes, du shellbag de plusieurs secondes aux
	   milliers d'entrées amcache instantanées.
	   Unité en ASCII pur, sans accent : la console est en CP_UTF8, mais wprintf
	   convertit les wchar_t selon la locale C du programme, qui ne l'est pas — un
	   caractère accentué y ressortirait en idéogrammes. */
	printProgress(artefact, fait, total, L"elem");
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

std::wstring dump_wstring(LPBYTE buffer, int start, int longueur) {
	// Borne EXCLUSIVE : « longueur » octets depuis « start » (cf. tools.h).
	if (!buffer || longueur <= 0) return L"";
	std::wstringstream ss;
	for (int x = start; x < start + longueur; x++)
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
	const auto trouve = cache.find(_sid);
	if (trouve != cache.end()) return trouve->second;

	std::wstring nom;
	PSID pSID = NULL;
	log(3, L"🔈ConvertStringSidToSidW");
	if (ConvertStringSidToSidW(_sid.c_str(), &pSID)) {
		wchar_t lpName[256] = L"";
		wchar_t lpDomain[256] = L"";
		DWORD tailleNom = 256, tailleDomaine = 256;   // deux tailles distinctes
		SID_NAME_USE typeSid = SidTypeUnknown;
		log(3, L"🔈LookupAccountSidW");
		if (LookupAccountSidW(NULL, pSID, lpName, &tailleNom,
		                      lpDomain, &tailleDomaine, &typeSid))
			nom = lpName;
		else
			log(3, L"🔈LookupAccountSidW sans correspondance", GetLastError());
		LocalFree(pSID);                              // alloue par ConvertStringSidToSidW
	}

	// Mémorisé même vide : un SID non résoluble le restera, inutile d'attendre
	// une nouvelle fois le délai réseau à chaque occurrence.
	cache.emplace(_sid, nom);
	return nom;
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
void deuxChiffres(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! Quatre chiffres : "2026".
void quatreChiffres(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 1000) % 10);
	out += (wchar_t)(L'0' + (v / 100) % 10);
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! Vrai si le FILETIME est nul (époque 1601) : pas une date, une absence de date.
bool dateNulle(const FILETIME& ft) {
	return ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0;
}

//! Décalage de la machine d'EXÉCUTION (repli quand la ruche n'est pas lisible).
long biaisMachineMinutes() {
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
	const long biais = conf.timeZone.valid ? conf.timeZone.activeBiasMinutes
	                                       : biaisMachineMinutes();
	const long minutes = -biais;          // minutes à ajouter à l'UTC pour l'heure locale
	std::wstring s;
	s += (minutes < 0) ? L'-' : L'+';
	const long absolu = (minutes < 0) ? -minutes : minutes;
	deuxChiffres(s, (unsigned)(absolu / 60));
	s += L':';
	deuxChiffres(s, (unsigned)(absolu % 60));
	return s;
}

HRESULT loadProfileList() {
	PCWSTR CLE = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
	HKEY hKey = NULL;
	log(3, L"🔈RegOpenKeyExW ProfileList");
	HRESULT hresult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, CLE, 0, KEY_READ, &hKey);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥RegOpenKeyExW ProfileList", hresult);
		return hresult;
	}

	for (DWORD i = 0; ; ++i) {
		WCHAR sid[MAX_KEY_NAME] = L"";
		DWORD taille = MAX_KEY_NAME;
		log(3, L"🔈RegEnumKeyExW ProfileList " + std::to_wstring(i));
		hresult = RegEnumKeyExW(hKey, i, sid, &taille, NULL, NULL, NULL, NULL);
		if (hresult == ERROR_NO_MORE_ITEMS) break;
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥RegEnumKeyExW ProfileList", hresult);
			break;
		}

		HKEY hProfil = NULL;
		if (RegOpenKeyExW(hKey, sid, 0, KEY_READ, &hProfil) != ERROR_SUCCESS) continue;
		DWORD octets = 0;
		if (RegQueryValueExW(hProfil, L"ProfileImagePath", NULL, NULL, NULL, &octets) == ERROR_SUCCESS
		    && octets >= sizeof(wchar_t)) {
			std::vector<BYTE> tampon(octets + sizeof(wchar_t), 0);
			if (RegQueryValueExW(hProfil, L"ProfileImagePath", NULL, NULL,
			                     tampon.data(), &octets) == ERROR_SUCCESS) {
				std::wstring chemin = (PCWSTR)tampon.data();
				/* `ProfileImagePath` est un REG_EXPAND_SZ : pour les comptes de
				   service, il vaut litteralement
				   « %systemroot%\system32\config\systemprofile ». Sans
				   developpement, le chemin ne designe aucun fichier et
				   l'extraction brute de leur ntuser.dat echoue en silence — ce
				   qui s'observait comme une extraction « partielle » sans cause
				   apparente. */
				if (chemin.find(L'%') != std::wstring::npos) {
					wchar_t developpe[MAX_PATH] = L"";
					const DWORD n = ExpandEnvironmentStringsW(chemin.c_str(),
					                                          developpe, MAX_PATH);
					if (n > 0 && n <= MAX_PATH) {
						log(2, L"❇️Profil developpe : " + chemin + L" -> " + developpe);
						chemin = developpe;
					}
					else
						log(2, L"🔥ExpandEnvironmentStringsW " + chemin, GetLastError());
				}
				if (!chemin.empty()) {
					conf.profiles.push_back({ sid, chemin });
					log(2, L"❇️Profil : " + std::wstring(sid) + L" -> " + chemin);
				}
			}
		}
		RegCloseKey(hProfil);
	}
	RegCloseKey(hKey);
	log(2, L"❇️" + std::to_wstring(conf.profiles.size()) + L" profils utilisateurs releves");
	return conf.profiles.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

std::wstring volumeDuChemin(const std::wstring& absolu) {
	if (absolu.size() >= 2 && absolu[1] == L':')
		return std::wstring(1, (wchar_t)towupper(absolu[0]));
	// Chemin deja relatif a une racine : il appartient au volume systeme.
	return conf.systemDrive.substr(0, 1);
}

std::wstring cheminRelatifAuVolume(const std::wstring& absolu) {
	if (absolu.size() >= 2 && absolu[1] == L':') return absolu.substr(2);
	return absolu;
}

std::wstring cheminSous(const std::wstring& racine, const std::wstring& absolu) {
	const std::wstring volume   = volumeDuChemin(absolu);
	const std::wstring relatif  = cheminRelatifAuVolume(absolu);
	const std::wstring systeme  = conf.systemDrive.substr(0, 1);
	if (enMinuscules(volume) == enMinuscules(systeme))
		return racine + relatif;                   // cas courant : rien ne change
	// Volume secondaire : sous-dossier dedie, pour ne pas ecraser une copie
	// homonyme venant d'un autre disque.
	return racine + L"\\_volume_" + volume + relatif;
}

std::wstring cheminExtrait(const std::wstring& absolu) {
	return cheminSous(conf.mountpoint, absolu);
}

std::wstring cheminOriginal(const std::wstring& extrait) {
	std::wstring reste = replaceAll(extrait, conf.mountpoint, L"");
	// « \_volume_D\... » : le fichier venait d'un autre disque que Windows.
	const std::wstring marque = L"\\_volume_";
	if (reste.compare(0, marque.size(), marque) == 0
	    && reste.size() > marque.size()) {
		const wchar_t lettre = reste[marque.size()];
		return std::wstring(1, lettre) + L":" + reste.substr(marque.size() + 1);
	}
	return conf.systemDrive + reste;
}

void loadSystemDrive() {
	/* GetSystemDirectoryW rend "X:\Windows\System32" : les deux premiers
	   caractères donnent le lecteur. Préféré à la variable d'environnement
	   %SystemDrive%, qui peut être altérée par le processus appelant. */
	wchar_t tampon[MAX_PATH] = L"";
	const UINT n = GetSystemDirectoryW(tampon, MAX_PATH);
	if (n >= 2 && tampon[1] == L':') {
		conf.systemDrive = std::wstring(tampon, 2);
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

	PCWSTR cle = L"Control\\TimeZoneInformation";
	DWORD activeBias = 0;
	log(3, L"🔈getRegDwordValue ActiveTimeBias");
	HRESULT hresult = getRegDwordValue(conf.CurrentControlSet, cle, L"ActiveTimeBias", &activeBias);
	if (hresult != ERROR_SUCCESS) {
		/* ActiveTimeBias absent : on recompose Bias + biais saisonnier. On ne
		   peut pas savoir lequel des deux s'appliquait au moment de chaque
		   artefact, donc on prend Bias seul et on le signale. */
		DWORD bias = 0;
		log(3, L"🔈getRegDwordValue Bias");
		hresult = getRegDwordValue(conf.CurrentControlSet, cle, L"Bias", &bias);
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
	if (getRegDwordValue(conf.CurrentControlSet, cle, L"Bias", &biasStandard) == ERROR_SUCCESS) {
		conf.timeZone.standardBiasMinutes = (long)(int32_t)biasStandard;
		conf.timeZone.daylightInEffect =
			(conf.timeZone.activeBiasMinutes != conf.timeZone.standardBiasMinutes);
	}
	else
		conf.timeZone.standardBiasMinutes = conf.timeZone.activeBiasMinutes;

	getRegSzValue(conf.CurrentControlSet, cle, L"TimeZoneKeyName", &conf.timeZone.keyName);
	getRegSzValue(conf.CurrentControlSet, cle, L"StandardName",    &conf.timeZone.standardName);
	getRegSzValue(conf.CurrentControlSet, cle, L"DaylightName",    &conf.timeZone.daylightName);
	conf.timeZone.fromHive = true;
	conf.timeZone.valid    = true;

	log(2, L"❇️Fuseau du suspect (ruche SYSTEM) : " + conf.timeZone.keyName
	     + L", UTC" + localUtcOffsetString());
	return ERROR_SUCCESS;
}

std::wstring timeToIso8601(const SYSTEMTIME& st, bool utc) {
	if (st.wYear <= 1601) return L"";        // date nulle : chaîne vide, pas 1601
	std::wstring s;
	s.reserve(25);
	quatreChiffres(s, st.wYear);   s += L'-';
	deuxChiffres(s, st.wMonth);    s += L'-';
	deuxChiffres(s, st.wDay);      s += L'T';
	deuxChiffres(s, st.wHour);     s += L':';
	deuxChiffres(s, st.wMinute);   s += L':';
	deuxChiffres(s, st.wSecond);
	if (utc) s += L'Z';
	else     s += localUtcOffsetString();
	return s;
}

std::wstring timeToIso8601Utc(const FILETIME& filetime) {
	if (dateNulle(filetime)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&filetime, &st)) return L"";
	return timeToIso8601(st, true);
}

std::wstring timeToIso8601Local(const FILETIME& filetime) {
	if (dateNulle(filetime)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&filetime, &st)) return L"";
	return timeToIso8601(st, false);
}

bool utcVersLocalSuspect(const FILETIME& filetimeUtc, FILETIME* filetimeLocal) {
	if (!filetimeLocal) return false;
	*filetimeLocal = FILETIME{ 0, 0 };
	if (dateNulle(filetimeUtc)) return false;
	/* Le biais est en minutes à AJOUTER à l'heure locale pour obtenir l'UTC
	   (convention de la ruche) : l'heure locale s'obtient donc en le
	   RETRANCHANT de l'UTC. Même source que localUtcOffsetString(), afin que la
	   valeur et son étiquette parlent du même fuseau. */
	const long biais = conf.timeZone.valid ? conf.timeZone.activeBiasMinutes
	                                       : biaisMachineMinutes();
	const ULONGLONG utc100ns = ((ULONGLONG)filetimeUtc.dwHighDateTime << 32)
	                         | filetimeUtc.dwLowDateTime;
	const long long decalage100ns = (long long)biais * 60LL * 10000000LL;
	if ((long long)utc100ns < decalage100ns) return false;   // sous l'epoque : aberrant
	const ULONGLONG local100ns = (ULONGLONG)((long long)utc100ns - decalage100ns);
	filetimeLocal->dwLowDateTime  = (DWORD)(local100ns & 0xFFFFFFFFULL);
	filetimeLocal->dwHighDateTime = (DWORD)(local100ns >> 32);
	return true;
}

std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc) {
	FILETIME local = { 0, 0 };
	if (!utcVersLocalSuspect(filetimeUtc, &local)) return L"";
	return timeToIso8601Local(local);
}

std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal) {
	if (dateNulle(filetimeLocal)) return L"";
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

bool estReferenceMui(const std::wstring& valeur) {
	/* Forme reconnue : « @<fichier>,-<id> ». Le « @ » initial seul ne suffit
	   pas : certaines descriptions commencent par une arobase sans être des
	   références. La virgule suivie du signe moins est le marqueur fiable. */
	if (valeur.size() < 4 || valeur.front() != L'@') return false;
	const size_t virgule = valeur.rfind(L',');
	return virgule != std::wstring::npos
	    && virgule + 1 < valeur.size()
	    && valeur[virgule + 1] == L'-';
}

std::wstring enMinuscules(std::wstring s) {
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
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, LPBYTE* octets, DWORD* taille)
{
	//Attention octets doit être suffisamment grand pour accepter les données LPBYTE octets = new BYTE[MAX_DATA]; si la taille n'est pas connue
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD typeValeur = 0;
	HRESULT hresult = 0;
	if (*octets != NULL)
		delete[] * octets; // on supprime tout buffer passé en paramètre pour ne pas avoir de memory leak;
	do {
		*octets = new BYTE[*taille];
		memset(*octets, 0, *taille);
		log(3, L"🔈ORGetValue");
		hresult = ORGetValue(key, sousCle, nomValeur, &typeValeur, *octets, taille); //lecture des données
	} while (hresult == ERROR_MORE_DATA);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue", hresult);
	}

	return hresult;
}


// Lire une valeur booléenne en base de registre
HRESULT getRegboolValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, bool* valeur)
{
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD taille = 0;
	LPBYTE octets = NULL;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, sousCle, nomValeur, &octets, &taille);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		*valeur = (bool)octets[0];
	}
	delete[] octets;
	return hresult;
}

// Lit une valeur FILETIME en base de registre
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, FILETIME* filetime)
{
	//les REG_FILETIME  sont stockées sous forme de bytes
	// leur type est soit REG_BINARY soi REG_FILETIME(16) 
	DWORD taille = 0;
	LPBYTE donnees = new BYTE[taille + 2];
	HRESULT hresult = 0;

	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, sousCle, nomValeur, &donnees, &taille);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		FILETIME temp = { 0 };
		temp = *reinterpret_cast<FILETIME*>(donnees);
		*filetime = temp;
	}

	delete[] donnees;
	return hresult;
}

// Lire une chaîne de caractère en base de registre
// S'assure que la chaîne est printable et se termine par \0. Si un caractère n'est pas imprimable il est remplacé par ?
HRESULT getRegDwordValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, DWORD* pdword)
{
	DWORD taille = 0;
	LPBYTE donnees = NULL;
	log(3, L"🔈getRegBinaryValue");
	HRESULT hresult = getRegBinaryValue(key, sousCle, nomValeur, &donnees, &taille);
	if (hresult != ERROR_SUCCESS) return hresult;
	// Une valeur plus courte que 4 octets n'est pas un DWORD exploitable.
	if (taille < sizeof(DWORD)) { delete[] donnees; return ERROR_INVALID_DATA; }
	*pdword = *reinterpret_cast<DWORD*>(donnees);
	delete[] donnees;
	return ERROR_SUCCESS;
}

HRESULT getRegQwordValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, unsigned long long* pqword)
{
	DWORD taille = 0;
	LPBYTE donnees = NULL;
	log(3, L"🔈getRegBinaryValue");
	HRESULT hresult = getRegBinaryValue(key, sousCle, nomValeur, &donnees, &taille);
	if (hresult != ERROR_SUCCESS) return hresult;
	// Une valeur plus courte que 8 octets n'est pas un QWORD exploitable.
	if (taille < sizeof(unsigned long long)) { delete[] donnees; return ERROR_INVALID_DATA; }
	memcpy(pqword, donnees, sizeof(unsigned long long));
	delete[] donnees;
	return ERROR_SUCCESS;
}

HRESULT getRegSzValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, std::wstring* ws)
{
	//les REG_SZ sont stockées sous forme de wchar_t = 16 bit par caractère
	DWORD taille = 0;
	LPWSTR donnees = NULL;
	size_t nbChar = 0;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, sousCle, nomValeur, (LPBYTE*)&donnees, &taille);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
		return hresult;
	}
	else {
		nbChar = taille / sizeof(wchar_t);
		*ws = std::wstring(donnees, donnees + nbChar).data();
	}
	delete[] donnees;
	return hresult;
}

// Lit une valeur multi chaîne en base de registre. Chaque chaîne se termine par \0
// Les caractères non imprimable sont remplacés par ?
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, std::vector<std::wstring>* out)
{
	//les REG_MULTI_SZ sont stockées sous forme de wchar_t = 16 bit par caractère et d'un succession de chaîne séparées par \0 et à la fin \0\0
	DWORD taille = 0;
	wchar_t* donnees = NULL;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, sousCle, nomValeur, (LPBYTE*)&donnees, &taille);
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
		const size_t nbCar = taille / sizeof(wchar_t);
		size_t pos = 0;
		while (pos < nbCar) {
			size_t fin = pos;
			while (fin < nbCar && donnees[fin] != L'\0') ++fin;
			if (fin > pos) out->push_back(std::wstring(donnees + pos, fin - pos));
			if (fin >= nbCar) break;          // tampon epuise
			pos = fin + 1;                    // apres le \0 separateur
			if (pos < nbCar && donnees[pos] == L'\0') break;   // \0\0 = fin de liste
		}
	}
	delete[] donnees;
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

	std::wstring trouve;
	do {
		// Points de montage du volume. Le tampon est agrandi tant que l'API le
		// demande, ce que le test d'origine ne faisait jamais.
		std::vector<wchar_t> chemins(MAX_PATH);
		DWORD nbCar = (DWORD)chemins.size();
		BOOL ok = FALSE;
		for (int essai = 0; essai < 3; ++essai) {
			log(3, L"🔈GetVolumePathNamesForVolumeNameW");
			ok = GetVolumePathNamesForVolumeNameW(volume, chemins.data(),
			                                      (DWORD)chemins.size(), &nbCar);
			if (ok || GetLastError() != ERROR_MORE_DATA) break;
			chemins.assign(nbCar ? nbCar : chemins.size() * 2, L'\0');
		}
		if (!ok) {
			log(2, L"🔥GetVolumePathNamesForVolumeNameW " + std::wstring(volume),
			    GetLastError());
		}
		else {
			DWORD numeroSerie = 0;
			log(3, L"🔈GetVolumeInformationW");
			/* Le resultat etait ignore. Sur un volume sans media (lecteur de
			   carte vide, lecteur optique), l'appel echoue et numeroSerie reste
			   a zero : on comparait alors un numero de serie nul, si bien qu'une
			   recherche de « 0 » aurait designe un volume au hasard. */
			if (!GetVolumeInformationW(volume, NULL, NULL, &numeroSerie,
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
				swprintf(hexa, 9, L"%08X", numeroSerie);
				if (std::wstring(hexa) == searchSerial) {
					// Premier point de montage, chaine terminee par un zero.
					const std::wstring chemin(chemins.data());
					// On ne garde que « C: », sans la barre oblique inverse.
					trouve = replaceAll(chemin, L"\\", L"");
					break;
				}
			}
		}
		log(3, L"🔈FindNextVolumeW");
	} while (FindNextVolumeW(recherche, volume, ARRAYSIZE(volume)));

	log(3, L"🔈FindVolumeClose");
	FindVolumeClose(recherche);   // ferme sur TOUS les chemins, y compris le succes
	return trouve;
}

HRESULT writeJsonFile(const std::string& nom, const Json& valeur) {
	std::error_code ec;
	std::filesystem::create_directories(conf._outputDir, ec); // pas d'erreur si présent
	std::wofstream f;
	f.open(conf._outputDir + "/" + nom);
	if (!f) {
		log(2, L"🔥Ouverture du fichier de sortie impossible : " + string_to_wstring(nom));
		return E_FAIL;
	}
	f << ansi_to_utf8(valeur.dump(0));
	f.close();
	return ERROR_SUCCESS;
}

EcrivainJsonTableau::EcrivainJsonTableau(const std::string& nom) : nom_(nom) {
	std::error_code ec;
	std::filesystem::create_directories(conf._outputDir, ec);  // pas d'erreur si présent
	f_.open(conf._outputDir + "/" + nom);
	if (!f_) {
		log(2, L"🔥Ouverture du fichier de sortie impossible : " + string_to_wstring(nom));
		return;
	}
	ouvert_ = true;
	f_ << L"[";
}

void EcrivainJsonTableau::ajouter(const Json& element) {
	if (!ouvert_ || ferme_) return;
	// La virgule précède l'élément : on ne sait pas, en écrivant, s'il en
	// viendra d'autres — c'est ce qui évite la virgule finale sans relecture.
	f_ << (ecrits_ ? L",\n\t" : L"\n\t");
	f_ << ansi_to_utf8(element.dump(1));
	++ecrits_;
}

HRESULT EcrivainJsonTableau::fermer() {
	if (!ouvert_ || ferme_) return ouvert_ ? ERROR_SUCCESS : E_FAIL;
	ferme_ = true;
	if (ecrits_) f_ << L"\n";
	f_ << L"]";
	const bool bon = f_.good();
	f_.close();
	if (!bon) {
		log(2, L"🔥Ecriture incomplete : " + string_to_wstring(nom_));
		return E_FAIL;
	}
	return ERROR_SUCCESS;
}

EcrivainJsonTableau::~EcrivainJsonTableau() {
	// Sans cela, un retour anticipé laisserait un tableau JSON non refermé :
	// un fichier invalide se lit comme « rien collecté », pas comme une erreur.
	fermer();
}

HRESULT writeNotCollected(const std::string& nom, const std::wstring& artefact,
                          HRESULT resultat) {
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"NotCollected"));
	o.add(L"Error",            Json::str(L"0x" + to_hex(resultat) + L" " + getErrorMessage(resultat)));
	// Sans cette precision, un tableau vide et une lecture en echec se lisent de
	// la meme facon : « aucune trace ».
	o.add(L"Note",             Json::str(L"La lecture de cet artefact a échoué : "
	                                     L"l'absence de données ci-dessus ne signifie PAS "
	                                     L"qu'aucune trace n'existe sur le système."));
	return writeJsonFile(nom, o);
}

//! Minuscules ASCII : suffisant pour des extensions de fichiers.
static std::wstring toLowerAscii(std::wstring s) {
	for (wchar_t& c : s) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
	return s;
}

std::vector<std::filesystem::path> listFilesByExtension(const std::filesystem::path& repertoire,
	const std::vector<std::wstring>& extensions) {
	std::vector<std::filesystem::path> resultats;
	std::error_code ec;
	std::filesystem::directory_iterator it(repertoire, ec);
	if (ec) {                                    // absent ou illisible : cas nominal
		log(4, L"🔈Repertoire non parcouru : " + repertoire.wstring());
		return resultats;
	}
	std::vector<std::wstring> attendues;         // abaissees une seule fois
	attendues.reserve(extensions.size());
	for (const std::wstring& e : extensions) attendues.push_back(toLowerAscii(e));

	for (const std::filesystem::directory_iterator fin; it != fin; it.increment(ec)) {
		if (ec) {                                // parcours interrompu : on garde l'acquis
			log(2, L"🔥Parcours interrompu : " + repertoire.wstring());
			break;
		}
		std::error_code ecFichier;
		if (!it->is_regular_file(ecFichier) || ecFichier) continue;
		const std::wstring ext = toLowerAscii(it->path().extension().wstring());
		for (const std::wstring& attendue : attendues) {
			if (ext == attendue) { resultats.push_back(it->path()); break; }
		}
	}
	return resultats;
}

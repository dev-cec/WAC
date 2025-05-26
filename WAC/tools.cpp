#pragma once

#include <cstdio>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <array>
#include <windows.h>
#include <ShellAPI.h> 
#include <stdio.h>
#include <regex>
#include <comdef.h>
#include <sddl.h>
#include "tools.h"

/****************************************************
*                   FORMAT DE DONNEES               *
*****************************************************/


FatDateTime::FatDateTime(unsigned int _i) {

	i = _i;
	date = (uint16_t)(_i & 0x0ffffL);
	time = (uint16_t)(_i >> 16);
}


SYSTEMTIME FatDateTime::to_systemtime() {

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

FILETIME FatDateTime::to_filetime() {

	FILETIME f;
	if (i != 0) {
		log(3, L"🔈to_systemtime s");
		const SYSTEMTIME s = to_systemtime();
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

void printSuccess() {

	SetConsoleTextAttribute(conf.hConsole, 10);
	std::wcout << L"OK" << std::endl;
	std::wcout.flush();
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printError(std::wstring errorText) {

	SetConsoleTextAttribute(conf.hConsole, 12);
	std::wcout << errorText << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printError(HRESULT  hresult) {

	std::wstring errorText = getErrorMessage(hresult);
	SetConsoleTextAttribute(conf.hConsole, 12);
	DWORD written = 0;
	std::wcout << ansi_to_utf8(errorText) << std::endl;
	SetConsoleTextAttribute(conf.hConsole, 7);
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
	log(loglevel, message + getErrorMessage(result));
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
		std::wcout << std::setw(2) << std::setfill(L'0') << std::hex << static_cast<int>(buffer[x]) << " ";
	std::wcout << std::endl;
}

std::wstring dump_wstring(LPBYTE buffer, int start, int end) {

	std::wstringstream ss;
	for (int x = start; x <= end; x++) {
		log(3, L"🔈to_hex buffer[x]");
		ss << std::setw(2) << std::setfill(L'0') << std::hex << static_cast<int>(buffer[x]) << " ";
	}
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
	for (int i = 0; i < source.length(); ++i) {
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
	SID_NAME_USE SidType;
	wchar_t lpName[256];
	wchar_t lpDomain[256];
	PSID pSID = NULL;
	if (_sid != L"") {
		log(3, L"🔈ConvertStringSidToSidW");
		ConvertStringSidToSidW(_sid.c_str(), &pSID);
		DWORD dwSize = 256;
		log(3, L"🔈LookupAccountSidW");
		LookupAccountSidW(NULL, pSID, lpName, &dwSize, lpDomain, &dwSize, &SidType);
		return std::wstring(lpName);
	}
	return L"";
}

std::wstring luid_to_wstring(LUID luid) {

	ULONG value = ((ULONG)luid.HighPart << 32) + luid.LowPart;
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
		log(3, L"🔈time_to_wstring systemtime");
	}
	return time_to_wstring(systemtime);

}

BSTR wstring_to_bstr(std::wstring ws) {
	if (!ws.empty())
		return SysAllocStringLen(ws.data(), ws.size());
	return BSTR(L"");
}

std::wstring bstr_to_wstring(BSTR bstr)
{
	if (bstr != nullptr) {
		std::wstring ws(bstr, SysStringLen(bstr));
		return ws;
	}
	else return L"";
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

std::string wstring_to_string(const std::wstring& wstr)
{

	std::string str;
	size_t size;
	str.resize(wstr.length());
	wcstombs_s(&size, &str[0], str.size() + 1, wstr.c_str(), wstr.size());
	return str;
}

std::wstring multiSz_to_json(std::vector<std::wstring> vec, int niveau)
{
	std::wstring out = L"[\n";
	for (int i = 0; i < vec.size(); i++) { // se termine par 2 chaîne \0\0
		log(3, L"🔈replaceAll vec[i]");
		vec[i] = replaceAll(vec[i], L"\\", L"\\\\");
		out += tab(niveau + 1) + L"\"" + vec[i] + L"\"";
		if (i < vec.size() - 1) out += L",\n";
		else out += L"\n";
	}
	out += tab(niveau) + L"]";
	return out;
}

std::wstring multiFiletime_to_json(std::vector<FILETIME> vec, int niveau)
{
	std::wstring out = L"[\n";
	for (int i = 0; i < vec.size(); i++) { // se termine par 2 chaîne \0\0
		log(3, L"🔈time_to_wstring vec[i]");
		out += tab(niveau + 1) + L"\"" + time_to_wstring(vec[i]) + L"\"";
		if (i < vec.size() - 1) out += L",\n";
		else out += L"\n";
	}
	out += tab(niveau) + L"]";
	return out;
}

std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size)
{

	std::vector<std::wstring> out;
	wchar_t* d = (wchar_t*)data;
	int pos = 0;

	while (pos < size / sizeof(wchar_t))
	{

		std::wstring ws = std::wstring(d);
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
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, LPBYTE* pBytes, DWORD* dwSize)
{
	//Attention pBytes doit être suffisamment grand pour accepter les données LPBYTE pBytes = new BYTE[MAX_DATA]; si la taille n'est pas connue
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD dwType = 0;
	HRESULT hresult = 0;
	if (*pBytes != NULL)
		delete[] *pBytes; // on supprime tout buffer passé en paramètre pour ne pas avoir de memory leak;
	do {
		*pBytes = new BYTE[*dwSize];
		log(3, L"🔈ORGetValue");
		
		hresult = ORGetValue(key, szSubKey, szValue, &dwType, *pBytes, dwSize); //lecture des données
	} while (hresult == ERROR_MORE_DATA);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue", hresult);
	}

	return hresult;
}


// Lire une valeur booléenne en base de registre
HRESULT getRegboolValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, bool* pbool)
{
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD dwType = 0;
	DWORD dwSize = 0;
	LPBYTE pBytes = NULL;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, szSubKey, szValue, &pBytes, &dwSize);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		*pbool = (bool)pBytes[0];
	}
	delete[] pBytes;
	return hresult;
}

// Lit une valeur FILETIME en base de registre
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, FILETIME* filetime)
{
	//les REG_FILETIME  sont stockées sous forme de bytes
	// leur type est soit REG_BINARY soi REG_FILETIME(16) 
	DWORD dwSize = 0;
	DWORD dwType;
	LPBYTE pData = new BYTE[dwSize];
	HRESULT hresult = 0;

	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, szSubKey, szValue, &pData, &dwSize);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
	}
	else {
		FILETIME temp = { 0 };
		temp = *reinterpret_cast<FILETIME*>(pData);
		*filetime = temp;
	}

	delete[] pData;
	return hresult;
}

// Lire une chaîne de caractère en base de registre
// S'assure que la chaîne est printable et se termine par \0. Si un caractère n'est pas imprimable il est remplacé par ?
HRESULT getRegSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::wstring* ws)
{
	//les REG_SZ sont stockées sous forme de wchar_t = 16 bit par caractère
	DWORD dwType = 0;
	DWORD dwSize = 0;
	wchar_t* pData = NULL;
	DWORD nbChar = 0;
	HRESULT hresult = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, szSubKey, szValue, (LPBYTE*)&pData, &dwSize);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
		return hresult;
	}
	else {
		nbChar = dwSize / sizeof(wchar_t);
		*ws = std::wstring(pData);
	}
	delete[] pData;
	return hresult;
}

// Lit une valeur multi chaîne en base de registre. Chaque chaîne se termine par \0
// Les caractères non imprimable sont remplacés par ?
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::vector<std::wstring>* out)
{
	//les REG_MULTI_SZ sont stockées sous forme de wchar_t = 16 bit par caractère et d'un succession de chaîne séparées par \0 et à la fin \0\0
	DWORD dwType = 0;
	DWORD dwSize = 0;
	wchar_t* pData = NULL;
	HRESULT hresult = 0;
	int nbChar = 0;
	log(3, L"🔈getRegBinaryValue");
	hresult = getRegBinaryValue(key, szSubKey, szValue, (LPBYTE*)&pData, &dwSize);

	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥getRegBinaryValue", hresult);
		return hresult;
	}
	else {
		DWORD pos = 0;
		while (pos < nbChar)
		{
			std::wstring ws = std::wstring((LPWSTR)(pData), (LPWSTR)(pData)+nbChar);
			if (!ws.empty()) out->push_back(ws);
			pos += ws.length() + 1;//position du premier caractère de la chaîne suivante après le \0 de fin de chaîne de la suivante
		}
	}
	delete[] pData;
	return ERROR_SUCCESS;
}

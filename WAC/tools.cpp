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
	SYSTEMTIME date_time_values;
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
		const SYSTEMTIME s = to_systemtime();
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
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 10);
	std::cout << "OK" << std::endl;
	std::cout.flush();
	SetConsoleTextAttribute(hConsole, 7);
}



void printError(HRESULT  hresult) {
	std::wstring errorText = NULL;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	errorText = getErrorWstring(hresult);
	SetConsoleTextAttribute(hConsole, 12);
	SetConsoleOutputCP(CP_UTF8);
	//DWORD written;
	std::wcout << ansi_to_utf8(errorText) << std::endl;
	//WriteConsoleW(hConsole, errorText, wcslen(errorText), &written, nullptr); //std::wcout ne fonctionne pas pour les accents avec le format retourné par FormatmessageW
	SetConsoleTextAttribute(hConsole, 7);
}

std::wstring getErrorWstring(HRESULT hresult)
{
	LPWSTR errorText = NULL;
	if(FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		hresult,
		LANG_SYSTEM_DEFAULT,
		//MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), 
		(LPWSTR)&errorText,
		0,
		NULL))
		return replaceAll(ansi_to_utf8(std::wstring(errorText)), L"\r\n", L"");
	return L"";
}

void printError(std::wstring errorText) {
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 12);
	SetConsoleOutputCP(CP_UTF8);
	std::wcout << errorText << std::endl;
	SetConsoleTextAttribute(hConsole, 7);
}

std::string ansi_to_utf8(std::string in)
{
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
	int utf8_size = WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
		in.length(), nullptr, 0,
		nullptr, nullptr);
	std::string utf8_str(utf8_size, '\0');
	WideCharToMultiByte(CP_UTF8, 0, in.c_str(),
		in.length(), &utf8_str[0], utf8_size,
		nullptr, nullptr);

	return string_to_wstring(utf8_str);
}

BSTR bstr_concat(BSTR a, BSTR b)
{
	auto lengthA = SysStringLen(a);
	auto lengthB = SysStringLen(b);

	auto result = SysAllocStringLen(NULL, lengthA + lengthB);

	memcpy(result, a, lengthA * sizeof(OLECHAR));
	memcpy(result + lengthA, b, lengthB * sizeof(OLECHAR));

	result[lengthA + lengthB] = 0;
	return result;
}

void dump(LPBYTE buffer, int start, int end) {
	for (int x = start; x <= end; x++)
		std::wcout << to_hex(buffer[x]) << " ";
	std::wcout << std::endl;
}

std::wstring dump_wstring(LPBYTE buffer, int start, int end) {
	std::stringstream ss;
	for (int x = start; x <= end; x++)
		ss << wstring_to_string(to_hex(buffer[x])) << " ";
	return string_to_wstring(ss.str());

}
/****************************************************
*                     CHAINES                       *
*****************************************************/

std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement)
{
	size_t pos = 0;
	while ((pos = src.find(search, pos)) != std::wstring::npos) {
		src.replace(pos, search.length(), replacement);
		pos += replacement.length();
	}
	return src;
}

std::wstring ROT13(std::wstring source)
{
	std::wstring transformed;
	for (size_t i = 0; i < source.size(); ++i) {
		if (isalpha(source[i])) {
			if ((tolower(source[i]) - 'a') < 13)
				transformed.append(1, source[i] + 13);
			else
				transformed.append(1, source[i] - 13);
		}
		else {
			transformed.append(1, source[i]);
		}
	}
	return transformed;
}

void static checkWstring(wchar_t* s)
{
	for (int x = 0; x < wcslen(s); x++) {
		if (!isascii(s[x]))
			s[x] = L'?';
	}
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
	std::stringstream ss;
	ss << std::setw(2) << std::setfill('0') << std::hex << i;
	return string_to_wstring(ss.str());
}

std::wstring tab(int i) {
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
		ConvertStringSidToSidW(_sid.c_str(), &pSID);
		DWORD dwSize = 256;
		LookupAccountSidW(NULL, pSID, lpName, &dwSize, lpDomain, &dwSize, &SidType);
		return ansi_to_utf8(std::wstring(lpName));
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
	FILETIME ft;
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
		LocalFileTimeToFileTime(&filetime, &utc);
		FileTimeToSystemTime(&utc, &systemtime); //conversion filetime to systemtime
	}
	else
		FileTimeToSystemTime(&filetime, &systemtime); //conversion filetime to systemtime
	return time_to_wstring(systemtime);

}

FILETIME bytes_to_filetime(LPBYTE bytes)
{
	FILETIME* temp = (FILETIME*)bytes;
	return *temp;
}

int bytes_to_int(LPBYTE bytes)
{
	int val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

unsigned int bytes_to_unsigned_int(LPBYTE bytes)
{
	unsigned int val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

short int bytes_to_short(LPBYTE bytes)
{
	short int val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

unsigned short int bytes_to_unsigned_short(LPBYTE bytes)
{
	unsigned short int val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

double bytes_to_double(LPBYTE bytes)
{
	double val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

long bytes_to_long(LPBYTE bytes)
{
	long val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

unsigned long bytes_to_unsigned_long(LPBYTE bytes)
{
	unsigned long val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

unsigned long long bytes_to_unsigned_long_long(LPBYTE bytes)
{
	unsigned long long val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

long long bytes_to_long_long(LPBYTE bytes)
{
	long long val;
	memcpy(&val, bytes, sizeof val);
	return val;
}

unsigned char bytes_to_unsigned_char(LPBYTE bytes)
{
	unsigned char val;
	memcpy(&val, bytes, sizeof val);
	return val;
}
std::wstring bstr_to_wstring(BSTR bstr)
{
	if (_bstr_t(bstr).length() > 0) {
		std::wstring ws(bstr, SysStringLen(bstr));
		// codage ANSI mais on veut de l'UTF8
		ws = ansi_to_utf8(ws);
		ws = replaceAll(ws, L"’", L"'");
		//on doit tester si la chaîne comprend des guillemets ou des antislash pour le json final
		ws = replaceAll(ws, L"\\", L"\\\\");
		ws = replaceAll(ws, L"\"", L"\\\"");
		return ws;
	}
	else return L"";
}

std::wstring string_to_wstring(const std::string& str)
{
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
	int nbelments = vec.size();
	std::wstring out = L"[\n";
	for (int i = 0; i < vec.size(); i++) { // se termine par 2 chaîne \0\0
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
	int nbelments = vec.size();
	std::wstring out = L"[\n";
	for (int i = 0; i < vec.size(); i++) { // se termine par 2 chaîne \0\0
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
		// codage ANSI mais on veut de l'UTF8
		ws = ansi_to_utf8(ws);
		pos += ws.length() + 1;//position du premier caractère de la chaîne suivante après le \0 de fin de chaîne de la suivante
		d += ws.length() + 1;
		if (!ws.empty()) {
			out.push_back(ws);
		}
	}
	pos = 0;

	return out;
}

std::wstring guid_to_wstring(GUID guid) {
	OLECHAR* result;
	HRESULT r = StringFromCLSID(guid, &result);
	if (r == ERROR_SUCCESS)
		return std::wstring(result);
	else
		return L"";

}


/****************************************************
*                   REGISTRY                        *
*****************************************************/

// Lire une chaîne de caractère en base de registre
// S'assure que la chaîne est printable et se termine par \0. Si un caractère n'est pas imprimable il est remplacé par ?
HRESULT getRegSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::wstring* ws)
{
	//les REG_SZ sont stockées sous forme de wchar_t = 16 bit par caractère
	DWORD dwType = 0;
	DWORD dwSize = 0;

	HRESULT hresult = ORGetValue(key, szSubKey, szValue, &dwType, nullptr, &dwSize);//taille des donnes à lire
	wchar_t* data = new wchar_t[dwSize + 1];
	if (!data) return 1;
	hresult = ORGetValue(key, szSubKey, szValue, &dwType, (LPBYTE)data, &dwSize); //lecture des données
	if (hresult != ERROR_SUCCESS) return hresult;
	data[dwSize / sizeof(wchar_t)] = '\0'; // Ensure std::string terminate with \0
	checkWstring(data); // ensure std::string is printable
	*ws = std::wstring(data);
	return ERROR_SUCCESS;
}

// Lire une donnée au format binaire en base de données
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, LPBYTE pBytes)
{
	//Attention pBytes doit être suffisamment grand pour accepter les données LPBYTE pBytes = new BYTE[MAX_DATA]; si la taille n'est pas connue
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD dwType = 0;
	DWORD dwSize = MAX_DATA;

	HRESULT hresult = ORGetValue(key, szSubKey, szValue, &dwType, nullptr, &dwSize); //taille des donnes à lire
	if (hresult != ERROR_SUCCESS) return hresult;

	hresult = ORGetValue(key, szSubKey, szValue, &dwType, pBytes, &dwSize); //lecture des données
	if (hresult != ERROR_SUCCESS) return hresult;
	return ERROR_SUCCESS;
}

// Lire une valeur booléenne en base de registre
HRESULT getRegboolValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, bool* pbool)
{
	//les REG_BINARY sont stockées sous forme de bytes 
	DWORD dwType = 0;
	DWORD dwSize = 0;

	HRESULT hresult = ORGetValue(key, szSubKey, szValue, &dwType, nullptr, &dwSize); //taille des donnes à lire
	if (hresult != ERROR_SUCCESS) return hresult;

	LPBYTE pBytes = new BYTE[dwSize];
	hresult = ORGetValue(key, szSubKey, szValue, &dwType, pBytes, &dwSize); //lecture des données
	if (hresult != ERROR_SUCCESS) return hresult;
	*pbool = (bool)pBytes[0];
	return ERROR_SUCCESS;
}

// Lit une valeur FILETIME en base de registre
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, FILETIME* filetime)
{
	//les REG_FILETIME  sont stockées sous forme de bytes
	// leur type est soit REG_BINARY soi REG_FILETIME(16) 
	DWORD dwSize = MAX_DATA;
	DWORD dwType;
	HRESULT hresult = ORGetValue(key, szSubKey, szValue, &dwType, nullptr, &dwSize); //taille des donnes à lire
	// allocate memory to store the name
	LPBYTE pData = new BYTE[dwSize + 2];

	memset(pData, 0, dwSize + 2);
	// get the name, type, and data 
	hresult = ORGetValue(key, szSubKey, szValue, &dwType, pData, &dwSize); //lecture des données
	FILETIME temp = { 0 };
	temp = bytes_to_filetime(pData);
	*filetime = temp;
	return ERROR_SUCCESS;
}

// Lit une valeur multi chaîne en base de registre. Chaque chaîne se termine par \0
// Les caractères non imprimable sont remplacés par ?
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::vector<std::wstring>* out)
{
	//les REG_MULTI_SZ sont stockées sous forme de wchar_t = 16 bit par caractère et d'un succession de chaîne séparées par \0 et à la fin \0\0
	DWORD dwType = 0;
	DWORD dwSize = 0;

	HRESULT hresult = ORGetValue(key, szSubKey, szValue, &dwType, nullptr, &dwSize); //taille des donnes à lire
	if (hresult != ERROR_SUCCESS) return hresult;
	int nbChar = dwSize / sizeof(wchar_t);// dwSize en BYTES et 1 wchar_t = 2 BYTES

	wchar_t* data = new wchar_t[nbChar];
	if (!data) return 1;
	hresult = ORGetValue(key, szSubKey, szValue, &dwType, (LPBYTE)data, &dwSize); //lecture des données
	checkWstring(data);
	if (hresult != ERROR_SUCCESS) return hresult;
	DWORD pos = 0;
	while (pos < nbChar)
	{
		std::wstring ws = std::wstring(data);
		if (!ws.empty()) out->push_back(ws);
		pos += ws.length() + 1;//position du premier caractère de la chaîne suivante après le \0 de fin de chaîne de la suivante
		data += ws.length() + 1;
	}
	return ERROR_SUCCESS;
}
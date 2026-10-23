/*! \file
 *  \brief Implementation of the shared tools (see tools.h).
 */
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <array>
#include <map>
#include "sha.h"
#include <cwctype>
#include <windows.h>
#include <stdio.h>
#include <regex>
#include "tools.h"
#include "version_info.h"
#include "running_machine.h"
#include <cstring>
#include <climits>
#include <cmath>
#include <filesystem>
#include <chrono>

/****************************************************
*                   DATA FORMATS                   *
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

	FILETIME f = { 0, 0 };
	if (i == 0) return f;
	const SYSTEMTIME s = toSystemTime();
	/* The fields are masked but not validated: month 0 or 13, day 31 in
	   April, hour 24 to 31, second 60 or 62 fit in their bits. Windows refuses
	   such a date; f then stays null, and the field is not emitted. Before,
	   the refusal was ignored and f, uninitialised, emitted whatever the stack
	   held. */
	log(3, L"🔈SystemTimeToFileTime f");
	if (!SystemTimeToFileTime(&s, &f)) f = { 0, 0 };
	return f;
}

/****************************************************
*                   DISPLAY                         *
*****************************************************/

namespace {
//! True if stdout is a console: otherwise the progress is useless and noisy.
bool outputIsConsole() {
	static const bool console =
		GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR;
	return console;
}
bool g_progressRunning = false;
std::wstring g_currentStep;          //!< last label set by printStep
/* THE TIME OF EACH STEP (backlog B-033). The investigation log dates its
   operations, but most artefacts write no operation of their own: the time
   of twenty of them was charged to the next one that does — 140 s to the
   event logs, of which their reading took 25. Every step printed is timed
   from printStep to its OK or its error. */
std::chrono::steady_clock::time_point g_stepStart;                 //!< when the current step began
std::wstring g_stepEnglish;   //!< the current step's label in English, when it is a translated text
std::vector<std::pair<std::wstring, double>> g_stepTimes;         //!< each ended step and its seconds

//! Records the time of the step being ended, once.
void endStep() {
	if (g_currentStep.empty()) return;
	// The investigation log is in English whatever the console's language.
	std::wstring label = g_stepEnglish.empty() ? g_currentStep : g_stepEnglish;
	const wchar_t* blanks = L" -:";
	label.erase(0, std::min(label.find_first_not_of(blanks), label.size()));
	label.erase(std::min(label.find_last_not_of(blanks) + 1, label.size()));
	g_stepTimes.emplace_back(label, std::chrono::duration<double>(std::chrono::steady_clock::now() - g_stepStart).count());
	g_currentStep.clear();
	g_stepEnglish.clear();
}
} // namespace

/*  WHY NOT wprintf. It converts the wchar_t through the program's C locale,
    which is not UTF-8 although the console is: every accented letter of the
    French texts came out as ideograms. On a console the text goes through
    WriteConsoleW, in UTF-16; redirected to a file, where WriteConsoleW writes
    nothing, it goes through stdout in UTF-8. */
void writeConsole(const std::wstring& text) {
	if (outputIsConsole()) {
		WriteConsoleW(conf.hConsole, text.c_str(), (DWORD)text.length(), NULL, NULL);
	}
	else {
		const std::string utf8 = encodeText(text);
		fwrite(utf8.data(), 1, utf8.size(), stdout);
		fflush(stdout);
	}
}

void printStep(const std::wstring& label) {
	g_currentStep = label;
	g_stepEnglish.clear();
	g_stepStart = std::chrono::steady_clock::now();
	writeConsole(label);
}

void printStep(Text step, const std::wstring& qualifier) {
	printStep(L" - " + text(step) + qualifier + L" : ");
	g_stepEnglish = text(step, Language::English) + qualifier;
}

void printHeading(Text heading) {
	SetConsoleTextAttribute(conf.hConsole, 14);
	writeConsole(text(heading) + L"\n");
	SetConsoleTextAttribute(conf.hConsole, 7);
}

/*! The width of the console window, in characters: a line written to its
 *  last column wraps, and a rewritten progress line or its erasure then
 *  leaves a blank line behind (a console of 96 columns, measured; 80 by
 *  default in the older console).
 *  @return the width, or 80 when it cannot be read */
size_t consoleWidth() {
	CONSOLE_SCREEN_BUFFER_INFO info = {};
	if (!GetConsoleScreenBufferInfo(conf.hConsole, &info)) return 80;
	const int width = info.srWindow.Right - info.srWindow.Left + 1;
	return width > 1 ? (size_t)width : 80;
}

void printProgress(const std::wstring& label, unsigned long long done,
                   unsigned long long total, const std::wstring& unit) {
	if (!outputIsConsole()) return;

	/* Rate-limited by TIME, and not by number of elements.
	 * A fixed step cannot suit the two extremes met: 38 shellbags of which each
	 * takes seconds (a step of 50 never fired, hence an impression of being
	 * stuck) and 3,000 amcache entries that scroll instantly (the display then
	 * cost more than the work).
	 * A refresh every 150 ms stays smooth to the eye whatever the pace. The last
	 * call (done == total) always goes through, so that the line ends on the
	 * exact value. */
	static ULONGLONG lastDisplay = 0;
	const ULONGLONG now = GetTickCount64();
	const bool last = (total > 0 && done >= total);
	if (!last && now - lastDisplay < 150) return;
	lastDisplay = now;

	// The label is truncated so that the line does not overflow and cause a line
	// break, which would break the rewriting in place.
	std::wstring court = label;
	if (court.size() > 40) court = L"..." + court.substr(court.size() - 37);

	court.resize(40, L' ');
	std::wstring line = L"\r   " + court + L" " + std::to_wstring(done);
	if (total > 0)
		line += L"/" + std::to_wstring(total) + L" " + unit + L" ("
		      + std::to_wstring(done * 100ULL / total) + L"%)   ";
	else
		line += L" " + unit + L"   ";
	// Within the window, its last column left free: "\r" plus the text.
	if (line.size() > consoleWidth()) line.resize(consoleWidth());
	writeConsole(line);
	g_progressRunning = true;
}

void printProgressEnd() {
	if (!outputIsConsole() || !g_progressRunning) return;
	// Erases the progress line, then puts the step label back: without it the "OK"
	// that follows would appear alone, without saying what it refers to.
	writeConsole(L"\r" + std::wstring(consoleWidth() - 1, L' ') + L"\r" + g_currentStep);
	g_progressRunning = false;
}

void printSuccess() {
	// Restores the step label if a progress erased it, so that the "OK" stays
	// attached to its step.
	printProgressEnd();
	endStep();
	SetConsoleTextAttribute(conf.hConsole, 10);
	writeConsole(L"OK\n");
	SetConsoleTextAttribute(conf.hConsole, 7);
}

std::wstring stepTimes() {
	std::wstring text;
	for (const auto& [label, seconds] : g_stepTimes) {
		wchar_t value[32];
		swprintf(value, 32, L"%.2f s", seconds);
		text += (text.empty() ? L"" : L"; ") + label + L" " + value;
	}
	return text;
}

void printProgressStep(const std::wstring& artefact, unsigned long long done,
                       unsigned long long total) {
	/* The rate limiting is done by printProgress (by time): it holds for every
	   pace, from the shellbag of several seconds to the thousands of
	   instantaneous amcache entries. */
	printProgress(artefact, done, total, text(Text::ProgressUnit));
}

void printError(std::wstring errorText) {
	// As printSuccess does: restores the step label before writing the error.
	printProgressEnd();
	/* The line is ENDED: without the newline the next step label was printed
	   right after the error, on the same line. And WriteConsoleW writes nothing
	   when the output is redirected to a file, so the error was missing from
	   the redirected log altogether: the text then goes through stdout, in
	   UTF-8. */
	errorText += L"\n";
	endStep();
	SetConsoleTextAttribute(conf.hConsole, 12);
	writeConsole(errorText);
	SetConsoleTextAttribute(conf.hConsole, 7);
}

void printError(HRESULT  hresult) {
	printError(L"0x" + to_hex(hresult) + L" " + getErrorMessage(hresult, currentLanguage()));
}

std::wstring getErrorMessage(HRESULT hresult)
{
	// The files (JSON, logs) are in English whatever the console's language.
	return getErrorMessage(hresult, Language::English);
}

std::wstring getErrorMessage(HRESULT hresult, Language language)
{
	// used by log(), so it must not log itself
	/* The message is asked in the language wanted first, then in English, then
	   in the system's own language (0), which a system without either has.
	   FormatMessageW can fail (a code without a message): the result was then
	   built from a null pointer, which is undefined behaviour. The buffer the
	   system allocates is released, which it never was. */
	const DWORD english = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US);
	const DWORD languages[3] = {
		language == Language::French ? (DWORD)MAKELANGID(LANG_FRENCH, SUBLANG_FRENCH) : english, english, 0 };
	for (DWORD identifier : languages) {
		LPWSTR errorText = NULL;
		const DWORD n = FormatMessageW(
			FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_ALLOCATE_BUFFER
			| FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, hresult, identifier, (LPWSTR)&errorText, 0, NULL);
		if (n == 0 || errorText == NULL) continue;
		std::wstring result(errorText, n);
		LocalFree(errorText);
		result.erase(std::remove(result.begin(), result.end(), '\r'), result.cend()); // no newline
		result.erase(std::remove(result.begin(), result.end(), '\n'), result.cend()); // no newline
		while (!result.empty() && result.back() == L' ') result.pop_back();
		return result;
	}
	return L"(no system message for this code)";
}


void log(int loglevel, std::wstring message) {
	if (conf.loglevel >= loglevel && conf.loglevel > 0) {
		conf.log.open(std::filesystem::path(conf.name + L".log"), std::ios::app);
		conf.log << encodeText(tab(loglevel) + message) << std::endl;
		conf.log.flush();
		conf.log.close();
	}
}

void log(int loglevel, std::wstring message, HRESULT result) {
	log(loglevel, message + L" : " + getErrorMessage(result));
}

void dump(LPBYTE buffer, int start, int end) {

	for (int x = start; x <= end; x++)
		wprintf(L"%02X ",static_cast<int>(buffer[x]));
	wprintf(L"\n");
}

std::wstring registryTypeName(DWORD type) {
	switch (type) {
	case REG_NONE: return L"REG_NONE";
	case REG_SZ: return L"REG_SZ";
	case REG_EXPAND_SZ: return L"REG_EXPAND_SZ";
	case REG_BINARY: return L"REG_BINARY";
	case REG_DWORD: return L"REG_DWORD";
	case REG_MULTI_SZ: return L"REG_MULTI_SZ";
	case REG_QWORD: return L"REG_QWORD";
	default: return L"0x" + to_hex(type);
	}
}

Json registryValueToJson(DWORD type, const std::vector<BYTE>& data) {
	switch (type) {
	case REG_SZ:
	case REG_EXPAND_SZ:
		return Json::str(readWideZ(data.data(), data.size(), 0));
	case REG_MULTI_SZ: {
		Json list = Json::arr();
		for (size_t at = 0; at + 1 < data.size();) {
			const std::wstring s = readWideZ(data.data(), data.size(), at);
			if (s.empty()) break;
			list.push(Json::str(s));
			at += (s.size() + 1) * sizeof(wchar_t);
		}
		return list;
	}
	case REG_DWORD:
		if (data.size() >= 4) { DWORD v; memcpy(&v, data.data(), 4); return Json::num((unsigned long long)v); }
		break;
	case REG_QWORD:
		if (data.size() >= 8) { uint64_t v; memcpy(&v, data.data(), 8); return Json::num((unsigned long long)v); }
		break;
	}
	return Json::str(toHexadecimal(data.data(), data.size()));
}


std::wstring registryNameToJsonKey(const std::wstring& valueName) {
	if (valueName.empty()) return L"DefaultValue";
	std::wstring key;
	bool wordStart = true;
	for (wchar_t c : valueName) {
		if (!iswalnum(c)) { wordStart = true; continue; }
		key += wordStart ? (wchar_t)towupper(c) : c;
		wordStart = false;
	}
	return key.empty() ? L"DefaultValue" : key;
}


namespace {

//! One SID of a descriptor, with its name; nothing if it does not fit.
void addSidField(Json& o, const wchar_t* key, const BYTE* base, size_t size, size_t offset) {
	if (offset == 0 || offset >= size) return;
	const std::wstring sid = sidToText(base + offset, size - offset);
	if (sid.empty()) return;
	o.add(key, Json::str(sid));
	o.add(std::wstring(key) + L"Name", Json::str(getNameFromSid(sid)));
}

//! The ACEs of one ACL at `offset`, bounded by the ACL's declared size.
Json aclToJson(const BYTE* sd, size_t size, size_t offset) {
	Json aces = Json::arr();
	const size_t ACL_HEADER = 8, ACE_HEADER = 4;
	if (offset == 0 || offset > size || size - offset < ACL_HEADER) return aces;
	uint16_t aclSize, count;
	memcpy(&aclSize, sd + offset + 2, 2);
	memcpy(&count, sd + offset + 4, 2);
	const size_t end = std::min(size, offset + aclSize);
	size_t at = offset + ACL_HEADER;
	for (uint16_t i = 0; i < count && at + ACE_HEADER <= end; ++i) {
		const BYTE type = sd[at], flags = sd[at + 1];
		uint16_t aceSize;
		memcpy(&aceSize, sd + at + 2, 2);
		if (aceSize < ACE_HEADER || aceSize > end - at) break;
		Json ace = Json::obj();
		static const wchar_t* TYPES[] = { L"Allow", L"Deny", L"Audit", L"Alarm" };
		ace.add(L"Type", type < 4 ? Json::str(TYPES[type]) : Json::num((unsigned)type));
		ace.add(L"Flags", Json::str(to_hex(flags)));
		// Allow, Deny, Audit, Alarm: a mask then the SID; other kinds carry GUIDs first.
		if (type < 4 && aceSize >= ACE_HEADER + 4) {
			uint32_t mask;
			memcpy(&mask, sd + at + 4, 4);
			ace.add(L"Mask", Json::str(L"0x" + to_hex(mask, 8)));
			const std::wstring sid = sidToText(sd + at + 8, aceSize - 8);
			ace.add(L"Sid", Json::str(sid));
			if (!sid.empty()) ace.add(L"SidName", Json::str(getNameFromSid(sid)));
		}
		else ace.add(L"Size", Json::num((unsigned)aceSize));
		aces.push(std::move(ace));
		at += aceSize;
	}
	return aces;
}

} // namespace

Json securityDescriptorToJson(const BYTE* sd, size_t size) {
	Json o = Json::obj();
	const size_t HEADER = 20;   // revision, Sbz1, control, then four offsets
	if (size < HEADER || sd[0] != 1) return o;
	uint16_t control;
	uint32_t owner, group, sacl, dacl;
	memcpy(&control, sd + 2, 2);
	memcpy(&owner, sd + 4, 4);
	memcpy(&group, sd + 8, 4);
	memcpy(&sacl, sd + 12, 4);
	memcpy(&dacl, sd + 16, 4);
	o.add(L"Control", Json::str(L"0x" + to_hex(control, 4)));
	addSidField(o, L"Owner", sd, size, owner);
	addSidField(o, L"Group", sd, size, group);
	if (control & SE_DACL_PRESENT) o.add(L"Dacl", aclToJson(sd, size, dacl));
	if (control & SE_SACL_PRESENT) o.add(L"Sacl", aclToJson(sd, size, sacl));
	return o;
}

FILETIME unixToFiletime(unsigned long long seconds) {
	const unsigned long long ticks = (seconds + SECONDS_1601_TO_1970) * 10000000ULL;
	return filetimeFromTicks(ticks);
}

std::wstring dump_wstring(LPBYTE buffer, int start, int length) {
	// EXCLUSIVE bound: "length" bytes from "start" (see tools.h).
	if (!buffer || length <= 0) return L"";
	std::wstringstream ss;
	for (int x = start; x < start + length; x++)
		ss << std::setw(2) << std::setfill(L'0') << std::hex
		   << static_cast<int>(buffer[x]) << L" ";
	return ss.str();
}
/****************************************************
*                     STRINGS                       *
*****************************************************/

std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement)
{
	/* An empty `search` is "found" at every position without ever advancing:
	   the loop used to never end. It happens as soon as the string looked for
	   is an empty setting — originalPath() with no mount point. */
	if (search.empty()) return src;
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

		// NOT alpha
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

/*! A LUID as a decimal number (its 64 bits).
 * @param luid the LUID
 * @return the number, as text */
std::wstring luid_to_wstring(LUID luid) {
	/* FIX: a LUID is 64 bits (LowPart ULONG + HighPart LONG), but the computation
	   was done on a 32-bit ULONG. Shifting a 32-bit type by 32 is undefined
	   behaviour, and HighPart was lost: two LUIDs differing only in their high
	   part returned the same value. */
	const ULONGLONG value = ((ULONGLONG)(ULONG)luid.HighPart << 32) | (ULONGLONG)luid.LowPart;
	return std::to_wstring(value);
}

std::wstring bool_to_wstring(bool b)
{

	if (b) return L"true";
	else return L"false";
}

FILETIME wstring_to_filetime(std::wstring input, Precision* precision) {

	std::istringstream istr(encodeText(input));   // digits and separators: ASCII
	SYSTEMTIME st = { 0 };
	FILETIME ft = { 0 };
	istr >> st.wMonth;
	istr.ignore(1, '/');
	istr >> st.wDay;
	istr.ignore(1, '/');
	istr >> st.wYear;
	// Two digits: read as 1980 to 2079, a FAT date starting in 1980.
	if (!istr.fail() && st.wYear < 100) st.wYear += st.wYear < 80 ? 2000 : 1900;
	istr.ignore(1, ' ');
	istr >> st.wHour;
	istr.ignore(1, ':');
	istr >> st.wMinute;
	// At the end already, the minute read last: std::ws would then fail the stream.
	const bool withoutSeconds = !istr.fail() && (istr.eof() || (istr >> std::ws).eof());
	if (withoutSeconds && precision != nullptr) {
		*precision = Precision::Minute;
	}
	else {
		istr.ignore(1, ':');
		istr >> st.wSecond;
		if (precision != nullptr) *precision = Precision::Second;
	}
	st.wMilliseconds = 0;
	log(3, L"🔈SystemTimeToFileTime ft");
	if (istr.fail() || !SystemTimeToFileTime(&st, &ft)) return FILETIME{ 0, 0 };
	return ft;
}

///////////////////////////////////////////////////////
// ISO 8601 timestamps — see tools.h for the rationale
///////////////////////////////////////////////////////
namespace {

//! Two digits, zero in front: "07", "15".
void twoDigits(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! Four digits: "2026".
void fourDigits(std::wstring& out, unsigned v) {
	out += (wchar_t)(L'0' + (v / 1000) % 10);
	out += (wchar_t)(L'0' + (v / 100) % 10);
	out += (wchar_t)(L'0' + (v / 10) % 10);
	out += (wchar_t)(L'0' + v % 10);
}

//! True if the FILETIME is null (the 1601 epoch): not a date, an absence of date.
bool nullDate(const FILETIME& ft) {
	return ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0;
}

const long long MINUTE_100NS = 600000000LL;   //!< one minute, in hundreds of nanoseconds

/*! Rules of the RUNNING examined machine, as its snapshot recorded them: the
 *  fallback when the suspect's hive cannot be read. Only its current rule; the
 *  rules per year come from the hive. Built once. */
const TimeZoneRules& machineRules() {
	// Built once the snapshot exists: an empty rule is never kept (see runningMachine).
	static TimeZoneRules rules;
	static bool built = false;
	if (built) return rules;
	const RunningMachine& machine = runningMachine();
	if (!machine.read) return rules;
	built = true;
	if (machine.timeZoneId == TIME_ZONE_ID_INVALID) return rules;
	const TIME_ZONE_INFORMATION& tz = machine.timeZone;
	// Through the registry layout, to share the validation of parseTimeZoneRule.
	BYTE tzi[44] = {};
	const int32_t bias[3] = { (int32_t)tz.Bias, (int32_t)tz.StandardBias, (int32_t)tz.DaylightBias };
	memcpy(tzi, bias, sizeof(bias));
	memcpy(tzi + 12, &tz.StandardDate, sizeof(SYSTEMTIME));
	memcpy(tzi + 28, &tz.DaylightDate, sizeof(SYSTEMTIME));
	parseTimeZoneRule(tzi, sizeof(tzi), rules.current);
	return rules;
}

const TimeZoneRules& suspectRules() {
	return conf.timeZone.valid ? conf.timeZone.rules : machineRules();
}

//! "+HH:MM" of a bias (minutes to ADD to the local time to obtain UTC).
std::wstring offsetSuffix(long bias) {
	const long minutes = -bias;          // minutes to add to UTC to get the local time
	std::wstring s;
	s += (minutes < 0) ? L'-' : L'+';
	const long absolute = (minutes < 0) ? -minutes : minutes;
	twoDigits(s, (unsigned)(absolute / 60));
	s += L':';
	twoDigits(s, (unsigned)(absolute % 60));
	return s;
}

} // namespace


namespace {

/*! Expands the environment variables of a `ProfileImagePath`, WITHOUT querying
 *  the process's environment.
 *
 *  WHY NOT `ExpandEnvironmentStringsW`. That function reads the environment of
 *  the CURRENT process. As long as the value came from the live registry, that
 *  coincided with the examined machine; read offline in a copied hive, the value
 *  belongs to another installation than the one running WAC, and expanding it
 *  with the local environment would become a guess.
 *
 *  `ProfileImagePath` is a REG_EXPAND_SZ, and holds literally
 *  "%systemroot%\\system32\\config\\systemprofile" for the service accounts.
 *  Without expansion, the path names no file and the raw extraction of their
 *  ntuser.dat fails in silence — which showed up as a "partial" extraction with
 *  no apparent cause. */
std::wstring expandProfilePath(const std::wstring& path) {
	if (path.find(L'%') == std::wstring::npos) return path;
	const std::wstring expanded = normalizeFilePath(path);
	if (expanded.empty()) {
		log(2, L"🔥ProfileImagePath: unknown variable in " + path);
		return path;
	}
	return expanded;
}

} // namespace

const wchar_t DEFAULT_PROFILE_SID[] = L"S-0-0-0";

HRESULT loadProfileList() {
	if (!conf.Software) {
		log(2, L"🔥SOFTWARE hive unavailable: user profiles not read",
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
			log(2, L"❇️Profile expanded: " + path + L" -> " + expanded);
		if (expanded.empty()) continue;

		conf.profiles.push_back({ sid, expanded });
		log(2, L"❇️Profile: " + std::wstring(sid) + L" -> " + expanded);
	}
	/* The Default profile: the template every new profile is copied from. It
	   belongs to no account, yet a Run value or a shortcut planted there
	   reaches every user created afterwards — read like the others, under a
	   SID that cannot be one (DEFAULT_PROFILE_SID). Its path is a value of
	   ProfileList itself, not a subkey. */
	std::wstring defaultPath;
	if (getRegSzValue(hKey, NULL, L"Default", &defaultPath) == ERROR_SUCCESS) {
		const std::wstring expanded = expandProfilePath(defaultPath);
		if (!expanded.empty()) {
			conf.profiles.push_back({ DEFAULT_PROFILE_SID, expanded });
			log(2, L"❇️Default profile -> " + expanded);
		}
	}
	ORCloseKey(hKey);
	log(2, L"❇️" + std::to_wstring(conf.profiles.size()) + L" user profiles read");
	return conf.profiles.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

std::wstring volumeOfPath(const std::wstring& absolute) {
	if (absolute.size() >= 2 && absolute[1] == L':')
		return std::wstring(1, (wchar_t)towupper(absolute[0]));
	// Path already relative to a root: it belongs to the system volume.
	return conf.systemDrive.substr(0, 1);
}

std::wstring pathRelativeToVolume(const std::wstring& absolute) {
	if (absolute.size() >= 2 && absolute[1] == L':') return absolute.substr(2);
	return absolute;
}

/*! Resolves the path of a file named by `ImagePath` or `ServiceDll`.
*
*  The hive stores heterogeneous forms, which no API normalises offline:
*    - `\SystemRoot\System32\drivers\x.sys`   (kernel prefix)
*    - `\??\C:\folder\x.exe`                  (NT object path)
*    - `system32\svchost.exe -k netsvcs`      (relative to %SystemRoot%)
*    - `"C:\Program Files\App\x.exe" /service`(quotes + arguments)
*
*  WHAT WAS WRONG. The original version cut on the first occurrence of "-" or
*  "/", including inside the path: a binary installed in a folder holding a dash
*  saw its path truncated, and its MD5 was therefore never computed. Here, the
*  cut is made AFTER the file's extension, which is the only reliable marker of
*  the end of the path.
*/
std::wstring normalizeFilePath(std::wstring path) {
	// Surrounding spaces and quotes: present in Shimcache and Amcache.
	while (!path.empty() && (path.front() == L' ' || path.front() == L'"')) path.erase(0, 1);
	while (!path.empty() && (path.back() == L' ' || path.back() == L'"')) path.pop_back();
	if (path.empty()) return L"";

	std::wstring low = toLower(path);
	// NT object prefixes: "\??\C:\…" (Shimcache, ImagePath), "\\?\C:\…".
	if (low.compare(0, 4, L"\\??\\") == 0 || low.compare(0, 4, L"\\\\?\\") == 0) {
		if (low.compare(4, 4, L"unc\\") == 0) return L"";   // network share
		path.erase(0, 4);
		low.erase(0, 4);
	}
	// Kernel prefix.
	if (low.compare(0, 12, L"\\systemroot\\") == 0)
		return conf.systemDrive + L"\\Windows\\" + path.substr(12);
	// "SYSVOL\": the system volume, as the ShimCache of Windows 8 and 8.1 names it.
	if (low.compare(0, 7, L"sysvol\\") == 0)
		return conf.systemDrive + L"\\" + path.substr(7);

	/* VARIABLES, expanded from the DETECTED system drive and never from the
	   process's environment: the value belongs to the examined installation, not
	   to the one running WAC (and WAC runs as SYSTEM, whose environment says
	   nothing about the users).
	   `%windir%` is a synonym of `%systemroot%`; not handling it gave paths of
	   the kind "C:\Windows\%windir%\system32\ncsi.dll".
	   The variables SPECIFIC TO A USER (%APPDATA%, %LOCALAPPDATA%,
	   %USERPROFILE%…) are not expanded: the account is not known here, and
	   guessing would return the fingerprint of another file than the one
	   named. */
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

	// Quoted path: it ends at the closing quote.
	if (imagePath.front() == L'"') {
		const size_t end = imagePath.find(L'"', 1);
		imagePath = (end == std::wstring::npos) ? imagePath.substr(1)
		                                        : imagePath.substr(1, end - 1);
	}
	else {
		/* Without quotes, the end of the path is found by the extension. The FIRST
		   extension met is taken: what follows is an option. */
		const std::wstring low = toLower(imagePath);
		size_t end = std::wstring::npos;
		for (PCWSTR ext : { L".exe", L".sys", L".dll" }) {
			const size_t p = low.find(ext);
			if (p != std::wstring::npos && (end == std::wstring::npos || p < end))
				end = p + 4;
		}
		if (end != std::wstring::npos) imagePath = imagePath.substr(0, end);
	}

	// Kernel prefixes, NT object prefixes and variables: the common rule.
	{
		const std::wstring normalized = normalizeFilePath(imagePath);
		if (!normalized.empty()) return normalized;
		if (imagePath.find(L'%') != std::wstring::npos) return L"";   // unknown variable
	}

	/* Relative path: it is relative to %SystemRoot%, not to the current
	   directory. A service whose ImagePath is "system32\\x.exe" therefore names
	   C:\\Windows\\system32\\x.exe. */
	if (imagePath.size() < 2 || imagePath[1] != L':') {
		if (!imagePath.empty() && imagePath.front() == L'\\')
			return L"";   // \Driver\..., \FileSystem\...: a kernel object, not a file
		imagePath = conf.systemDrive + L"\\Windows\\" + imagePath;
	}
	return imagePath;
}

std::wstring pathUnder(const std::wstring& root, const std::wstring& absolute) {
	const std::wstring volume   = volumeOfPath(absolute);
	const std::wstring relative  = pathRelativeToVolume(absolute);
	const std::wstring system_  = conf.systemDrive.substr(0, 1);
	if (toLower(volume) == toLower(system_))
		return root + relative;                   // the common case: nothing changes
	// Secondary volume: a dedicated subfolder, so as not to overwrite a copy of the
	// same name coming from another disk.
	return root + L"\\_volume_" + volume + relative;
}

std::wstring extractedPath(const std::wstring& absolute) {
	return pathUnder(conf.mountpoint, examinedLayout(absolute));
}

std::wstring examinedLayout(const std::wstring& path) {
	std::vector<std::wstring> roots;
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) roots.push_back(std::get<1>(profileEntry));
	return examinedFolderLayout(path, conf.examinedVersion, roots);
}

std::wstring originalPath(const std::wstring& extracted) {
	std::wstring rest = replaceAll(extracted, conf.mountpoint, L"");
	// "\_volume_D\..." : the file came from another disk than Windows.
	const std::wstring mark = L"\\_volume_";
	if (rest.compare(0, mark.size(), mark) == 0
	    && rest.size() > mark.size()) {
		const wchar_t letter = rest[mark.size()];
		return std::wstring(1, letter) + L":" + rest.substr(mark.size() + 1);
	}
	return conf.systemDrive + rest;
}

void loadSystemDrive() {
	/* GetSystemDirectoryW returns "X:\Windows\System32": the first two characters
	   give the drive. Preferred to the environment variable %SystemDrive%, which
	   the calling process can alter. */
	wchar_t buffer[MAX_PATH] = L"";
	const UINT n = GetSystemDirectoryW(buffer, MAX_PATH);
	if (n >= 2 && buffer[1] == L':') {
		conf.systemDrive = std::wstring(buffer, 2);
		log(2, L"❇️System drive: " + conf.systemDrive);
	}
	else {
		log(2, L"🔥GetSystemDirectoryW: system drive not determined, "
		       L"falling back on " + conf.systemDrive, GetLastError());
	}
}

namespace {

//! Reads a registry value of an exact size; false if it is absent or of another size.
bool readExactValue(ORHKEY key, PCWSTR subKey, PCWSTR name, void* out, DWORD size) {
	DWORD read = size;
	return ORGetValue(key, subKey, name, nullptr, out, &read) == ERROR_SUCCESS && read == size;
}

/*! Reads the daylight saving rules of the suspect's time zone into
 *  conf.timeZone.rules. The current rule comes from the values of
 *  TimeZoneInformation (parseTimeZoneInformation: beware their layout);
 *  the rules per year come from the zone's "Dynamic DST" key in SOFTWARE.
 *  Failing that, the rule stays the offset of the collection day, without
 *  daylight saving time — the former behaviour — and the log says so.
 *  @param key the TimeZoneInformation key, under CurrentControlSet */
void loadSuspectTimeZoneRules(PCWSTR key) {
	TimeZoneRules& rules = conf.timeZone.rules;
	int32_t bias = 0, standardBias = 0, daylightBias = 0;
	BYTE standardStart[16] = {}, daylightStart[16] = {};
	if (!readExactValue(conf.CurrentControlSet, key, L"Bias", &bias, 4)
	    || !readExactValue(conf.CurrentControlSet, key, L"StandardBias", &standardBias, 4)
	    || !readExactValue(conf.CurrentControlSet, key, L"DaylightBias", &daylightBias, 4)
	    || !readExactValue(conf.CurrentControlSet, key, L"StandardStart", standardStart, 16)
	    || !readExactValue(conf.CurrentControlSet, key, L"DaylightStart", daylightStart, 16)
	    || !parseTimeZoneInformation(bias, standardBias, daylightBias, standardStart, daylightStart, rules.current)) {
		rules.current = TimeZoneRule{};
		rules.current.biasMinutes = conf.timeZone.activeBiasMinutes;
		log(2, L"🔥Daylight saving rules unreadable: the offset of the collection day applies to every date");
		return;
	}
	DWORD disabled = 0;
	if (getRegDwordValue(conf.CurrentControlSet, key, L"DynamicDaylightTimeDisabled", &disabled) == ERROR_SUCCESS
	    && disabled != 0) {
		log(2, L"❇️Rules per year disabled on the examined machine: its current rule applies to every year");
		return;
	}
	// The key name comes from the hive: a separator in it would read another key.
	const std::wstring& zone = conf.timeZone.keyName;
	if (!conf.Software || zone.empty() || zone.find(L'\\') != std::wstring::npos) return;
	const std::wstring dynamic = L"Microsoft\\Windows NT\\CurrentVersion\\Time Zones\\" + zone + L"\\Dynamic DST";
	DWORD first = 0, last = 0;
	if (!readExactValue(conf.Software, dynamic.c_str(), L"FirstEntry", &first, 4)
	    || !readExactValue(conf.Software, dynamic.c_str(), L"LastEntry", &last, 4)) return;
	if (first < 1601 || last > 30827 || first > last || last - first > 1000) {
		log(2, L"🔥Dynamic DST of " + zone + L": inconsistent years, ignored");
		return;
	}
	for (DWORD year = first; year <= last; ++year) {
		BYTE bytes[44] = {};
		TimeZoneRule rule;
		if (readExactValue(conf.Software, dynamic.c_str(), std::to_wstring(year).c_str(), bytes, sizeof(bytes))
		    && parseTimeZoneRule(bytes, sizeof(bytes), rule))
			rules.byYear[(int)year] = rule;
	}
	if (!rules.byYear.empty()) {
		conf.timeZone.firstRuleYear = rules.byYear.begin()->first;
		conf.timeZone.lastRuleYear = rules.byYear.rbegin()->first;
		log(2, L"❇️Daylight saving rules per year: " + std::to_wstring(conf.timeZone.firstRuleYear)
		     + L"-" + std::to_wstring(conf.timeZone.lastRuleYear));
	}
}

} // namespace

HRESULT loadSuspectTimeZone() {
	conf.timeZone = TimeZoneInfo{};       // starts again from a clean state
	if (!conf.CurrentControlSet) return ERROR_INVALID_HANDLE;

	PCWSTR key = L"Control\\TimeZoneInformation";
	DWORD activeBias = 0;
	log(3, L"🔈getRegDwordValue ActiveTimeBias");
	HRESULT hresult = getRegDwordValue(conf.CurrentControlSet, key, L"ActiveTimeBias", &activeBias);
	if (hresult != ERROR_SUCCESS) {
		/* ActiveTimeBias absent: Bias + the seasonal bias are recomposed. One cannot
		   know which of the two applied at the time of each artefact, so Bias
		   alone is taken and that is reported. */
		DWORD bias = 0;
		log(3, L"🔈getRegDwordValue Bias");
		hresult = getRegDwordValue(conf.CurrentControlSet, key, L"Bias", &bias);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥Suspect's time zone unreadable in the SYSTEM hive", hresult);
			return hresult;
		}
		activeBias = bias;
		log(2, L"🔥ActiveTimeBias absent: Bias used alone (daylight saving time not accounted for)");
	}

	// ActiveTimeBias/Bias are DWORDs but carry a SIGNED integer, in minutes.
	conf.timeZone.activeBiasMinutes = (long)(int32_t)activeBias;

	/* Daylight saving time in force or not. Not stored as such: it is DEDUCED
	   from the difference between ActiveTimeBias (the offset really applied) and
	   Bias (the offset out of season). If the two differ, the seasonal bias
	   applied at collection time. */
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
	loadSuspectTimeZoneRules(key);
	conf.timeZone.fromHive = true;
	conf.timeZone.valid    = true;

	log(2, L"❇️Suspect's time zone (SYSTEM hive): " + conf.timeZone.keyName
	     + L", UTC" + offsetSuffix(conf.timeZone.activeBiasMinutes) + L" at collection time");
	return ERROR_SUCCESS;
}

namespace {

/*! Formats a SYSTEMTIME as ISO 8601, with the suffix given.
 *  @param st the date
 *  @param fraction100ns fraction of a second, in hundreds of nanoseconds (0..9999999)
 *  @param suffix "Z", or the offset "+HH:MM" of the value
 *  @param precision how many digits of fraction the source really has
 *  @return the formatted date, or "" if it is null */
std::wstring formatIso8601(const SYSTEMTIME& st, long fraction100ns, const std::wstring& suffix,
                           Precision precision) {
	if (st.wYear <= 1601) return L"";        // null date: an empty string, not 1601
	std::wstring s;
	s.reserve(33);
	fourDigits(s, st.wYear);   s += L'-';
	twoDigits(s, st.wMonth);    s += L'-';
	twoDigits(s, st.wDay);      s += L'T';
	twoDigits(s, st.wHour);     s += L':';
	twoDigits(s, st.wMinute);
	if (precision != Precision::Minute) {
		s += L':';
		twoDigits(s, st.wSecond);
	}
	/*  The fraction is written HERE, between the seconds and the time-zone suffix.
	    Inserting it afterwards meant finding the end of the seconds in the
	    finished string: on the local variant, whose "+02:00" suffix ends with
	    digits, the search stopped at once and the fraction landed AFTER the
	    time-zone offset. */
	const int digits = precision == Precision::HundredNanoseconds ? 7
	                 : precision == Precision::Millisecond ? 3 : 0;
	if (digits) s += L'.';
	for (int p = 6; p >= 7 - digits; --p) {
		long divisor = 1;
		for (int k = 0; k < p; ++k) divisor *= 10;
		s += (wchar_t)(L'0' + ((fraction100ns / divisor) % 10));
	}
	return s + suffix;
}

/*  SUB-SECOND PRECISION.
 *
 *  A FILETIME counts intervals of 100 nanoseconds: its resolution is ten
 *  million times finer than the second. Going through a SYSTEMTIME, which caps
 *  at the millisecond, lost four digits of it — and formatting to the second
 *  lost seven.
 *
 *  WHY IT MATTERS. Correlating artefacts means ORDERING them. Two events within
 *  the same second — a process creation and the network connection it opens, a
 *  file written then executed — become indistinguishable if the timestamp is
 *  rounded, and the order is precisely what one seeks to establish. Windows
 *  itself writes seven digits in the XML of its logs.
 *
 *  The fraction is taken from the FILETIME and not from the SYSTEMTIME: it is
 *  the only source that carries it.
 */
//! Fraction of a second of a FILETIME, in hundreds of nanoseconds (0..9999999).
long fraction100ns(const FILETIME& ft) {
	const ULONGLONG v = ticksFromFiletime(ft);
	return (long)(v % 10000000ULL);
}

//! A FILETIME as a signed count of 100 ns (negative if bit 63 is set: not a date for Windows).
long long ticksOf(const FILETIME& ft) {
	return (long long)(ticksFromFiletime(ft));
}

/*! Shifts a FILETIME by an offset.
 *  @return the shifted instant, or a null FILETIME if the input is not a date
 *          or the result leaves the FILETIME range */
FILETIME shifted(const FILETIME& filetime, long long offset100ns) {
	const long long value = ticksOf(filetime);
	// A FILETIME is signed-positive for Windows: FileTimeToSystemTime refuses bit 63.
	if (value <= 0) return FILETIME{ 0, 0 };
	if (offset100ns < 0 ? value < -offset100ns : value > LLONG_MAX - offset100ns)
		return FILETIME{ 0, 0 };
	const ULONGLONG result = (ULONGLONG)(value + offset100ns);
	return filetimeFromTicks(result);
}

//! Formats a local FILETIME with the bias that goes with it.
std::wstring formatLocal(const FILETIME& local, long bias, Precision precision) {
	if (nullDate(local)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&local, &st)) return L"";
	return formatIso8601(st, fraction100ns(local), offsetSuffix(bias), precision);
}

} // namespace

std::wstring timeToIso8601Utc(const FILETIME& filetime, Precision precision) {
	if (nullDate(filetime)) return L"";
	SYSTEMTIME st = { 0 };
	if (!FileTimeToSystemTime(&filetime, &st)) return L"";
	return formatIso8601(st, fraction100ns(filetime), L"Z", precision);
}

std::wstring timeToIso8601Local(const FILETIME& filetime, Precision precision) {
	if (nullDate(filetime)) return L"";
	// The offset suspectLocalToUtc applies to the same local time: label and UTC agree.
	return formatLocal(filetime, biasAtLocal(suspectRules(), ticksOf(filetime)), precision);
}

/* Each date takes the offset in force AT THAT DATE, from the suspect's rules
   (time_zone.h): a winter date collected in summer is at +01:00, not +02:00.
   Same source as the labels, so that a value and its label speak of the same
   time zone. */
FILETIME utcToSuspectLocal(const FILETIME& filetimeUtc) {
	if (nullDate(filetimeUtc)) return FILETIME{ 0, 0 };
	return shifted(filetimeUtc, -biasAtUtc(suspectRules(), ticksOf(filetimeUtc)) * MINUTE_100NS);
}

FILETIME suspectLocalToUtc(const FILETIME& filetimeLocal) {
	if (nullDate(filetimeLocal)) return FILETIME{ 0, 0 };
	return shifted(filetimeLocal, biasAtLocal(suspectRules(), ticksOf(filetimeLocal)) * MINUTE_100NS);
}

bool iso8601UtcToFiletime(const std::wstring& text, FILETIME& filetime) {
	// Fixed layout: 20 characters, or 21 + 1 to 7 fraction digits.
	if (text.size() < 20 || text.back() != L'Z') return false;
	auto digits = [&](size_t at, size_t count, WORD& out) {
		unsigned v = 0;
		for (size_t i = at; i < at + count; ++i) {
			if (text[i] < L'0' || text[i] > L'9') return false;
			v = v * 10 + (unsigned)(text[i] - L'0');
		}
		out = (WORD)v;
		return true;
	};
	SYSTEMTIME st = {};
	if (!digits(0, 4, st.wYear) || text[4] != L'-' || !digits(5, 2, st.wMonth) || text[7] != L'-'
	    || !digits(8, 2, st.wDay) || text[10] != L'T' || !digits(11, 2, st.wHour) || text[13] != L':'
	    || !digits(14, 2, st.wMinute) || text[16] != L':' || !digits(17, 2, st.wSecond)) return false;
	unsigned long long ticks = 0;                 // fraction, in 100 ns
	if (text.size() > 20) {
		const size_t count = text.size() - 21;
		if (text[19] != L'.' || count < 1 || count > 7) return false;
		for (size_t i = 20; i < 20 + count; ++i) {
			if (text[i] < L'0' || text[i] > L'9') return false;
			ticks = ticks * 10 + (unsigned)(text[i] - L'0');
		}
		for (size_t i = count; i < 7; ++i) ticks *= 10;
	}
	FILETIME whole = {};
	if (!SystemTimeToFileTime(&st, &whole)) return false;   // refuses a month 13, a day 32…
	const unsigned long long value = (ticksFromFiletime(whole)) + ticks;
	filetime = filetimeFromTicks(value);
	return true;
}

std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc, Precision precision) {
	if (nullDate(filetimeUtc)) return L"";
	/* The bias of the UTC instant labels the result: in the hour repeated in
	   autumn, the local time alone could not tell which of the two offsets. */
	const long bias = biasAtUtc(suspectRules(), ticksOf(filetimeUtc));
	return formatLocal(shifted(filetimeUtc, -bias * MINUTE_100NS), bias, precision);
}

std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal, Precision precision) {
	return timeToIso8601Utc(suspectLocalToUtc(filetimeLocal), precision);
}

std::wstring decodeText(const std::string& bytes, UINT codePage)
{
	//used to log, so no log to this call function
	if (bytes.empty()) return std::wstring();
	if (codePage == 0) codePage = conf.ansiCodePage ? conf.ansiCodePage : CP_ACP;
	// UTF-8 is checked strictly: an invalid sequence is not silently replaced.
	const DWORD flags = (codePage == CP_UTF8) ? MB_ERR_INVALID_CHARS : 0;
	const int n = MultiByteToWideChar(codePage, flags, bytes.data(), (int)bytes.size(), nullptr, 0);
	if (n > 0) {
		std::wstring text((size_t)n, L'\0');
		if (MultiByteToWideChar(codePage, flags, bytes.data(), (int)bytes.size(), &text[0], n) == n)
			return text;
	}
	std::wstring widened;   // invalid for the code page: the bytes rather than nothing
	for (unsigned char c : bytes) widened.push_back((wchar_t)c);
	return widened;
}

std::string encodeText(const std::wstring& text, UINT codePage)
{
	//used to log, so no log to this call function
	if (text.empty()) return std::string();
	const int n = WideCharToMultiByte(codePage, 0, text.data(), (int)text.size(), nullptr, 0, nullptr, nullptr);
	if (n <= 0) return std::string();
	std::string bytes((size_t)n, '\0');
	if (WideCharToMultiByte(codePage, 0, text.data(), (int)text.size(), &bytes[0], n, nullptr, nullptr) != n)
		return std::string();
	return bytes;
}

HRESULT loadSuspectAnsiCodePage() {
	if (!conf.CurrentControlSet) return ERROR_INVALID_HANDLE;
	std::wstring acp;
	log(3, L"🔈getRegSzValue Nls\\CodePage\\ACP");
	const HRESULT hresult = getRegSzValue(conf.CurrentControlSet, L"Control\\Nls\\CodePage", L"ACP", &acp);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥Suspect's ANSI code page unreadable in the SYSTEM hive", hresult);
		return hresult;
	}
	const UINT codePage = (UINT)wcstoul(acp.c_str(), nullptr, 10);
	CPINFO info;
	// A code page this Windows does not know cannot be used for the conversion.
	if (codePage == 0 || !GetCPInfo(codePage, &info)) {
		log(2, L"🔥Suspect's ANSI code page \"" + acp + L"\" not usable here", ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA;
	}
	conf.ansiCodePage = codePage;
	log(2, L"❇️Suspect's ANSI code page (SYSTEM hive): " + std::to_wstring(codePage));
	return ERROR_SUCCESS;
}

bool isMuiReference(const std::wstring& value) {
	/* Recognised form: "@<file>,-<id>". The leading "@" alone is not enough: some
	   descriptions start with an at sign without being references. The comma
	   followed by a minus sign is the reliable marker. */
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

std::wstring decodeTextFile(const std::string& bytes) {
	if (bytes.size() >= 2 && (uint8_t)bytes[0] == 0xFF && (uint8_t)bytes[1] == 0xFE)
		return readWideZ(reinterpret_cast<const BYTE*>(bytes.data()), bytes.size(), 2);
	const bool bom = bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") == 0;
	return decodeText(bom ? bytes.substr(3) : bytes, CP_UTF8);
}

std::wstring readWideZ(const BYTE* base, size_t limit, size_t offset) {
	std::wstring r;
	if (base == nullptr) return r;
	for (size_t i = offset; i < limit && limit - i >= 2; i += 2) {
		const wchar_t c = (wchar_t)(base[i] | (base[i + 1] << 8));
		if (c == 0) break;
		r += c;
	}
	return r;
}

std::string readNarrowZ(const BYTE* base, size_t limit, size_t offset) {
	std::string r;
	if (base == nullptr) return r;
	for (size_t i = offset; i < limit && base[i] != 0; ++i) r += (char)base[i];
	return r;
}

std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size)
{
	/* Each string is read within the block: it used to be read up to the first
	   zero met, and a block whose last string is not terminated was read past
	   its end. */
	std::vector<std::wstring> out;
	if (size <= 0) return out;
	size_t pos = 0;   // in bytes
	while (pos + sizeof(wchar_t) <= (size_t)size) {
		const std::wstring ws = readWideZ(data, (size_t)size, pos);
		pos += (ws.length() + 1) * sizeof(wchar_t);   // past the string and its \0
		if (!ws.empty()) out.push_back(ws);
	}
	return out;
}

GuidV1 decodeGuidV1(const GUID& guid) {
	GuidV1 v;
	// The version is the high nibble of Data3; the RFC 4122 variant, the two
	// high bits of Data4[0] set to 10.
	if ((guid.Data3 >> 12) != 1 || (guid.Data4[0] & 0xC0) != 0x80) return v;
	// 60-bit count of 100 ns since 1582-10-15, the Gregorian reform; FILETIME
	// counts from 1601-01-01: 5,748,192,000,000,000 intervals later.
	const uint64_t UUID_TO_FILETIME = 5748192000000000ULL;
	const uint64_t ticks = ((uint64_t)(guid.Data3 & 0x0FFF) << 48)
	                     | ((uint64_t)guid.Data2 << 32) | guid.Data1;
	if (ticks < UUID_TO_FILETIME) return v;
	const uint64_t filetime = ticks - UUID_TO_FILETIME;
	v.createdUtc.dwLowDateTime  = (DWORD)(filetime & 0xFFFFFFFFULL);
	v.createdUtc.dwHighDateTime = (DWORD)(filetime >> 32);
	memcpy(v.node, guid.Data4 + 2, sizeof v.node);
	v.valid = true;
	return v;
}

std::wstring sidToText(const BYTE* sid, size_t size) {
	if (size < 8) return L"";
	const unsigned revision = sid[0];
	const unsigned subAuthorities = sid[1];
	if (size < 8 + 4 * (size_t)subAuthorities) return L"";
	// The authority is BIG-endian, unlike the rest of the format.
	unsigned long long authority = 0;
	for (int i = 0; i < 6; ++i) authority = (authority << 8) | sid[2 + i];
	std::wostringstream o;
	o << L"S-" << revision << L"-";
	if (authority < 0x100000000ULL) o << authority;
	else o << L"0x" << std::uppercase << std::hex << authority << std::dec << std::nouppercase;   // no padding, as Windows
	for (unsigned i = 0; i < subAuthorities; ++i) {
		uint32_t v = 0;
		std::memcpy(&v, sid + 8 + 4 * (size_t)i, 4);
		o << L"-" << v;
	}
	return o.str();
}

std::vector<BYTE> textToSid(const std::wstring& text) {
	// "S-" revision "-" authority ("-" sub-authority){0,15}
	std::vector<unsigned long long> parts;
	if (text.size() < 4 || (text[0] != L'S' && text[0] != L's') || text[1] != L'-') return {};
	size_t pos = 2;
	while (pos <= text.size()) {
		const size_t end = text.find(L'-', pos);
		const std::wstring field = text.substr(pos, end == std::wstring::npos ? std::wstring::npos : end - pos);
		if (field.empty()) return {};
		const bool hex = parts.size() == 1 && field.size() > 2 && field[0] == L'0' && (field[1] == L'x' || field[1] == L'X');
		size_t used = 0;
		unsigned long long v = 0;
		try { v = std::stoull(hex ? field.substr(2) : field, &used, hex ? 16 : 10); }
		catch (...) { return {}; }
		if (used != field.size() - (hex ? 2 : 0)) return {};
		parts.push_back(v);
		if (end == std::wstring::npos) break;
		pos = end + 1;
	}
	if (parts.size() < 2 || parts.size() > 2 + 15 || parts[0] > 0xFF || parts[1] > 0xFFFFFFFFFFFFULL) return {};
	std::vector<BYTE> sid(8 + 4 * (parts.size() - 2));
	sid[0] = (BYTE)parts[0];
	sid[1] = (BYTE)(parts.size() - 2);
	for (int i = 0; i < 6; ++i) sid[2 + i] = (BYTE)(parts[1] >> (8 * (5 - i)));
	for (size_t i = 2; i < parts.size(); ++i) {
		if (parts[i] > 0xFFFFFFFFULL) return {};
		const uint32_t v = (uint32_t)parts[i];
		std::memcpy(&sid[8 + 4 * (i - 2)], &v, 4);
	}
	return sid;
}

bool oleDateToSystemTime(double date, SYSTEMTIME& st) {
	/* VariantTimeToSystemTime's rounding, established against Windows by
	   system_conversions_test.cpp on 200,000 dates: half a second is added TO
	   THE DATE ITSELF (a double, whose precision is then only a few tens of
	   microseconds), then the time of day is truncated to the second. Rounding
	   the seconds of the day instead — whatever the order of the operations —
	   disagreed with Windows on the half-second cases. For a negative date the
	   time counts forward from the integer part: the half second goes that
	   way, and a time that overflows the day moves to the next one.
	   Range ]-657435, 2958466[, as Windows; NaN is refused — Windows returns a
	   meaningless time for it. */
	if (!(date > -657435.0 && date < 2958466.0)) return false;
	const double whole = std::trunc(date);
	long long days = (long long)whole;
	const double halfSecond = 0.5 / 86400.0;
	double time = std::fabs((date >= 0 ? date + halfSecond : date - halfSecond) - whole);
	if (time >= 1.0) { time -= 1.0; days += 1; }
	long long seconds = (long long)(time * 86400.0);
	if (seconds >= 86400) { seconds -= 86400; days += 1; }   // rounded up to midnight
	// Civil date of `days` after 1899-12-30 (H. Hinnant's days-to-civil).
	long long z = days - 25569 + 719468;                     // 1899-12-30 is day -25569 of 1970
	const long long era = (z >= 0 ? z : z - 146096) / 146097;
	const unsigned doe = (unsigned)(z - era * 146097);
	const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
	const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
	const unsigned mp = (5 * doy + 2) / 153;
	const unsigned day = doy - (153 * mp + 2) / 5 + 1;
	const unsigned month = mp < 10 ? mp + 3 : mp - 9;
	const long long year = (long long)yoe + era * 400 + (month <= 2);
	st = SYSTEMTIME{};
	st.wYear = (WORD)year;
	st.wMonth = (WORD)month;
	st.wDay = (WORD)day;
	st.wDayOfWeek = (WORD)(((days % 7) + 7 + 6) % 7);        // 1899-12-30 was a Saturday
	st.wHour = (WORD)(seconds / 3600);
	st.wMinute = (WORD)(seconds / 60 % 60);
	st.wSecond = (WORD)(seconds % 60);
	return true;
}


/****************************************************
*                   REGISTRY                        *
*****************************************************/

// Read a value in binary form from the registry
HRESULT enumRegistryValue(ORHKEY key, DWORD index, std::wstring& name, DWORD& type, std::vector<BYTE>& data)
{
	// A value name is at most 16,383 characters (registry limit), plus the terminating zero.
	std::vector<wchar_t> nameBuffer(16384);
	DWORD nameLength = (DWORD)nameBuffer.size();
	DWORD size = 0;
	/* A null data buffer asks for the size only. Unlike ORGetValue, OREnumValue
	   then answers ERROR_MORE_DATA with the size (offreg's contract, which
	   offline_registry.cpp reproduces): taken for a failure, it emptied the BAM
	   and UserAssist collections. */
	HRESULT hresult = OREnumValue(key, index, nameBuffer.data(), &nameLength, &type, nullptr, &size);
	if (hresult != ERROR_SUCCESS && hresult != ERROR_MORE_DATA) return hresult;
	data.assign(size, 0);
	nameLength = (DWORD)nameBuffer.size();
	hresult = OREnumValue(key, index, nameBuffer.data(), &nameLength, &type, size ? data.data() : nullptr, &size);
	if (hresult != ERROR_SUCCESS) return hresult;
	data.resize(size);
	name.assign(nameBuffer.data(), nameLength);
	return ERROR_SUCCESS;
}

/*  The value is asked for its size, then read into a buffer of that size; the
    size may grow in between (ERROR_MORE_DATA), hence the loop. The buffer is a
    vector: the former LPBYTE, allocated here and released by each caller,
    leaked on every error path a caller forgot. */
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::vector<BYTE>& bytes)
{
	DWORD valueType = 0, size = 0;
	log(3, L"🔈ORGetValue");
	HRESULT hresult = ORGetValue(key, subKey, valueName, &valueType, nullptr, &size);
	while (hresult == ERROR_SUCCESS || hresult == ERROR_MORE_DATA) {
		bytes.assign(size, 0);
		hresult = ORGetValue(key, subKey, valueName, &valueType, size ? bytes.data() : nullptr, &size);
		if (hresult != ERROR_MORE_DATA) break;
	}
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue", hresult);
		bytes.clear();
		return hresult;
	}
	bytes.resize(size);
	return ERROR_SUCCESS;
}

HRESULT readMruListEx(ORHKEY key, std::vector<unsigned int>& ids)
{
	std::vector<BYTE> list;
	const HRESULT hresult = getRegBinaryValue(key, L"", L"MRUListEx", list);
	if (hresult != ERROR_SUCCESS) return hresult;
	for (size_t pos = 0; pos + sizeof(DWORD) <= list.size(); pos += sizeof(DWORD)) {
		DWORD id = 0;
		memcpy(&id, list.data() + pos, sizeof(DWORD));
		if (id == 0xFFFFFFFF) break;
		ids.push_back(id);
	}
	return ERROR_SUCCESS;
}


HRESULT readMruList(ORHKEY key, std::vector<std::wstring>& names)
{
	std::wstring list;
	const HRESULT hresult = getRegSzValue(key, nullptr, L"MRUList", &list);
	if (hresult != ERROR_SUCCESS) return hresult;
	for (const wchar_t c : list) names.push_back(std::wstring(1, c));
	return ERROR_SUCCESS;
}


// Read a boolean value from the registry
HRESULT getRegboolValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, bool* value)
{
	std::vector<BYTE> bytes;
	const HRESULT hresult = getRegBinaryValue(key, subKey, valueName, bytes);
	if (hresult != ERROR_SUCCESS) return hresult;
	if (bytes.empty()) return ERROR_INVALID_DATA;
	*value = bytes[0] != 0;
	return ERROR_SUCCESS;
}

// Read a FILETIME value from the registry
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, FILETIME* filetime)
{
	/* REG_BINARY or the device property type FILETIME (0x10): exactly 8 bytes.
	   The value is read straight into the FILETIME, bounded by its size: the
	   former version read 8 bytes whatever the value held. */
	if (!filetime) return ERROR_INVALID_PARAMETER;
	FILETIME value = { 0, 0 };
	DWORD size = sizeof(value);
	log(3, L"🔈ORGetValue");
	HRESULT hresult = ORGetValue(key, subKey, valueName, nullptr, &value, &size);
	if (hresult == ERROR_SUCCESS && size != sizeof(value)) hresult = ERROR_INVALID_DATA;
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORGetValue FILETIME", hresult);
		return hresult;
	}
	*filetime = value;
	return ERROR_SUCCESS;
}

// Read a string from the registry
// Makes sure the string is printable and ends with \0. A character that is not printable is replaced by ?
HRESULT getRegDwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, DWORD* pdword)
{
	std::vector<BYTE> data;
	const HRESULT hresult = getRegBinaryValue(key, subKey, valueName, data);
	if (hresult != ERROR_SUCCESS) return hresult;
	// A value shorter than 4 bytes is not a usable DWORD.
	if (data.size() < sizeof(DWORD)) return ERROR_INVALID_DATA;
	memcpy(pdword, data.data(), sizeof(DWORD));
	return ERROR_SUCCESS;
}

HRESULT getRegQwordValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, unsigned long long* pqword)
{
	std::vector<BYTE> data;
	const HRESULT hresult = getRegBinaryValue(key, subKey, valueName, data);
	if (hresult != ERROR_SUCCESS) return hresult;
	// A value shorter than 8 bytes is not a usable QWORD.
	if (data.size() < sizeof(unsigned long long)) return ERROR_INVALID_DATA;
	memcpy(pqword, data.data(), sizeof(unsigned long long));
	return ERROR_SUCCESS;
}

HRESULT getRegSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::wstring* ws)
{
	// REG_SZ: UTF-16, up to its first zero, within the value.
	std::vector<BYTE> data;
	const HRESULT hresult = getRegBinaryValue(key, subKey, valueName, data);
	if (hresult != ERROR_SUCCESS) return hresult;
	*ws = readWideZ(data.data(), data.size(), 0);
	return ERROR_SUCCESS;
}

// Read a multi-string value from the registry. Each string ends with \0
// Characters that are not printable are replaced by ?
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR subKey, PCWSTR valueName, std::vector<std::wstring>* out)
{
	// REG_MULTI_SZ values are stored as wchar_t = 16 bits per character, a succession of strings separated by \0 and ended by \0\0
	std::vector<BYTE> bytes;
	const HRESULT hresult = getRegBinaryValue(key, subKey, valueName, bytes);
	if (hresult != ERROR_SUCCESS) return hresult;
	std::vector<wchar_t> data(bytes.size() / sizeof(wchar_t));
	if (!data.empty()) memcpy(data.data(), bytes.data(), data.size() * sizeof(wchar_t));
	const DWORD size = (DWORD)bytes.size();
	{
		/* WHAT WAS WRONG. The loop re-read `data` at every turn without ever
		   advancing the pointer: only the position counter progressed. Every
		   REG_MULTI_SZ value therefore came out as its FIRST string, repeated as
		   many times as there were characters to walk — seen on
		   `DependOnService` ("RPCSS" five times) and on the `HardwareId` of USB
		   devices.
		
		   The bound is now computed on the buffer, without trusting a possible
		   final \0: a value truncated in the hive would otherwise be read past
		   its end. */
		const size_t nbCar = size / sizeof(wchar_t);
		size_t pos = 0;
		while (pos < nbCar) {
			size_t end = pos;
			while (end < nbCar && data[end] != L'\0') ++end;
			if (end > pos) out->push_back(std::wstring(data.data() + pos, end - pos));
			if (end >= nbCar) break;          // buffer exhausted
			pos = end + 1;                    // after the \0 separator
			if (pos < nbCar && data[pos] == L'\0') break;   // \0\0 = end of the list
		}
	}
	return ERROR_SUCCESS;
}

std::wstring getVolumeLetter(std::wstring searchSerial) {
	/* From the snapshot of the running machine, not from the machine running
	   WAC: under --convert, that one is the analysis workstation, whose
	   volumes have nothing to do with the Prefetch files (running_machine.h). */
	const std::map<std::wstring, std::wstring>& volumes = runningMachine().volumeBySerial;
	const auto found = volumes.find(searchSerial);
	return found == volumes.end() ? std::wstring() : found->second;
}

HRESULT writeJsonFile(const std::string& name, const Json& value) {
	const std::wstring folder = conf.jsonFolder.empty() ? conf._outputDir : conf.jsonFolder;
	std::error_code ec;
	std::filesystem::create_directories(folder, ec); // no error if present
	std::ofstream f;
	f.open(std::filesystem::path(folder) / name);
	if (!f) {
		log(2, L"🔥Cannot open the output file: " + decodeText(name));
		return E_FAIL;
	}
	f << encodeText(value.dump(0));
	f.close();
	return ERROR_SUCCESS;
}

JsonArrayWriter::JsonArrayWriter(const std::string& name) : name_(name) {
	const std::wstring folder = conf.jsonFolder.empty() ? conf._outputDir : conf.jsonFolder;
	std::error_code ec;
	std::filesystem::create_directories(folder, ec);  // no error if present
	f_.open(std::filesystem::path(folder) / name);
	if (!f_) {
		log(2, L"🔥Cannot open the output file: " + decodeText(name));
		return;
	}
	open_ = true;
	f_ << "[";
}

void JsonArrayWriter::add(const Json& element) {
	if (!open_ || closed_) return;
	// The comma precedes the element: while writing, one does not know whether
	// others will come — that is what avoids a trailing comma without re-reading.
	f_ << (written_ ? ",\n\t" : "\n\t");
	f_ << encodeText(element.dump(1));
	++written_;
}

HRESULT JsonArrayWriter::close() {
	if (!open_ || closed_) return open_ ? ERROR_SUCCESS : E_FAIL;
	closed_ = true;
	if (written_) f_ << "\n";
	f_ << "]";
	const bool good = f_.good();
	f_.close();
	if (!good) {
		log(2, L"🔥Incomplete write: " + decodeText(name_));
		return E_FAIL;
	}
	return ERROR_SUCCESS;
}

JsonArrayWriter::~JsonArrayWriter() {
	// Without this, an early return would leave a JSON array unclosed: an invalid
	// file reads as "nothing collected", not as an error.
	close();
}

HRESULT writeNotCollected(const std::string& name, const std::wstring& artefact,
                          HRESULT result) {
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"NotCollected"));
	o.add(L"Error",            Json::str(L"0x" + to_hex(result) + L" " + getErrorMessage(result)));
	// Without that detail, an empty array and a failed reading read the same way:
	// "no trace".
	o.add(L"Note",             Json::str(L"Reading this artefact failed: "
	                                     L"the absence of data above does NOT mean "
	                                     L"that no trace exists on the system."));
	return writeJsonFile(name, o);
}

std::wstring WacVersion() {
	static const std::wstring version = [] {
		HRSRC found = FindResourceW(nullptr, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(16));   // VS_VERSION_INFO, RT_VERSION
		HGLOBAL loaded = found ? LoadResource(nullptr, found) : nullptr;
		const uint8_t* bytes = loaded ? static_cast<const uint8_t*>(LockResource(loaded)) : nullptr;
		if (!bytes) return std::wstring();
		VersionInfo info;
		if (!ReadVersionInfo(std::vector<uint8_t>(bytes, bytes + SizeofResource(nullptr, found)), info)) return std::wstring();
		const auto product = info.strings.find(L"ProductVersion");
		return product == info.strings.end() ? std::wstring() : product->second;
	}();
	return version;
}

HRESULT writeNotRequested(const std::string& name, const std::wstring& artefact, const std::wstring& key) {
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"NotRequested"));
	o.add(L"Note",             Json::str(L"Switched off by the configuration (" + key + L": false): not collected "
	                                     L"on purpose. The absence of data says NOTHING about the system."));
	return writeJsonFile(name, o);
}

HRESULT writeAbsentFromVersion(const std::string& name, const std::wstring& artefact, const std::wstring& key) {
	bool known = false;
	const WindowsRelease& release = releaseOf(conf.examinedVersion, known);
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"AbsentFromThisVersion"));
	o.add(L"WindowsRelease",   Json::str(release.name));
	o.add(L"WindowsBuild",     Json::num((unsigned long long)conf.examinedVersion.build));
	o.add(L"Note",             Json::str(L"This artefact does not exist on this version of Windows (" + key + L"): "
	                                     L"there was nothing to collect. Its absence is normal and says nothing "
	                                     L"about what happened on the system."));
	return writeJsonFile(name, o);
}

HRESULT processElevated(bool& elevated) {
	elevated = false;
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return GetLastError();
	TOKEN_ELEVATION elevation = { 0 };
	DWORD length = 0;
	const BOOL read = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length);
	const DWORD error = read ? ERROR_SUCCESS : GetLastError();
	CloseHandle(token);
	if (read) { elevated = elevation.TokenIsElevated != 0; return ERROR_SUCCESS; }
	if (error != ERROR_INVALID_PARAMETER) return error;
	// Before Vista: member of the Administrators group (S-1-5-32-544), or not.
	SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
	PSID administrators = nullptr;
	if (!AllocateAndInitializeSid(&authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators))
		return GetLastError();
	BOOL member = FALSE;
	const BOOL checked = CheckTokenMembership(nullptr, administrators, &member);
	const DWORD membershipError = checked ? ERROR_SUCCESS : GetLastError();
	FreeSid(administrators);
	if (!checked) return membershipError;
	elevated = member != FALSE;
	return ERROR_SUCCESS;
}

bool sourceNotFound(HRESULT result) {
	return result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND
	    || result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || result == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
}

std::string catalogueKey(const std::wstring& key) {
	return encodeText(key.substr(key.find(L'.') + 1));
}

HRESULT writeExpectedButMissing(const std::string& name, const std::wstring& artefact, const std::wstring& key,
                                HRESULT result) {
	bool known = false;
	const WindowsRelease& release = releaseOf(conf.examinedVersion, known);
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"ExpectedButMissing"));
	o.add(L"WindowsRelease",   Json::str(release.name));
	o.add(L"WindowsBuild",     Json::num((unsigned long long)conf.examinedVersion.build));
	if (const ArtefactEntry* entry = artefactEntry(catalogueKey(key)))
		o.add(L"ExpectedLocation", Json::str(formOf(*entry, conf.examinedVersion).location));
	o.add(L"Error",            Json::str(L"0x" + to_hex(result) + L" " + getErrorMessage(result)));
	/* What the conversion knows is that the sealed collection does not hold
	   the source; whether the machine lacked it or its extraction failed is
	   in the collection's own log, hence the pointer. */
	o.add(L"Note",             Json::str(L"This version of Windows always has this artefact's source (" + key + L") "
	                                     L"and the collection does not hold it. Unless the collection's log "
	                                     L"(investigation.json) records a failed extraction of it, the source was "
	                                     L"missing on the machine: a finding in itself — erased, switched off or "
	                                     L"damaged —, to be explained. It is NOT the absence of traces on the system."));
	return writeJsonFile(name, o);
}

//! What an unsupported format says of itself, for a piece or a whole artefact: signature, form if known, note.
static void addFormatMet(Json& o, const std::string& key, unsigned signature) {
	o.add(L"FormatSignature", Json::str(L"0x" + to_hex(signature, 8, HexLetters::Upper)));
	const PieceFormat format = pieceFormat(key, signature);
	// "FormatName", not "Format": that key is already an image's format in thumbcache.json.
	if (format.form) o.add(L"FormatName", Json::str(format.form->format));
	o.add(L"Note", Json::str(format.form
		? L"Collected raw, not converted: this version of WAC has no decoder for this format. The exhibit store holds the source."
		: L"Collected raw, not converted: a format this version of WAC does not know. The exhibit store holds the source."));
}

void addUnsupportedFormat(Json& o, const std::string& key, unsigned signature) {
	o.add(L"DecodingStatus", Json::str(L"UnsupportedFormat"));
	addFormatMet(o, key, signature);
}

HRESULT writeUnsupportedFormat(const std::string& name, const std::wstring& artefact, const std::string& key,
                               unsigned signature) {
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"UnsupportedFormat"));
	addFormatMet(o, key, signature);
	return writeJsonFile(name, o);
}

HRESULT writeUndecodedOnVersion(const std::string& name, const std::wstring& artefact, const std::wstring& key) {
	bool known = false;
	const WindowsRelease& release = releaseOf(conf.examinedVersion, known);
	Json o = Json::obj();
	o.add(L"Artifact",         Json::str(artefact));
	o.add(L"CollectionStatus", Json::str(L"UnsupportedFormat"));
	o.add(L"WindowsRelease",   Json::str(release.name));
	o.add(L"WindowsBuild",     Json::num((unsigned long long)conf.examinedVersion.build));
	if (const ArtefactEntry* entry = artefactEntry(catalogueKey(key))) {
		const ArtefactForm& form = formOf(*entry, conf.examinedVersion);
		o.add(L"FormatName", Json::str(form.format));
		o.add(L"Location",   Json::str(form.location));
	}
	o.add(L"Note",             Json::str(L"On this version of Windows this artefact (" + key + L") is in a format this "
	                                     L"version of WAC has no decoder for. Collected raw, not converted: the exhibit "
	                                     L"store holds the source. The absence of data here says NOTHING about the system."));
	return writeJsonFile(name, o);
}

//! ASCII lower case: enough for file extensions.
static std::wstring toLowerAscii(std::wstring s) {
	for (wchar_t& c : s) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
	return s;
}

std::vector<std::filesystem::path> listFilesByExtension(const std::filesystem::path& directory,
	const std::vector<std::wstring>& extensions) {
	std::vector<std::filesystem::path> results;
	std::error_code ec;
	std::filesystem::directory_iterator it(directory, ec);
	if (ec) {                                    // missing or unreadable: the nominal case
		log(4, L"🔈Directory not walked: " + directory.wstring());
		return results;
	}
	std::vector<std::wstring> expectedExtensions;   // lowercased only once
	expectedExtensions.reserve(extensions.size());
	for (const std::wstring& e : extensions) expectedExtensions.push_back(toLowerAscii(e));

	for (const std::filesystem::directory_iterator end; it != end; it.increment(ec)) {
		if (ec) {                                // walk interrupted: what was gathered is kept
			log(2, L"🔥Walk interrupted: " + directory.wstring());
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

void addDate(Json& o, const std::wstring& key, const FILETIME& utc) {
	if (utc.dwLowDateTime == 0 && utc.dwHighDateTime == 0) return;
	o.add(key + L"Utc", Json::str(timeToIso8601Utc(utc)));
	o.add(key,          Json::str(utcTimeToIso8601Local(utc)));
}

void addUtcDate(Json& o, const std::wstring& key, const FILETIME& utc) {
	if (utc.dwLowDateTime || utc.dwHighDateTime) o.add(key, Json::str(timeToIso8601Utc(utc)));
}

std::vector<std::wstring> splitLines(const std::wstring& text) {
	std::vector<std::wstring> lines;
	size_t start = 0;
	while (start < text.size()) {
		size_t end = text.find(L'\n', start);
		if (end == std::wstring::npos) end = text.size();
		lines.push_back(text.substr(start, end - start));
		if (!lines.back().empty() && lines.back().back() == L'\r') lines.back().pop_back();
		start = end + 1;
	}
	return lines;
}

void forEachProfileHive(const std::wstring& relativeHive,
                        const std::function<void(ORHKEY root, const std::wstring& sid)>& visit) {
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring file = extractedPath(std::get<1>(profileEntry) + relativeHive);
		ORHKEY root = NULL;
		const HRESULT hresult = OROpenHive(file.c_str(), &root);
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥OROpenHive " + file, hresult);
			continue;
		}
		visit(root, std::get<0>(profileEntry));
		ORCloseHive(root);
	}
}


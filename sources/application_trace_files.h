/*! \file
 *  \brief The applications' traces converted: each file the collection took for
 *         a product of application_traces.h, in its group's JSON (<group>.json).
 *
 *  WHY A GENERIC CONVERSION. The 97 products write in their own formats, and
 *  change them; but most of what they leave is text, one event per line —
 *  logs of antivirus, remote administration tools, servers, VPN —, and much of
 *  the rest is XML, JSON or INI. Read as such, without knowing the product,
 *  each file becomes something an analysis can search and order in time.
 *  Decision of the user, 2026-11-08 (backlog B-076): a raw copy alone left
 *  nothing to read.
 *
 *  WHAT IS WRITTEN. One element per record of a text file: its Product, File,
 *  Line (of its first line), Text, and the time read at its head — every one
 *  in the same form, whatever the product wrote (decision of the user,
 *  2026-11-08): Time, in the examined machine's local time with its offset,
 *  and TimeUtc, as every artefact of WAC; TimeAsWritten keeps the text. A time
 *  written without its offset is read as the examined machine's local time —
 *  what nearly every product writes —, or UTC for a product the harness
 *  measured writing UTC (TraceProduct::writesUtc); TimeZoneAssumed then says
 *  which ("Local", "UTC"). The harness checks the assumption on every log of a
 *  cycle: a log's last line against the moment its file was last written.
 *  Lines with no time of their own that follow a dated one (a stack trace, a
 *  continuation) belong to it. One element per structured file (XML, JSON,
 *  INI): its Format and Content, its structure; a value named like a secret
 *  (isPasswordValue) is left out, HasPassword says so. One element for any
 *  other file (a database, a binary, an encrypted store): Converted false and
 *  its Reason — the file stays in the exhibit store, sealed.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>
#include "application_traces.h"
#include "json.h"

//! The time at the head of a log line, as its clock wrote it.
struct WrittenTime {
	std::wstring asWritten;      //!< as the line writes it; empty when none is recognised
	uint64_t ticks = 0;          //!< the time written, in 100 ns since 1601, no zone applied
	bool hasOffset = false;      //!< the line gives its offset
	int offsetMinutes = 0;       //!< that offset, east of UTC
	unsigned fractionDigits = 0; //!< digits of fraction written, up to seven: a FILETIME counts 100 ns
	bool fractionCut = false;    //!< more than seven were written: cut at 100 ns, the text kept in TimeAsWritten
};

/*! Reads the time a log line starts with, after blanks and one `[` or `<`:
 *  yyyy-MM-dd, yyyy/MM/dd or yyyy.MM.dd — or MM/dd/yyyy for a product that
 *  declares it (TraceProduct::monthFirst) —, a space or `T`, HH:mm:ss, an
 *  optional fraction (`.` or `,`, `:` month first, up to nine digits), an
 *  optional offset (`Z`, `±hh:mm`, `±hhmm`). Days of the month, hours, minutes
 *  and seconds within their range. A date day first, or month first for any
 *  other product, is not read: written 08/11/2026, it is two dates.
 *  @param line the line
 *  @param time receives the time
 *  @param monthFirst the product writes its dates month first
 *  @return whether the line starts with a time */
bool leadingTime(const std::wstring& line, WrittenTime& time, bool monthFirst = false);

/*! Writes a record's time as every artefact does: Time, in the examined
 *  machine's local time with its offset, and TimeUtc. A time with its offset is
 *  that instant; one without is read as the examined machine's local time
 *  (suspectLocalToUtc, its rules for that date), or as UTC for a product that
 *  writes UTC — TimeZoneAssumed says which. TimeAsWritten keeps the text.
 *  Exactly as many digits of fraction as the line wrote, none invented: an
 *  offset or a zone moves whole minutes, never the fraction. Past seven digits
 *  (100 ns), the cut is said (TimePrecisionCut). Nothing for a record without a time.
 *  @param row the element
 *  @param time the time read at the head of the record
 *  @param writesUtc the product writes UTC without saying so */
void addRecordTimes(Json& row, const WrittenTime& time, bool writesUtc);

//! A record of a text file: a line, and the lines that continue it.
struct TextRecord {
	size_t line = 0;         //!< number of its first line, from 1
	std::wstring text;       //!< its lines, joined by "\n"
	WrittenTime time;        //!< the time of its first line
	bool truncated = false;  //!< cut at TEXT_RECORD_MAX characters
};

//! Longest record kept, in characters: a hostile line of any length costs no more.
constexpr size_t TEXT_RECORD_MAX = 64 * 1024;

/*! Cuts a text into records: each line starting with a time opens one, each
 *  line without a time that follows a dated record continues it, any other line
 *  is a record of its own. Blank lines are left out; "\r\n" and "\n" end a line.
 *  @param text the decoded text
 *  @param monthFirst the product writes its dates month first (leadingTime)
 *  @return its records, in order */
std::vector<TextRecord> textRecords(const std::wstring& text, bool monthFirst = false);

//! How a file of a product is read.
enum class TraceFormat { Text, Xml, Json, Ini, Database, Binary };

/*! The format of a file, by its extension and, for the rest, by its bytes: text
 *  if it starts with a UTF-16 byte-order mark, or holds no null byte and few
 *  control characters in its first 64 KiB.
 *  @param name the file name
 *  @param bytes its content
 *  @return its format */
TraceFormat traceFormatOf(const std::wstring& name, const std::string& bytes);

/*! A structured file's content as JSON: XML as its elements (Name, Attributes,
 *  Text, Children), JSON as itself, INI as its sections (Name, Values). A key,
 *  attribute or element named like a secret is left out.
 *  @param format Xml, Json or Ini
 *  @param text the decoded text
 *  @param hasPassword set when a secret was left out
 *  @return the content, or a null Json when the text does not parse */
Json structuredContent(TraceFormat format, const std::wstring& text, bool& hasPassword);

//! A group of the applications' traces, converted (<group>.json).
class ApplicationTraceFiles {
public:
	explicit ApplicationTraceFiles(const TraceGroup& group) : group_(group) {}
	HRESULT getData();  //!< @return ERROR_SUCCESS, even when the group left nothing
	HRESULT toJson();   //!< @return the result of the write
	void clear();       //!< releases what was read
private:
	const TraceGroup& group_;
	Json rows_ = Json::arr();
};

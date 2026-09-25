/*! \file
 *  \brief CSV reading (see csv_reader.h).
 */
#include "csv_reader.h"

bool CsvRead(const std::string& text, std::vector<std::vector<std::string>>& records, std::string& reason) {
	records.clear();
	size_t i = text.compare(0, 3, "\xEF\xBB\xBF") == 0 ? 3 : 0;
	std::vector<std::string> record;
	std::string field;
	bool quoted = false, fieldStarted = false;
	auto endRecord = [&]() {
		record.push_back(std::move(field));
		field.clear();
		fieldStarted = false;
		records.push_back(std::move(record));
		record.clear();
	};
	for (; i < text.size(); ++i) {
		const char c = text[i];
		if (quoted) {
			if (c != '"') field += c;
			else if (i + 1 < text.size() && text[i + 1] == '"') { field += '"'; ++i; }   // "" is a quote
			else quoted = false;
			continue;
		}
		if (c == '"' && !fieldStarted) { quoted = fieldStarted = true; continue; }
		if (c == ',') { record.push_back(std::move(field)); field.clear(); fieldStarted = false; continue; }
		if (c == '\r' && i + 1 < text.size() && text[i + 1] == '\n') continue;   // CRLF: the LF ends it
		if (c == '\n') { endRecord(); continue; }
		field += c;
		fieldStarted = true;
	}
	if (quoted) { reason = "a quoted field is not closed"; return false; }
	if (fieldStarted || !record.empty()) endRecord();                // no line break after the last record
	for (size_t r = 1; r < records.size(); ++r)
		if (records[r].size() != records[0].size()) {
			reason = "record " + std::to_string(r) + " has " + std::to_string(records[r].size())
			       + " field(s), the header " + std::to_string(records[0].size());
			return false;
		}
	return true;
}

/*! \file
 *  \brief The DHCP Server role (see dhcp_server.h).
 */
#include "dhcp_server.h"
#include "ese_recovery.h"
#include "registry_common.h"
#include "whole_file.h"
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <set>

namespace {

const uintmax_t LOG_MAX = 256ULL * 1024 * 1024;   //!< DhcpLogFilesMaxSize is in MiB, 70 by default: a forged one is refused
const wchar_t PARAMETERS_KEY[] = L"Services\\DHCPServer\\Parameters";
const size_t V4_COLUMNS = 19, V6_COLUMNS = 12;
const size_t LINE_MAX = 65536;   //!< an audit line is short; a forged one of millions of commas is not cut into fields

//! The fields of a line, cut at its commas.
std::vector<std::wstring> csvFields(const std::wstring& line) {
	std::vector<std::wstring> fields;
	size_t start = 0;
	for (;;) {
		const size_t comma = line.find(L',', start);
		if (comma == std::wstring::npos) { fields.push_back(line.substr(start)); return fields; }
		fields.push_back(line.substr(start, comma - start));
		start = comma + 1;
	}
}

//! MM/dd/yy and HH:mm:ss as a FILETIME, without zone. @return false if they do not read
bool readLogDate(const std::wstring& date, const std::wstring& time, FILETIME& out) {
	if (date.size() != 8 || date[2] != L'/' || date[5] != L'/' || time.size() != 8) return false;
	const std::wstring iso = L"20" + date.substr(6, 2) + L"-" + date.substr(0, 2) + L"-" + date.substr(3, 2) + L"T" + time + L"Z";
	return iso8601UtcToFiletime(iso, out);
}

//! A text column of the database: UTF-16, up to its first zero, within the value.
std::wstring wideText(const std::vector<uint8_t>& value) {
	return readWideZ(value.data(), value.size(), 0);
}

//! The cell of a column, or nullptr.
const EseCell* cellNamed(const EseTable& table, const EseRecord& record, const wchar_t* name, const EseColumn** column = nullptr) {
	for (const EseColumn& c : table.columns)
		if (c.name == name) {
			if (column) *column = &c;
			for (const EseCell& cell : record)
				if (cell.columnId == c.id && !cell.values.empty()) return &cell;
			return nullptr;
		}
	return nullptr;
}

//! Adds an address held in a Long column; nothing for a null one, -1 (no server named) included.
void addAddress(Json& o, const wchar_t* key, const EseTable& table, const EseRecord& record, const wchar_t* column) {
	const EseCell* cell = cellNamed(table, record, column);
	if (!cell) return;
	const std::optional<uint64_t> value = eseCellInteger(*cell);
	if (value && *value != 0 && *value != 0xFFFFFFFFULL) o.add(key, Json::str(dhcpAddressText((uint32_t)*value)));
}

//! Adds a text column.
void addText(Json& o, const wchar_t* key, const EseTable& table, const EseRecord& record, const wchar_t* column) {
	if (const EseCell* cell = cellNamed(table, record, column)) o.add(key, Json::str(wideText(cell->values.front())));
}

//! Adds a number column.
void addNumber(Json& o, const wchar_t* key, const EseTable& table, const EseRecord& record, const wchar_t* column) {
	const EseCell* cell = cellNamed(table, record, column);
	if (!cell) return;
	const std::optional<uint64_t> value = eseCellInteger(*cell);
	if (value) o.add(key, Json::num((unsigned long long)*value));
}

//! Adds every column as the database reader gives it: a table WAC names no field of, kept whole.
Json wholeRecord(const EseTable& table, const EseRecord& record) {
	Json o = Json::obj();
	for (const EseColumn& c : table.columns)
		for (const EseCell& cell : record)
			if (cell.columnId == c.id) o.add(c.name, eseCellToJson(c, cell));
	return o;
}

} // namespace

std::wstring dhcpAddressText(uint32_t address) {
	return std::to_wstring(address >> 24) + L"." + std::to_wstring((address >> 16) & 0xFF) + L"."
	       + std::to_wstring((address >> 8) & 0xFF) + L"." + std::to_wstring(address & 0xFF);
}

std::wstring dhcpClientId(const std::vector<uint8_t>& value) {
	static const size_t PREFIX = 5;   // the subnet, 4 bytes, and the hardware type
	if (value.size() <= PREFIX) return L"";
	static const wchar_t HEX[] = L"0123456789abcdef";
	std::wstring out;
	for (size_t i = PREFIX; i < value.size(); ++i) {
		if (i > PREFIX) out += L'-';
		out += HEX[value[i] >> 4];
		out += HEX[value[i] & 15];
	}
	return out;
}

Json DhcpLogEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"EventId", Json::str(eventId));
	addLocalDate(o, L"Time", time);
	o.add(L"TimeAsStored", Json::str(timeAsStored));
	o.add(L"Description", Json::str(description));
	o.add(L"Address", Json::str(address));
	o.add(L"HostName", Json::str(hostName));
	o.add(L"HardwareAddress", Json::str(hardwareAddress));
	o.add(L"UserName", Json::str(userName));
	o.add(L"TransactionId", Json::str(transactionId));
	o.add(L"QResult", Json::str(qResult));
	o.add(L"ProbationTime", Json::str(probationTime));
	o.add(L"CorrelationId", Json::str(correlationId));
	o.add(L"Dhcid", Json::str(dhcid));
	o.add(L"VendorClassHex", Json::str(vendorClassHex));
	o.add(L"VendorClassAscii", Json::str(vendorClassAscii));
	o.add(L"UserClassHex", Json::str(userClassHex));
	o.add(L"UserClassAscii", Json::str(userClassAscii));
	o.add(L"RelayAgentInformation", Json::str(relayAgentInformation));
	o.add(L"DnsRegistrationError", Json::str(dnsRegistrationError));
	o.add(L"ErrorCode", Json::str(errorCode));
	o.add(L"DuidLength", Json::str(duidLength));
	o.add(L"DuidBytes", Json::str(duidBytes));
	o.add(L"SubnetPrefix", Json::str(subnetPrefix));
	o.add(L"File", Json::str(file));
	o.add(L"Line", Json::num(line));
	return o;
}

std::vector<DhcpLogEntry> parseDhcpAuditLog(const std::wstring& text, const std::wstring& file, bool v6) {
	std::vector<DhcpLogEntry> entries;
	const std::vector<std::wstring> lines = splitLines(text);
	for (size_t n = 0; n < lines.size(); ++n) {
		if (lines[n].size() > LINE_MAX) continue;
		std::wstring line = lines[n];
		if (!line.empty() && line.back() == L'\r') line.pop_back();
		std::vector<std::wstring> f = csvFields(line);
		if (f.size() < 4 || f[0].empty() || f[0].size() > 6
		    || f[0].find_first_not_of(L"0123456789") != std::wstring::npos
		    || f[1].find(L'/') == std::wstring::npos) continue;   // the header, in the machine's language
		// A description with commas: what is beyond the columns belongs to it.
		const size_t columns = v6 ? V6_COLUMNS : V4_COLUMNS;
		while (f.size() > columns) {
			f[3] += L"," + f[4];
			f.erase(f.begin() + 4);
		}
		f.resize(columns);
		DhcpLogEntry e;
		e.v6 = v6; e.file = file; e.line = n + 1;
		e.eventId = f[0]; e.description = f[3]; e.address = f[4]; e.hostName = f[5];
		if (!readLogDate(f[1], f[2], e.time)) e.timeAsStored = f[1] + L" " + f[2];
		if (v6) {
			e.errorCode = f[6]; e.duidLength = f[7]; e.duidBytes = f[8]; e.userName = f[9]; e.dhcid = f[10]; e.subnetPrefix = f[11];
		}
		else {
			e.hardwareAddress = f[6]; e.userName = f[7]; e.transactionId = f[8]; e.qResult = f[9]; e.probationTime = f[10];
			e.correlationId = f[11]; e.dhcid = f[12]; e.vendorClassHex = f[13]; e.vendorClassAscii = f[14];
			e.userClassHex = f[15]; e.userClassAscii = f[16]; e.relayAgentInformation = f[17]; e.dnsRegistrationError = f[18];
		}
		entries.push_back(std::move(e));
	}
	return entries;
}

void dhcpServerFolders(std::wstring& database, std::vector<std::wstring>& logs) {
	const std::wstring fallback = conf.systemDrive.substr(0, 2) + L"\\Windows\\System32\\dhcp";
	const auto named = [](const wchar_t* value) {
		std::wstring path;
		if (conf.CurrentControlSet && getRegSzValue(conf.CurrentControlSet, PARAMETERS_KEY, value, &path) == ERROR_SUCCESS)
			return normalizeFilePath(path);
		return std::wstring();
	};
	database = named(L"DatabasePath");
	if (database.empty()) database = fallback;
	std::set<std::wstring> seen;
	for (const std::wstring& folder : { named(L"DhcpLogFilePath"), named(L"DhcpV6LogFilePath"), fallback })
		if (!folder.empty() && seen.insert(toLower(folder)).second) logs.push_back(folder);
}

void DhcpServer::readDatabase(const std::wstring& folder) {
	std::wstring name = L"dhcp.mdb", configured;
	if (conf.CurrentControlSet && getRegSzValue(conf.CurrentControlSet, PARAMETERS_KEY, L"DatabaseName", &configured) == ERROR_SUCCESS
	    && !configured.empty() && configured.find_first_of(L"\\/:") == std::wstring::npos) name = configured;
	const std::wstring original = folder + L"\\" + name;
	std::error_code ec;
	if (!std::filesystem::is_regular_file(std::filesystem::path(extractedPath(original)), ec)) return;
	EseDatabase database;
	const HRESULT opened = OpenRecoveredEseDatabase(database, extractedPath(original), original);
	if (opened != ERROR_SUCCESS) { log(2, L"🔥dhcp.mdb not read: " + original, opened); return; }
	if (database.dirtyShutdown()) log(1, L"⚠️dhcp.mdb read as copied live (dirty shutdown): the latest changes are in its logs, in the exhibit store");

	if (const EseTable* clients = database.table(L"ClientTable"))
		database.forEachRecord(*clients, [&](EseRecord& r) {
			Json o = Json::obj();
			o.add(L"Table", Json::str(L"ClientTable"));
			addAddress(o, L"Address", *clients, r, L"IpAddress");
			addAddress(o, L"SubnetMask", *clients, r, L"SubnetMask");
			addAddress(o, L"ServerAddress", *clients, r, L"ServerIpAddress");
			if (const EseCell* c = cellNamed(*clients, r, L"HardwareAddress")) o.add(L"ClientId", Json::str(dhcpClientId(c->values.front())));
			addText(o, L"HostName", *clients, r, L"MachineName");
			addText(o, L"MachineInfo", *clients, r, L"MachineInfo");
			addNumber(o, L"State", *clients, r, L"State");
			addNumber(o, L"ClientType", *clients, r, L"ClientType");
			if (const EseCell* c = cellNamed(*clients, r, L"LeaseTerminates")) {
				const std::optional<uint64_t> filetime = eseCellInteger(*c);
				if (filetime && *filetime) {
					FILETIME utc;
					utc.dwLowDateTime = (DWORD)*filetime;
					utc.dwHighDateTime = (DWORD)(*filetime >> 32);
					addDate(o, L"LeaseTerminates", utc);
				}
			}
			o.add(L"File", Json::str(original));
			leases_.push(std::move(o));
		});
	// IPv6 leases and multicast clients: no field named by WAC yet, the columns kept whole.
	for (const wchar_t* tableName : { L"LeaseTable", L"MCastClientTableVer3" })
		if (const EseTable* table = database.table(tableName))
			database.forEachRecord(*table, [&](EseRecord& r) {
				Json o = wholeRecord(*table, r);
				o.add(L"Table", Json::str(tableName));
				o.add(L"File", Json::str(original));
				leases_.push(std::move(o));
			});
	// A scope has a subnet address; the rows of class and option definitions have none.
	if (const EseTable* config = database.table(L"DbcfgTable"))
		database.forEachRecord(*config, [&](EseRecord& r) {
			if (!cellNamed(*config, r, L"DbcfgIpAddress") && !cellNamed(*config, r, L"DbcfgRangeStart")) return;
			Json o = Json::obj();
			addAddress(o, L"Address", *config, r, L"DbcfgIpAddress");
			addAddress(o, L"SubnetMask", *config, r, L"DbcfgMaskStr");
			addAddress(o, L"RangeStart", *config, r, L"DbcfgRangeStart");
			addAddress(o, L"RangeEnd", *config, r, L"DbcfgRangeEnd");
			addText(o, L"Name", *config, r, L"DbcfgName");
			addText(o, L"Comment", *config, r, L"DbcfgComment");
			addNumber(o, L"Type", *config, r, L"DbcfgType");
			o.add(L"File", Json::str(original));
			scopes_.push(std::move(o));
		});
}

HRESULT DhcpServer::getData() {
	if (conf.CurrentControlSet) {
		ORHKEY key = NULL;
		if (OROpenKey(conf.CurrentControlSet, PARAMETERS_KEY, &key) == ERROR_SUCCESS) {
			std::vector<std::pair<std::wstring, Json>> values;
			readAllValues(key, values);
			Json o = Json::obj();
			o.add(L"Key", Json::str(PARAMETERS_KEY));
			addDate(o, L"KeyLastWrite", lastWrite(key));
			for (auto& [name, value] : values) o.add(name == L"Key" ? L"ValueKey" : name, std::move(value));
			configuration_.push(std::move(o));
			ORCloseKey(key);
		}
	}
	std::wstring database;
	std::vector<std::wstring> logs;
	dhcpServerFolders(database, logs);
	readDatabase(database);
	std::set<std::wstring> read;
	for (const std::wstring& folder : logs) {
		std::error_code ec;
		for (std::filesystem::directory_iterator it(extractedPath(folder), ec), end; !ec && it != end; it.increment(ec)) {
			const std::wstring name = it->path().filename().wstring(), lower = toLower(name);
			const bool v4 = lower.rfind(L"dhcpsrvlog-", 0) == 0, v6 = lower.rfind(L"dhcpv6srvlog-", 0) == 0;
			if ((!v4 && !v6) || !it->is_regular_file(ec) || !read.insert(toLower(folder + L"\\" + name)).second) continue;
			std::string bytes;
			if (!readWholeFile(it->path(), LOG_MAX, bytes)) { log(2, L"🔥DHCP log not read: " + it->path().wstring()); continue; }
			for (DhcpLogEntry& e : parseDhcpAuditLog(decodeTextFile(bytes), folder + L"\\" + name, v6)) logEntries_.push_back(std::move(e));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT DhcpServer::toJson() {
	HRESULT failed = ERROR_SUCCESS;
	const auto note = [&failed](HRESULT written) { if (written != ERROR_SUCCESS) failed = written; };
	note(writeJsonFile("dhcp_server_configuration.json", configuration_));
	note(writeJsonFile("dhcp_server_scopes.json", scopes_));
	note(writeJsonFile("dhcp_server_leases.json", leases_));
	note(writeList("dhcp_server_log.json", logEntries_));
	return failed;
}

void DhcpServer::clear() {
	configuration_ = Json::arr();
	scopes_ = Json::arr();
	leases_ = Json::arr();
	logEntries_.clear();
}

/*! \file
 *  \brief The DNS Server role: configuration, zones, records and debug log.
 *
 *  WHAT THE ARTEFACT PROVES. A DNS server answers for a whole network. A record
 *  added or changed redirects its clients (ATT&CK T1584.002, T1565); the value
 *  ServerLevelPluginDll makes the service load a DLL as SYSTEM, the known way
 *  from the DnsAdmins group to the domain; forwarders send its queries elsewhere;
 *  the debug log, when it is on, names who asked for what.
 *
 *  WHERE, measured on Server 2022:
 *    - SYSTEM `Services\DNS\Parameters`: the server's settings, every value kept;
 *    - SOFTWARE `Microsoft\Windows NT\CurrentVersion\DNS Server\Zones\<zone>`: a
 *      zone kept in a file, its DatabaseFile relative to System32\dns;
 *    - `System32\dns\*.dns` (and `backup`): zones as master files, RFC 1035 text;
 *    - `System32\dns\dns.log`, or LogFilePath: the debug log, off by default.
 *  A zone integrated with Active Directory is in the directory, not in these
 *  files: its objects are in active_directory_objects.json, its records not decoded.
 *
 *  THE DEBUG LOG'S DATES are written in the language of the machine's account
 *  ("04/11/2026 09:04:04" on a French one, a 12-hour clock on an English one), with
 *  no field to say which: they are given as stored, never converted.
 */
#pragma once

#include <string>
#include <vector>
#include "tools.h"

//! One record of a zone file.
struct DnsZoneRecord {
	std::wstring zone;   //!< the origin it was read under, without its final dot
	std::wstring name;   //!< the absolute owner name, without its final dot
	long long ttl = -1;  //!< seconds: its own, or the file's default; -1 if neither is written
	std::wstring dnsClass;  //!< as written, IN if the file says none
	std::wstring type;   //!< A, AAAA, CNAME, MX, SOA...
	std::wstring data;   //!< the record's data, as written, on one line
	std::wstring file;   //!< the file on the examined machine
	size_t line = 0;     //!< the line it starts on, from 1
	Json toJson() const; //!< @return the record as a JSON object
};

//! One line of the debug log.
struct DnsLogEntry {
	std::wstring timeAsStored, thread, context, packet, protocol, direction, remoteAddress,
	             transactionId, opcode, flags, flagCodes, responseCode, questionType, questionName;
	bool response = false; //!< a response, not a query
	std::wstring text;     //!< the rest of a line that is no packet
	std::wstring file;     //!< the file on the examined machine
	size_t line = 0;       //!< its line, from 1
	Json toJson() const;   //!< @return the entry as a JSON object
};

/*! Reads a zone in the master file format of RFC 1035: comments, parentheses over
 *  several lines, quoted text, $ORIGIN, $TTL, owners left blank, optional TTL and class.
 *  A line it cannot read is skipped, the others stay.
 *  @param text the file, decoded
 *  @param zone its origin, empty for the root
 *  @param file its path on the examined machine
 *  @return the records, in the file's order */
std::vector<DnsZoneRecord> parseDnsZoneFile(const std::wstring& text, const std::wstring& zone, const std::wstring& file);

/*! Reads the debug log: the lines that begin with a date, the key at its head left out.
 *  @param text the log, decoded
 *  @param file its path on the examined machine
 *  @return the entries, in the log's order */
std::vector<DnsLogEntry> parseDnsDebugLog(const std::wstring& text, const std::wstring& file);

/*! The DNS server's debug log the examined registry names, and the default. Needs conf.CurrentControlSet.
 *  @return its absolute path */
std::wstring dnsServerLogFile();

/*! The artefact: dns_server_configuration.json, dns_server_zones.json,
 *  dns_server_records.json, dns_server_log.json. */
class DnsServer {
public:
	HRESULT getData();   //!< @return ERROR_SUCCESS, even without the role
	HRESULT toJson();    //!< @return the result of the last write that failed, or ERROR_SUCCESS
	void clear();        //!< releases what was read
private:
	Json configuration_ = Json::arr(), zones_ = Json::arr();
	std::vector<DnsZoneRecord> records_;
	std::vector<DnsLogEntry> logEntries_;
};

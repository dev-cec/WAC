/*! \file
 *  \brief The DHCP Server role: configuration, scopes, leases and audit log.
 *
 *  WHAT THE ARTEFACT PROVES. The audit log and the lease database say which machine
 *  held which address when: what ties an address seen in another log to a device
 *  (its hardware address, its name). A scope's options set the gateway and the DNS
 *  servers of a network. The value CalloutDlls makes the service load DLLs as its
 *  own account.
 *
 *  WHERE, measured on Server 2022:
 *    - SYSTEM `Services\DHCPServer\Parameters`: settings, DatabasePath, DhcpLogFilePath,
 *      DhcpV6LogFilePath, CalloutDlls;
 *    - `dhcp.mdb` in DatabasePath, ESE, with its logs: ClientTable (IPv4 leases),
 *      LeaseTable (IPv6), DbcfgTable (scopes and class definitions), ConfigTable6;
 *    - `DhcpSrvLog-<day>.log`, `DhcpV6SrvLog-<day>.log`: the audit log, one file per
 *      day of the week, overwritten after seven days.
 *
 *  THE AUDIT LOG. Comma-separated, its header in the machine's language: columns are
 *  known by their position, not by that header. The date is MM/dd/yy (measured on a
 *  French server, "11/04/26" on 4 November), local time: converted with the
 *  examined machine's time zone.
 *
 *  ClientTable's HardwareAddress starts with the subnet (4 bytes, low byte first)
 *  and a hardware type byte: measured, 00 02 00 C0 01 for 192.0.2.0 before the client id.
 */
#pragma once

#include <string>
#include <vector>
#include "ese_database.h"
#include "tools.h"

//! One line of an audit log.
struct DhcpLogEntry {
	std::wstring eventId, description, address, hostName, hardwareAddress, userName;
	std::wstring transactionId, qResult, probationTime, correlationId, dhcid, vendorClassHex, vendorClassAscii,
	             userClassHex, userClassAscii, relayAgentInformation, dnsRegistrationError;
	std::wstring errorCode, duidLength, duidBytes, subnetPrefix;  //!< the IPv6 log's own columns
	bool v6 = false;              //!< from the IPv6 log, whose columns differ
	FILETIME time = { 0 };        //!< local time as written; 0 if the date does not read
	std::wstring timeAsStored;    //!< given when the date does not read
	std::wstring file;            //!< the file on the examined machine
	size_t line = 0;              //!< its line, from 1
	Json toJson() const;          //!< @return the entry as a JSON object
};

/*! Reads an audit log: lines that begin with a numeric event id and a date.
 *  @param text the log, decoded
 *  @param file its path on the examined machine
 *  @param v6 true for the IPv6 log
 *  @return the entries, in the log's order */
std::vector<DhcpLogEntry> parseDhcpAuditLog(const std::wstring& text, const std::wstring& file, bool v6);

/*! An address held in a Long column, most significant byte highest.
 *  @return its dotted form */
std::wstring dhcpAddressText(uint32_t address);

/*! The client's identifier in ClientTable's HardwareAddress.
 *  @param value the column, subnet and hardware type first
 *  @return the bytes after them, separated by dashes; empty if the value is too short */
std::wstring dhcpClientId(const std::vector<uint8_t>& value);

/*! The role's database and logs on the examined machine, from its registry or the
 *  defaults: what the collection takes. Needs conf.CurrentControlSet.
 *  @param database receives dhcp.mdb's folder
 *  @param logs receives the log folders, each once */
void dhcpServerFolders(std::wstring& database, std::vector<std::wstring>& logs);

/*! The artefact: dhcp_server_configuration.json, dhcp_server_scopes.json,
 *  dhcp_server_leases.json, dhcp_server_log.json. */
class DhcpServer {
public:
	HRESULT getData();  //!< @return ERROR_SUCCESS, even without the role
	HRESULT toJson();   //!< @return the result of the last write that failed, or ERROR_SUCCESS
	void clear();       //!< releases what was read
private:
	void readDatabase(const std::wstring& folder);
	Json configuration_ = Json::arr(), scopes_ = Json::arr(), leases_ = Json::arr();
	std::vector<DhcpLogEntry> logEntries_;
};

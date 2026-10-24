/*! \file
 *  \brief The Windows Firewall's log, pfirewall.log (backlog B-052).
 *
 *  WHAT THE ARTEFACT PROVES. When its logging is switched on, the firewall
 *  writes one line per connection it allowed or dropped: date and time,
 *  action, protocol, addresses and ports, size, direction, and the process
 *  since Windows 10. It is the only record of network flows a Windows keeps
 *  on its disk — what ATT&CK's "Network Traffic Flow" and "Network
 *  Connection Creation" otherwise take from a network capture: a connection
 *  to a command server, a scan of the local network, an exfiltration.
 *  Off by default; a dropped-only log is common. Windows rotates it into
 *  `<name>.old` once it reaches its size limit: both are taken.
 *
 *  WHERE. The LogFilePath of each profile, in the examined hives: the
 *  firewall's own settings (SYSTEM `…\SharedAccess\Parameters\FirewallPolicy\
 *  <Domain|Standard|Public>Profile\Logging`) and a group policy's (SOFTWARE
 *  `Policies\Microsoft\WindowsFirewall\<Domain|Private|Public>Profile\
 *  Logging`); the default besides, `System32\LogFiles\Firewall\pfirewall.log`
 *  (Windows XP: `Windows\pfirewall.log`), where a log may stay after its path
 *  was changed.
 *
 *  THE FORMAT, W3C-like text: "#Version: 1.5", "#Software: Microsoft Windows
 *  Firewall", "#Time Format: Local", "#Fields: date time action protocol
 *  src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin
 *  icmptype icmpcode info path [pid]", then one line per connection, the
 *  fields separated by spaces, "-" for a field without value. The dates are
 *  in the examined machine's local time: converted with its time zone
 *  (suspectLocalToUtc), as every local date of WAC.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! The firewall's logs the examined registry names, and the defaults: each
 *  once, case ignored, absolute; the rotated `.old` of each is not listed.
 *  Needs conf.CurrentControlSet and conf.Software (either missing: its
 *  settings are not read; the defaults stay). */
std::vector<std::wstring> firewallLogFiles();

/*! One line of the log: one connection allowed or dropped. */
struct FirewallLogEntry {
	std::wstring file;              //!< the log on the examined machine
	unsigned long long line = 0;    //!< its line, from 1
	FILETIME timeLocal = { 0 };     //!< date and time, local time as written; 0 if unreadable
	bool timeIsLocal = true;        //!< false when the header names another time format: the date is then given as stored
	std::wstring timeAsStored;      //!< "2026-10-24 15:01:02", given when it is not converted
	std::vector<std::pair<std::wstring, std::wstring>> fields; //!< the other fields, by their JSON key, "-" left out
	Json toJson() const;            //!< @return the entry as a JSON object
};

/*! Reads the lines of a log.
 *  @param text the log, decoded
 *  @param file its path on the examined machine, recorded in each entry
 *  @return the entries, in the log's order; a line before any "#Fields:" is skipped */
std::vector<FirewallLogEntry> parseFirewallLog(const std::wstring& text, const std::wstring& file);

/*! The firewall's logs (firewall_log.json). */
class FirewallLog {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any log
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<FirewallLogEntry> entries_;
};

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
 *  THE FORMAT, W3C extended text (w3c_log.h): "#Version: 1.5", "#Software:
 *  Microsoft Windows Firewall", "#Time Format: Local", "#Fields: date time
 *  action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn
 *  tcpack tcpwin icmptype icmpcode info path [pid]", then one line per
 *  connection. The dates are in the examined machine's local time:
 *  converted with its time zone (suspectLocalToUtc), as every local date of
 *  WAC.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "w3c_log.h"

/*! The firewall's logs the examined registry names, and the defaults: each
 *  once, case ignored, absolute; the rotated `.old` of each is not listed.
 *  Needs conf.CurrentControlSet and conf.Software (either missing: its
 *  settings are not read; the defaults stay). */
std::vector<std::wstring> firewallLogFiles();

/*! Reads the lines of a log: one connection allowed or dropped each.
 *  @param text the log, decoded
 *  @param file its path on the examined machine, recorded in each entry
 *  @return the entries, in the log's order; a line before any "#Fields:" is skipped */
std::vector<W3cLogEntry> parseFirewallLog(const std::wstring& text, const std::wstring& file);

/*! The firewall's logs (firewall_log.json). */
class FirewallLog {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any log
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<W3cLogEntry> entries_;
};

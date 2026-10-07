/*! \file
 *  \brief Incoming Remote Desktop connections, from the collected event logs.
 *
 *  WHAT THE ARTEFACT PROVES. Who connected to this machine by RDP, from
 *  where and when: little used on a workstation, the first question on a
 *  server. The traces are events, in the logs WAC collects (events.json
 *  holds them too, among two hundred thousand): this artefact gathers them,
 *  each with the fields an analysis looks for under one name.
 *
 *  THE EVENTS KEPT, measured on a real session of the test VM:
 *    - TerminalServices-RemoteConnectionManager/Operational: 261 (the
 *      listener received a connection), 1149 (user authenticated: user,
 *      domain, source address);
 *    - RemoteDesktopServices-RdpCoreTS/Operational: 131 (TCP connection
 *      accepted, source address and port);
 *    - TerminalServices-LocalSessionManager/Operational: 21 (logon), 22
 *      (shell started), 23 (logoff), 24 (disconnected), 25 (reconnected),
 *      39, 40 (disconnection and its reason), 41 (session arbitration);
 *    - Security: 4624, 4625 and 4634 of logon type 10 (RemoteInteractive),
 *      4778 and 4779 (session reconnected, disconnected: client name and
 *      address).
 *  Each record keeps the event's data as written, and adds User, Domain,
 *  SourceAddress and SessionId taken from the name each log gives them
 *  (Param1, TargetUserName, AccountName, User…). The instant is the event's,
 *  in UTC and in the machine's local time, as in events.json.
 *  Network logons of type 3 are not kept: NLA makes one per RDP connection,
 *  but so does every share or remote call — 1149 and 131 say which was RDP.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! The incoming RDP traces of the collected logs (rdp_server.json). */
class RdpServer {
public:
	/*! Reads the RDP events of the logs' working copies.
	 *  @return ERROR_SUCCESS, even without any: none is an answer */
	HRESULT getData();
	/*! Writes rdp_server.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the traces read.
	void clear();
private:
	std::vector<Json> records_;   //!< one per event kept, in the logs' order
};

/*! Whether an event is an incoming RDP trace (see the file's header).
 *  @param channel the event's channel
 *  @param eventId its identifier
 *  @param logonType its LogonType for a Security logon event, "" otherwise
 *  @return true if it is kept */
bool isIncomingRdpEvent(const std::wstring& channel, unsigned eventId, const std::wstring& logonType);

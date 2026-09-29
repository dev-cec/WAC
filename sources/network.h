/*! \file
 *  \brief THE NETWORK STATE of the examined machine, observed live: who talks
 *         to whom, and through what.
 *
 *  WHY. A connection to a command server, a port opened by an implant, a
 *  gateway or a DNS server changed to intercept the traffic: none of it is
 *  in a file or a hive. Only the running system knows it, at the moment of
 *  the collection. Four tables, in the order an analyst reads them:
 *    - Connections: TCP connections and UDP ports, IPv4 and IPv6, their state,
 *      the process that owns each (its PID, named at conversion from the
 *      processes observed) and WHEN each was created — Windows keeps that
 *      time, and it dates a connection the process list alone does not;
 *    - Neighbours: the ARP (IPv4) and NDP (IPv6) caches — the machines of the
 *      local network this one spoke with lately, a lateral movement's trail;
 *    - Interfaces: addresses, gateways, DNS servers, DHCP;
 *    - Routes: the routing table, where a route added to divert traffic shows.
 *
 *  THE FOOTPRINT. Reads of the TCP/IP stack's state, through iphlpapi:
 *  in-memory queries, no packet sent, no event logged. iphlpapi.dll is
 *  loaded at run time, from System32, and only when this artefact is asked
 *  for (wac.yml, artefacts.network): WAC.exe imports no network library, and
 *  Winsock is not used at all — the addresses are formatted by WAC
 *  (ip_address.h).
 *
 *  WHAT IT DOES NOT SEE: a connection already closed (its trace, if any, is
 *  in the event logs), nor one a kernel rootkit hides from the stack's
 *  tables. Recorded as a sealed live snapshot (live_snapshot.h), converted
 *  here or on an analysis workstation.
 */
#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include "tools.h"

// The iphlpapi types stay in network.cpp: their headers (winsock2.h) must come
// before windows.h, which every other header of WAC includes first.

/*! One TCP connection or UDP port, and the process that owns it. */
struct Connection {
	std::wstring protocol;          //!< TCP, TCP6, UDP or UDP6
	std::wstring localAddress;      //!< local address, as text (ip_address.h)
	unsigned localPort = 0;         //!< local port
	std::wstring remoteAddress;     //!< remote address; empty for UDP, which has none
	unsigned remotePort = 0;        //!< remote port, TCP only
	std::wstring state;             //!< TCP state spelled out; empty for UDP
	DWORD processId = 0;            //!< owning process (0: the System Idle Process, e.g. TIME_WAIT)
	FILETIME createdUtc = { 0 };    //!< creation of the socket, UTC; zero if Windows gives none

	/*! Converts the connection to JSON, as observed: the creation time as raw
	 *  ticks (Created100ns), formatted by writeNetworkFromSnapshot.
	 *  @return its JSON object. */
	Json toJson() const;
};

/*! One entry of the ARP (IPv4) or NDP (IPv6) cache. */
struct Neighbour {
	std::wstring address;           //!< IP address of the neighbour
	std::wstring hardwareAddress;   //!< its hardware (MAC) address
	std::wstring state;             //!< NL_NEIGHBOR_STATE spelled out
	ULONG interfaceIndex = 0;       //!< interface it was seen on
	bool router = false;            //!< true if it announced itself as a router

	/*! Converts the neighbour to JSON. @return its JSON object. */
	Json toJson() const;
};

/*! One network interface and its configuration. */
struct NetworkInterface {
	std::wstring name;              //!< friendly name ("Ethernet")
	std::wstring description;       //!< adapter description
	ULONG interfaceIndex = 0;       //!< index, as the neighbours and routes cite it
	std::wstring hardwareAddress;   //!< hardware (MAC) address
	bool up = false;                //!< operational state
	std::vector<std::wstring> addresses;  //!< unicast addresses
	std::vector<std::wstring> gateways;   //!< default gateways
	std::vector<std::wstring> dnsServers; //!< DNS servers
	std::wstring dnsSuffix;         //!< DNS suffix
	bool dhcp = false;              //!< IPv4 configured by DHCP
	std::wstring dhcpServer;        //!< the DHCP server, when dhcp

	/*! Converts the interface to JSON. @return its JSON object. */
	Json toJson() const;
};

/*! One entry of the routing table. */
struct Route {
	std::wstring destination;       //!< prefix, "address/length"
	std::wstring nextHop;           //!< next hop
	ULONG interfaceIndex = 0;       //!< interface the route goes through
	ULONG metric = 0;               //!< metric of the route

	/*! Converts the route to JSON. @return its JSON object. */
	Json toJson() const;
};

/*! The network state while the collection runs. */
struct NetworkState {
	std::vector<Connection> connections;       //!< TCP and UDP, IPv4 and IPv6
	std::vector<Neighbour> neighbours;         //!< ARP and NDP caches
	std::vector<NetworkInterface> interfaces;  //!< interfaces and their configuration
	std::vector<Route> routes;                 //!< routing table
	/*! The tables Windows refused to give: recorded, since a table not read is
	 *  not an empty table. */
	std::vector<std::wstring> tablesNotRead;

	/*! Loads iphlpapi.dll from System32 and reads the four tables.
	 *  @return S_OK (a table not read is in tablesNotRead), or why iphlpapi
	 *          could not be loaded. */
	HRESULT getData();

	/*! Records the network state as a live snapshot (live_snapshot.h), which
	 *  writeNetworkFromSnapshot publishes.
	 *  @return the result of the write. */
	HRESULT snapshot();

	//! Releases the memory held by the tables.
	void clear();
};

/*! Publishes `network.json` from the live snapshot of the collection: each
 *  connection with the name of its process, from the processes snapshot when
 *  there is one, and its creation time local and UTC.
 *  @return ERROR_SUCCESS, or the reason the snapshot could not be read or written */
HRESULT writeNetworkFromSnapshot();

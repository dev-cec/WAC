/*! \file
 *  \brief The network state, observed live (see network.h).
 */
// Winsock's headers FIRST: included after windows.h, they clash with the old
// winsock.h it brings. Only their types are used — no Winsock function is
// called, and no network library is imported (build-windows.sh checks it).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "network.h"
#include "system_library.h"
#include "ip_address.h"
#include "live_snapshot.h"
#include <algorithm>
#include <cstring>
#include <map>

namespace {

/*! AllocateAndGetTcpExTableFromStack and its UDP twin: the tables WITH THEIR
 *  OWNERS on Windows XP and Server 2003 before the service packs that brought
 *  GetExtendedTcpTable — and removed by Vista. They allocate the table on the
 *  heap given; the caller frees it. Declared here: the SDK headers no longer
 *  carry them. */
using StackTable = DWORD (WINAPI*)(void** table, BOOL sorted, HANDLE heap, DWORD heapFlags, DWORD family);

//! One row of the TCP table of AllocateAndGetTcpExTableFromStack (MIB_TCPROW_EX).
struct StackTcpRow { DWORD state, localAddress, localPort, remoteAddress, remotePort, processId; };
//! One row of the UDP table of AllocateAndGetUdpExTableFromStack (MIB_UDPROW_EX).
struct StackUdpRow { DWORD localAddress, localPort, processId; };

//! The iphlpapi functions used, resolved at run time (see network.h).
struct IpHelper {
	HMODULE module = nullptr;
	decltype(&GetExtendedTcpTable) tcpTable = nullptr;
	decltype(&GetExtendedUdpTable) udpTable = nullptr;
	decltype(&GetIpNetTable2) neighbourTable = nullptr;
	decltype(&GetIpForwardTable2) routeTable = nullptr;
	decltype(&FreeMibTable) freeTable = nullptr;
	decltype(&GetAdaptersAddresses) adapters = nullptr;
	// Before Vista (see readConnectionsFromStack, readArpTable, readIpv4Routes).
	StackTable tcpStackTable = nullptr;
	StackTable udpStackTable = nullptr;
	decltype(&GetIpNetTable) arpTable = nullptr;
	decltype(&GetIpForwardTable) ipv4RouteTable = nullptr;
	~IpHelper() { if (module) FreeLibrary(module); }
};

/*! Loads iphlpapi.dll from System32 — never from the current folder — and its
 *  functions. @return ERROR_SUCCESS, or why it could not be loaded */
HRESULT load(IpHelper& api) {
	api.module = loadSystemLibrary(L"iphlpapi.dll");
	if (!api.module) return HRESULT_FROM_WIN32(GetLastError());
	/* EACH TABLE HAS ITS OWN FUNCTIONS, and an older Windows lacks some: the
	   tables with owners came with XP SP2, the neighbour and route tables of
	   both families with Vista. One missing function used to give up the
	   whole network state ("the specified procedure could not be found",
	   under XP SP1); now each table is read by the function this Windows has,
	   and listed in TablesNotRead when it has none. Only a Windows offering
	   none of them fails. */
	const bool tcp = resolveExport(api.module, "GetExtendedTcpTable", api.tcpTable);
	const bool udp = resolveExport(api.module, "GetExtendedUdpTable", api.udpTable);
	const bool neighbours = resolveExport(api.module, "GetIpNetTable2", api.neighbourTable);
	const bool routes = resolveExport(api.module, "GetIpForwardTable2", api.routeTable);
	const bool release = resolveExport(api.module, "FreeMibTable", api.freeTable);
	const bool adapters = resolveExport(api.module, "GetAdaptersAddresses", api.adapters);
	/* What Windows XP and Server 2003 offer instead, IPv4 only: asked for only
	   where the function above is missing. */
	const bool stack = !(tcp && udp) && resolveExport(api.module, "AllocateAndGetTcpExTableFromStack", api.tcpStackTable)
	                   && resolveExport(api.module, "AllocateAndGetUdpExTableFromStack", api.udpStackTable);
	const bool arp = !(neighbours && release) && resolveExport(api.module, "GetIpNetTable", api.arpTable);
	const bool ipv4Routes = !(routes && release) && resolveExport(api.module, "GetIpForwardTable", api.ipv4RouteTable);
	const bool any = (tcp && udp) || (neighbours && release) || (routes && release) || adapters || stack || arp || ipv4Routes;
	return any ? ERROR_SUCCESS : HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
}

/*! A table whose size is asked first, then read — retried, since it may grow
 *  between the two calls. @return the table, empty if it could not be read */
template <typename Call>
std::vector<uint8_t> readTable(Call call) {
	for (int attempt = 0; attempt < 4; ++attempt) {
		ULONG size = 0;
		DWORD result = call(nullptr, &size);
		if (result != ERROR_INSUFFICIENT_BUFFER && result != ERROR_BUFFER_OVERFLOW) return {};
		std::vector<uint8_t> table(size + 4096);          // some room for rows added meanwhile
		size = (ULONG)table.size();
		result = call(table.data(), &size);
		if (result == NO_ERROR) return table;
		if (result != ERROR_INSUFFICIENT_BUFFER && result != ERROR_BUFFER_OVERFLOW) return {};
	}
	return {};
}

//! A port as the tables hold it: network order, in the low 16 bits.
unsigned port(DWORD raw) { return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF); }

//! An IPv4 address as the tables hold it: network order in a DWORD.
std::wstring ipv4(DWORD address) {
	uint8_t bytes[4];
	std::memcpy(bytes, &address, 4);
	return Ipv4Text(bytes);
}

//! MIB_TCP_STATE: an ENUMERATION (1 to 12), not a field of bits.
std::wstring tcpState(DWORD state) {
	static const wchar_t* const NAMES[] = { L"", L"CLOSED", L"LISTEN", L"SYN_SENT", L"SYN_RCVD", L"ESTABLISHED",
	                                         L"FIN_WAIT1", L"FIN_WAIT2", L"CLOSE_WAIT", L"CLOSING", L"LAST_ACK",
	                                         L"TIME_WAIT", L"DELETE_TCB" };
	return state >= 1 && state <= 12 ? NAMES[state] : L"";
}

//! NL_NEIGHBOR_STATE: an ENUMERATION (0 to 6), not a field of bits.
std::wstring neighbourState(int state) {
	static const wchar_t* const NAMES[] = { L"Unreachable", L"Incomplete", L"Probe", L"Delay", L"Stale", L"Reachable", L"Permanent" };
	return state >= 0 && state <= 6 ? NAMES[state] : L"";
}

//! An address of the IP Helper tables (SOCKADDR_INET): IPv4 or IPv6.
std::wstring address(const SOCKADDR_INET& a) {
	if (a.si_family == AF_INET) return Ipv4Text(reinterpret_cast<const uint8_t*>(&a.Ipv4.sin_addr));
	if (a.si_family == AF_INET6) return Ipv6Text(reinterpret_cast<const uint8_t*>(&a.Ipv6.sin6_addr));
	return std::wstring();
}

//! An address of GetAdaptersAddresses (SOCKET_ADDRESS), bounded by its announced length.
std::wstring address(const SOCKET_ADDRESS& a) {
	if (!a.lpSockaddr) return std::wstring();
	if (a.lpSockaddr->sa_family == AF_INET && a.iSockaddrLength >= (INT)sizeof(sockaddr_in))
		return Ipv4Text(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in*>(a.lpSockaddr)->sin_addr));
	if (a.lpSockaddr->sa_family == AF_INET6 && a.iSockaddrLength >= (INT)sizeof(sockaddr_in6))
		return Ipv6Text(reinterpret_cast<const uint8_t*>(&reinterpret_cast<const sockaddr_in6*>(a.lpSockaddr)->sin6_addr));
	return std::wstring();
}

//! The addresses of a list of GetAdaptersAddresses.
template <typename Entry>
std::vector<std::wstring> addresses(const Entry* first) {
	std::vector<std::wstring> list;
	for (const Entry* e = first; e; e = e->Next) {
		std::wstring text = address(e->Address);
		if (!text.empty()) list.push_back(std::move(text));
	}
	return list;
}

//! A list of texts as a JSON array.
Json textArray(const std::vector<std::wstring>& texts) {
	Json list = Json::arr();
	for (const std::wstring& t : texts) list.push(Json::str(t));
	return list;
}

//! A table AllocateAndGet…FromStack allocated on the process heap, freed with it.
struct StackTableMemory {
	void* table = nullptr;
	~StackTableMemory() { if (table) HeapFree(GetProcessHeap(), 0, table); }
	/*! The rows the allocation really holds: the count the table announces,
	 *  bounded by the size of its block. */
	template <typename Row>
	std::vector<Row> rows() const {
		std::vector<Row> list;
		const SIZE_T size = table ? HeapSize(GetProcessHeap(), 0, table) : (SIZE_T)-1;
		if (size == (SIZE_T)-1 || size < sizeof(DWORD)) return list;
		DWORD announced = 0;
		std::memcpy(&announced, table, sizeof(announced));
		const size_t held = std::min<size_t>(announced, (size - sizeof(DWORD)) / sizeof(Row));
		list.resize(held);
		if (held) std::memcpy(list.data(), static_cast<const uint8_t*>(table) + sizeof(DWORD), held * sizeof(Row));
		return list;
	}
};

/*! The TCP and UDP tables of Windows XP and Server 2003, IPv4, with their
 *  owners; these versions keep no creation time. @return false if one of the
 *  two could not be read */
bool readConnectionsFromStack(const IpHelper& api, std::vector<Connection>& connections) {
	StackTableMemory tcp, udp;
	if (api.tcpStackTable(&tcp.table, FALSE, GetProcessHeap(), 0, AF_INET) != NO_ERROR || !tcp.table) return false;
	if (api.udpStackTable(&udp.table, FALSE, GetProcessHeap(), 0, AF_INET) != NO_ERROR || !udp.table) return false;
	/* A LISTENING socket has no remote port, and these tables leave whatever
	   was in memory there (seen under XP SP1: 20675, 63591… where netstat
	   prints 0): Windows documents the field as meaningless in that state. */
	for (const StackTcpRow& r : tcp.rows<StackTcpRow>())
		connections.push_back({ L"TCP", ipv4(r.localAddress), port(r.localPort), ipv4(r.remoteAddress),
		                        r.state == MIB_TCP_STATE_LISTEN ? 0 : port(r.remotePort), tcpState(r.state), r.processId, FILETIME{ 0, 0 } });
	for (const StackUdpRow& r : udp.rows<StackUdpRow>())
		connections.push_back({ L"UDP", ipv4(r.localAddress), port(r.localPort), L"", 0, L"", r.processId, FILETIME{ 0, 0 } });
	return true;
}

//! MIB_IPNET_TYPE of the ARP table of before Vista: an ENUMERATION (1 to 4).
std::wstring arpEntryType(DWORD type) {
	static const wchar_t* const NAMES[] = { L"", L"Other", L"Invalid", L"Dynamic", L"Static" };
	return type >= 1 && type <= 4 ? NAMES[type] : L"";
}

/*! The ARP cache through GetIpNetTable, IPv4 — what Windows XP and Server
 *  2003 offer. An empty cache (ERROR_NO_DATA) is a table read.
 *  @return false if it could not be read */
bool readArpTable(const IpHelper& api, std::vector<Neighbour>& neighbours) {
	ULONG size = 0;
	DWORD result = api.arpTable(nullptr, &size, FALSE);
	if (result == ERROR_NO_DATA) return true;
	if (result != ERROR_INSUFFICIENT_BUFFER) return false;
	std::vector<uint8_t> buffer(size + 4096);          // some room for rows added meanwhile
	size = (ULONG)buffer.size();
	result = api.arpTable(reinterpret_cast<PMIB_IPNETTABLE>(buffer.data()), &size, FALSE);
	if (result == ERROR_NO_DATA) return true;
	if (result != NO_ERROR) return false;
	const auto* table = reinterpret_cast<const MIB_IPNETTABLE*>(buffer.data());
	const size_t held = std::min<size_t>(table->dwNumEntries, (buffer.size() - offsetof(MIB_IPNETTABLE, table)) / sizeof(MIB_IPNETROW));
	for (size_t k = 0; k < held; ++k) {
		const MIB_IPNETROW& r = table->table[k];
		Neighbour n;
		n.address = ipv4(r.dwAddr);
		n.hardwareAddress = HardwareAddressText(r.bPhysAddr, std::min<ULONG>(r.dwPhysAddrLen, sizeof(r.bPhysAddr)));
		n.type = arpEntryType(r.dwType);
		n.interfaceIndex = r.dwIndex;
		neighbours.push_back(std::move(n));
	}
	return true;
}

//! The length of an IPv4 mask as the tables hold it: its bits set.
unsigned prefixLength(DWORD mask) {
	unsigned length = 0;
	for (; mask; mask &= mask - 1) ++length;
	return length;
}

/*! The IPv4 routing table through GetIpForwardTable — what Windows XP and
 *  Server 2003 offer. @return false if it could not be read */
bool readIpv4Routes(const IpHelper& api, std::vector<Route>& routes) {
	const std::vector<uint8_t> buffer = readTable([&](void* t, ULONG* s) {
		return api.ipv4RouteTable(reinterpret_cast<PMIB_IPFORWARDTABLE>(t), s, FALSE); });
	if (buffer.empty()) return false;
	const auto* table = reinterpret_cast<const MIB_IPFORWARDTABLE*>(buffer.data());
	const size_t held = std::min<size_t>(table->dwNumEntries, (buffer.size() - offsetof(MIB_IPFORWARDTABLE, table)) / sizeof(MIB_IPFORWARDROW));
	for (size_t k = 0; k < held; ++k) {
		const MIB_IPFORWARDROW& r = table->table[k];
		routes.push_back({ ipv4(r.dwForwardDest) + L"/" + std::to_wstring(prefixLength(r.dwForwardMask)),
		                   ipv4(r.dwForwardNextHop), r.dwForwardIfIndex, r.dwForwardMetric1 });
	}
	return true;
}

/*! Reads the TCP and UDP tables, IPv4 and IPv6, with their owners and
 *  creation times. @return false if one of the four could not be read */
bool readConnections(const IpHelper& api, std::vector<Connection>& connections) {
	auto tcp = [&](ULONG family) { return readTable([&](void* t, ULONG* s) { return api.tcpTable(t, s, FALSE, family, TCP_TABLE_OWNER_MODULE_ALL, 0); }); };
	auto udp = [&](ULONG family) { return readTable([&](void* t, ULONG* s) { return api.udpTable(t, s, FALSE, family, UDP_TABLE_OWNER_MODULE, 0); }); };
	const std::vector<uint8_t> tcp4 = tcp(AF_INET), tcp6 = tcp(AF_INET6), udp4 = udp(AF_INET), udp6 = udp(AF_INET6);
	if (!tcp4.empty()) {
		const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_MODULE*>(tcp4.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_TCPROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"TCP", ipv4(r.dwLocalAddr), port(r.dwLocalPort), ipv4(r.dwRemoteAddr),
			                        port(r.dwRemotePort), tcpState(r.dwState), r.dwOwningPid, filetimeFromTicks((uint64_t)r.liCreateTimestamp.QuadPart) });
		}
	}
	if (!tcp6.empty()) {
		const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_MODULE*>(tcp6.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_TCP6ROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"TCP6", Ipv6Text(r.ucLocalAddr), port(r.dwLocalPort), Ipv6Text(r.ucRemoteAddr),
			                        port(r.dwRemotePort), tcpState(r.dwState), r.dwOwningPid, filetimeFromTicks((uint64_t)r.liCreateTimestamp.QuadPart) });
		}
	}
	if (!udp4.empty()) {
		const auto* t = reinterpret_cast<const MIB_UDPTABLE_OWNER_MODULE*>(udp4.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_UDPROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"UDP", ipv4(r.dwLocalAddr), port(r.dwLocalPort), L"", 0, L"", r.dwOwningPid,
			                        filetimeFromTicks((uint64_t)r.liCreateTimestamp.QuadPart) });
		}
	}
	if (!udp6.empty()) {
		const auto* t = reinterpret_cast<const MIB_UDP6TABLE_OWNER_MODULE*>(udp6.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_UDP6ROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"UDP6", Ipv6Text(r.ucLocalAddr), port(r.dwLocalPort), L"", 0, L"", r.dwOwningPid,
			                        filetimeFromTicks((uint64_t)r.liCreateTimestamp.QuadPart) });
		}
	}
	return !tcp4.empty() && !tcp6.empty() && !udp4.empty() && !udp6.empty();
}

//! Reads the ARP and NDP caches. @return false if they could not be read
bool readNeighbours(const IpHelper& api, std::vector<Neighbour>& neighbours) {
	PMIB_IPNET_TABLE2 table = nullptr;
	if (api.neighbourTable(AF_UNSPEC, &table) != NO_ERROR || !table) return false;
	for (ULONG k = 0; k < table->NumEntries; ++k) {
		const MIB_IPNET_ROW2& r = table->Table[k];
		const ULONG length = std::min<ULONG>(r.PhysicalAddressLength, sizeof(r.PhysicalAddress));
		neighbours.push_back({ address(r.Address), HardwareAddressText(r.PhysicalAddress, length),
		                       neighbourState((int)r.State), L"", r.InterfaceIndex, r.IsRouter != FALSE });
	}
	api.freeTable(table);
	return true;
}

//! Reads the routing table. @return false if it could not be read
bool readRoutes(const IpHelper& api, std::vector<Route>& routes) {
	PMIB_IPFORWARD_TABLE2 table = nullptr;
	if (api.routeTable(AF_UNSPEC, &table) != NO_ERROR || !table) return false;
	for (ULONG k = 0; k < table->NumEntries; ++k) {
		const MIB_IPFORWARD_ROW2& r = table->Table[k];
		routes.push_back({ address(r.DestinationPrefix.Prefix) + L"/" + std::to_wstring(r.DestinationPrefix.PrefixLength),
		                   address(r.NextHop), r.InterfaceIndex, r.Metric });
	}
	api.freeTable(table);
	return true;
}

//! Reads the interfaces and their configuration. @return false if they could not be read
bool readInterfaces(const IpHelper& api, std::vector<NetworkInterface>& interfaces) {
	if (!api.adapters) return false;
	/* The gateways are a flag of Windows Vista: asked for first, and the
	   table read without them if this Windows does not know the flag. */
	std::vector<uint8_t> buffer;
	for (const ULONG gateways : { (ULONG)GAA_FLAG_INCLUDE_GATEWAYS, 0UL }) {
		const ULONG flags = gateways | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
		buffer = readTable([&](void* t, ULONG* s) {
			return api.adapters(AF_UNSPEC, flags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(t), s); });
		if (!buffer.empty()) break;
	}
	if (buffer.empty()) return false;
	/* EACH ADAPTER STATES ITS OWN LENGTH, and the structure grew with the
	   versions: Windows XP's ends before the gateways and the DHCP server
	   that Vista added. A field is read only if this adapter's structure
	   holds it — read past its end, it was whatever followed in the buffer,
	   taken for a pointer: WAC32 crashed under Windows XP SP1. */
	const auto holds = [](const IP_ADAPTER_ADDRESSES* a, size_t offset, size_t size) { return offset + size <= a->Length; };
	for (auto* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
		NetworkInterface i;
		i.name = a->FriendlyName ? a->FriendlyName : L"";
		i.description = a->Description ? a->Description : L"";
		i.interfaceIndex = a->IfIndex;
		i.hardwareAddress = HardwareAddressText(a->PhysicalAddress, std::min<ULONG>(a->PhysicalAddressLength, sizeof(a->PhysicalAddress)));
		i.up = a->OperStatus == IfOperStatusUp;
		i.addresses = addresses(a->FirstUnicastAddress);
		if (holds(a, offsetof(IP_ADAPTER_ADDRESSES, FirstGatewayAddress), sizeof(a->FirstGatewayAddress)))
			i.gateways = addresses(a->FirstGatewayAddress);
		i.dnsServers = addresses(a->FirstDnsServerAddress);
		i.dnsSuffix = a->DnsSuffix ? a->DnsSuffix : L"";
		i.dhcp = a->Dhcpv4Enabled != 0;
		if (i.dhcp && holds(a, offsetof(IP_ADAPTER_ADDRESSES, Dhcpv4Server), sizeof(a->Dhcpv4Server)))
			i.dhcpServer = address(a->Dhcpv4Server);
		interfaces.push_back(std::move(i));
	}
	return true;
}

} // namespace

Json Connection::toJson() const {
	Json o = Json::obj();
	o.add(L"Protocol", Json::str(protocol));
	o.add(L"LocalAddress", Json::str(localAddress));
	o.add(L"LocalPort", Json::num(localPort));
	o.add(L"RemoteAddress", Json::str(remoteAddress));
	if (!remoteAddress.empty()) o.add(L"RemotePort", Json::num(remotePort));
	o.add(L"State", Json::str(state));
	o.add(L"ProcessId", Json::num(processId));
	// Raw ticks, as sessions.json: the conversion writes them local (the
	// examined machine's offset at that date) and UTC.
	const unsigned long long ticks = ticksFromFiletime(createdUtc);
	if (ticks) o.add(L"Created100ns", Json::num(ticks));
	return o;
}

Json Neighbour::toJson() const {
	Json o = Json::obj();
	o.add(L"Address", Json::str(address));
	o.add(L"HardwareAddress", Json::str(hardwareAddress));
	o.add(L"State", Json::str(state));
	o.add(L"Type", Json::str(type));
	o.add(L"InterfaceIndex", Json::num(interfaceIndex));
	if (router) o.add(L"Router", Json::boolean(true));
	return o;
}

Json NetworkInterface::toJson() const {
	Json o = Json::obj();
	o.add(L"Name", Json::str(name));
	o.add(L"Description", Json::str(description));
	o.add(L"InterfaceIndex", Json::num(interfaceIndex));
	o.add(L"HardwareAddress", Json::str(hardwareAddress));
	o.add(L"Up", Json::boolean(up));
	o.add(L"Addresses", textArray(addresses));
	o.add(L"Gateways", textArray(gateways));
	o.add(L"DnsServers", textArray(dnsServers));
	o.add(L"DnsSuffix", Json::str(dnsSuffix));
	o.add(L"Dhcp", Json::boolean(dhcp));
	o.add(L"DhcpServer", Json::str(dhcpServer));
	return o;
}

Json Route::toJson() const {
	Json o = Json::obj();
	o.add(L"Destination", Json::str(destination));
	o.add(L"NextHop", Json::str(nextHop));
	o.add(L"InterfaceIndex", Json::num(interfaceIndex));
	o.add(L"Metric", Json::num(metric));
	return o;
}

HRESULT NetworkState::getData() {
	log(3, L"🔈network getData");
	IpHelper api;
	const HRESULT hresult = load(api);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥LoadLibraryExW iphlpapi.dll", hresult);
		return hresult;
	}
	/* EACH TABLE BY THE FUNCTION THIS WINDOWS HAS: the one of Vista and later,
	   both address families; else the one of Windows XP and Server 2003, which
	   knows IPv4 only — said in TablesIpv4Only, so that the absence of an IPv6
	   row is not read as "no IPv6 connection". */
	const auto read = [&](const wchar_t* table, bool current, bool older, auto&& readCurrent, auto&& readOlder) {
		if (current) { if (!readCurrent()) tablesNotRead.push_back(table); }
		else if (!older || !readOlder()) tablesNotRead.push_back(table);
		else tablesIpv4Only.push_back(table);
	};
	read(L"Connections", api.tcpTable && api.udpTable, api.tcpStackTable && api.udpStackTable,
	     [&] { return readConnections(api, connections); }, [&] { return readConnectionsFromStack(api, connections); });
	read(L"Neighbours", api.neighbourTable && api.freeTable, api.arpTable != nullptr,
	     [&] { return readNeighbours(api, neighbours); }, [&] { return readArpTable(api, neighbours); });
	if (!readInterfaces(api, interfaces)) tablesNotRead.push_back(L"Interfaces");
	read(L"Routes", api.routeTable && api.freeTable, api.ipv4RouteTable != nullptr,
	     [&] { return readRoutes(api, routes); }, [&] { return readIpv4Routes(api, routes); });
	return ERROR_SUCCESS;
}

HRESULT NetworkState::snapshot() {
	log(3, L"🔈network snapshot");
	Json state = Json::obj();
	Json list = Json::arr();
	for (const Connection& c : connections) list.push(c.toJson());
	state.add(L"Connections", std::move(list));
	list = Json::arr();
	for (const Neighbour& n : neighbours) list.push(n.toJson());
	state.add(L"Neighbours", std::move(list));
	list = Json::arr();
	for (const NetworkInterface& i : interfaces) list.push(i.toJson());
	state.add(L"Interfaces", std::move(list));
	list = Json::arr();
	for (const Route& r : routes) list.push(r.toJson());
	state.add(L"Routes", std::move(list));
	state.add(L"TablesNotRead", textArray(tablesNotRead));
	state.add(L"TablesIpv4Only", textArray(tablesIpv4Only));
	return writeLiveSnapshot("network.json", state, L"network state (TCP/UDP tables, neighbours, interfaces, routes)");
}

void NetworkState::clear() {
	log(3, L"🔈network clear");
	connections.clear();
	neighbours.clear();
	interfaces.clear();
	routes.clear();
	tablesNotRead.clear();
	tablesIpv4Only.clear();
}

HRESULT writeNetworkFromSnapshot() {
	Json snapshot = Json::null();
	const HRESULT hresult = readLiveSnapshot("network.json", snapshot);
	if (hresult != ERROR_SUCCESS) return hresult;
	// The processes observed, by PID: the owner of a connection named as
	// observed at the same collection.
	std::map<std::wstring, std::wstring> names;
	Json processes = Json::null();
	if (readLiveSnapshot("processes.json", processes) == ERROR_SUCCESS)
		for (const auto& process : processes.members()) {
			const Json* pid = process.second.find(L"ProcessId");
			const Json* name = process.second.find(L"Name");
			if (pid && name) names[pid->text()] = name->text();
		}
	// Each connection with its process name after its PID, and its creation
	// time local and UTC in place of the raw ticks; the other tables as observed.
	Json published = Json::obj();
	for (const auto& table : snapshot.members()) {
		if (table.first != L"Connections") { published.add(table.first, table.second); continue; }
		Json list = Json::arr();
		for (const auto& connection : table.second.members()) {
			Json o = Json::obj();
			for (const auto& field : connection.second.members()) {
				long long ticks = 0;
				if (field.first != L"Created100ns") o.add(field.first, field.second);
				else if (snapshotInteger(field.second, ticks) && ticks > 0) {
					const FILETIME created = filetimeFromTicks(ticks);
					o.add(L"Created",    Json::str(utcTimeToIso8601Local(created)));
					o.add(L"CreatedUtc", Json::str(timeToIso8601Utc(created)));
				}
				if (field.first == L"ProcessId") {
					const auto found = names.find(field.second.text());
					if (found != names.end()) o.add(L"Process", Json::str(found->second));
				}
			}
			list.push(std::move(o));
		}
		published.add(table.first, std::move(list));
	}
	return writeJsonFile("network.json", published);
}

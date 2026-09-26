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
#include "ip_address.h"
#include "live_snapshot.h"
#include <algorithm>
#include <cstring>
#include <map>

namespace {

//! The iphlpapi functions used, resolved at run time (see network.h).
struct IpHelper {
	HMODULE module = nullptr;
	decltype(&GetExtendedTcpTable) tcpTable = nullptr;
	decltype(&GetExtendedUdpTable) udpTable = nullptr;
	decltype(&GetIpNetTable2) neighbourTable = nullptr;
	decltype(&GetIpForwardTable2) routeTable = nullptr;
	decltype(&FreeMibTable) freeTable = nullptr;
	decltype(&GetAdaptersAddresses) adapters = nullptr;
	~IpHelper() { if (module) FreeLibrary(module); }
};

//! One function of the loaded module. @return false if it is missing
template <typename F>
bool resolve(HMODULE module, const char* name, F& target) {
	target = reinterpret_cast<F>(reinterpret_cast<void*>(GetProcAddress(module, name)));
	return target != nullptr;
}

/*! Loads iphlpapi.dll from System32 — never from the current folder — and its
 *  functions. @return ERROR_SUCCESS, or why it could not be loaded */
HRESULT load(IpHelper& api) {
	api.module = LoadLibraryExW(L"iphlpapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!api.module) return HRESULT_FROM_WIN32(GetLastError());
	const bool complete = resolve(api.module, "GetExtendedTcpTable", api.tcpTable)
	    && resolve(api.module, "GetExtendedUdpTable", api.udpTable)
	    && resolve(api.module, "GetIpNetTable2", api.neighbourTable)
	    && resolve(api.module, "GetIpForwardTable2", api.routeTable)
	    && resolve(api.module, "FreeMibTable", api.freeTable)
	    && resolve(api.module, "GetAdaptersAddresses", api.adapters);
	return complete ? ERROR_SUCCESS : HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
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

//! A creation time as the tables hold it: FILETIME ticks in a LARGE_INTEGER.
FILETIME filetime(const LARGE_INTEGER& time) {
	return { time.LowPart, (DWORD)time.HighPart };
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
			                        port(r.dwRemotePort), tcpState(r.dwState), r.dwOwningPid, filetime(r.liCreateTimestamp) });
		}
	}
	if (!tcp6.empty()) {
		const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_MODULE*>(tcp6.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_TCP6ROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"TCP6", Ipv6Text(r.ucLocalAddr), port(r.dwLocalPort), Ipv6Text(r.ucRemoteAddr),
			                        port(r.dwRemotePort), tcpState(r.dwState), r.dwOwningPid, filetime(r.liCreateTimestamp) });
		}
	}
	if (!udp4.empty()) {
		const auto* t = reinterpret_cast<const MIB_UDPTABLE_OWNER_MODULE*>(udp4.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_UDPROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"UDP", ipv4(r.dwLocalAddr), port(r.dwLocalPort), L"", 0, L"", r.dwOwningPid,
			                        filetime(r.liCreateTimestamp) });
		}
	}
	if (!udp6.empty()) {
		const auto* t = reinterpret_cast<const MIB_UDP6TABLE_OWNER_MODULE*>(udp6.data());
		for (DWORD k = 0; k < t->dwNumEntries; ++k) {
			const MIB_UDP6ROW_OWNER_MODULE& r = t->table[k];
			connections.push_back({ L"UDP6", Ipv6Text(r.ucLocalAddr), port(r.dwLocalPort), L"", 0, L"", r.dwOwningPid,
			                        filetime(r.liCreateTimestamp) });
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
		                       neighbourState((int)r.State), r.InterfaceIndex, r.IsRouter != FALSE });
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
	const ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
	const std::vector<uint8_t> buffer = readTable([&](void* t, ULONG* s) {
		return api.adapters(AF_UNSPEC, flags, nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(t), s); });
	if (buffer.empty()) return false;
	for (auto* a = reinterpret_cast<const IP_ADAPTER_ADDRESSES*>(buffer.data()); a; a = a->Next) {
		NetworkInterface i;
		i.name = a->FriendlyName ? a->FriendlyName : L"";
		i.description = a->Description ? a->Description : L"";
		i.interfaceIndex = a->IfIndex;
		i.hardwareAddress = HardwareAddressText(a->PhysicalAddress, std::min<ULONG>(a->PhysicalAddressLength, sizeof(a->PhysicalAddress)));
		i.up = a->OperStatus == IfOperStatusUp;
		i.addresses = addresses(a->FirstUnicastAddress);
		i.gateways = addresses(a->FirstGatewayAddress);
		i.dnsServers = addresses(a->FirstDnsServerAddress);
		i.dnsSuffix = a->DnsSuffix ? a->DnsSuffix : L"";
		i.dhcp = a->Dhcpv4Enabled != 0;
		if (i.dhcp) i.dhcpServer = address(a->Dhcpv4Server);
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
	const unsigned long long ticks = ((unsigned long long)createdUtc.dwHighDateTime << 32) | createdUtc.dwLowDateTime;
	if (ticks) o.add(L"Created100ns", Json::num(ticks));
	return o;
}

Json Neighbour::toJson() const {
	Json o = Json::obj();
	o.add(L"Address", Json::str(address));
	o.add(L"HardwareAddress", Json::str(hardwareAddress));
	o.add(L"State", Json::str(state));
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
	if (!readConnections(api, connections)) tablesNotRead.push_back(L"Connections");
	if (!readNeighbours(api, neighbours)) tablesNotRead.push_back(L"Neighbours");
	if (!readInterfaces(api, interfaces)) tablesNotRead.push_back(L"Interfaces");
	if (!readRoutes(api, routes)) tablesNotRead.push_back(L"Routes");
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
	return writeLiveSnapshot("network.json", state, L"network state (TCP/UDP tables, neighbours, interfaces, routes)");
}

void NetworkState::clear() {
	log(3, L"🔈network clear");
	connections.clear();
	neighbours.clear();
	interfaces.clear();
	routes.clear();
	tablesNotRead.clear();
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
					const FILETIME created = { (DWORD)((unsigned long long)ticks & 0xFFFFFFFFULL),
					                           (DWORD)((unsigned long long)ticks >> 32) };
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

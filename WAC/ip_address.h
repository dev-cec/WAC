/*! \file
 *  \brief IP ADDRESSES AS TEXT, for the network state WAC records.
 *
 *  WHY WAC'S OWN. Windows formats addresses through Winsock (inet_ntop) or
 *  ntdll; the first would import ws2_32.dll, which the build refuses (see
 *  build-windows.sh), the second is undocumented. The formats are short and
 *  fixed:
 *    - IPv4: dotted decimal, "192.168.1.10";
 *    - IPv6: RFC 5952, the one form an analyst compares — lowercase, leading
 *      zeros dropped, the LONGEST run of two or more zero groups (the first
 *      if tied) written "::", and an IPv4-mapped address as
 *      "::ffff:192.168.1.10".
 *  Two forms of one address would make one connection look like two.
 *
 *  Portable C++: checked against Python's ipaddress (see ip_address_test).
 */
#pragma once

#include <cstdint>
#include <string>

/*! @param address the four bytes, in network order (as on the wire)
 *  @return dotted decimal */
std::wstring Ipv4Text(const uint8_t address[4]);

/*! @param address the sixteen bytes, in network order
 *  @return the RFC 5952 form */
std::wstring Ipv6Text(const uint8_t address[16]);

/*! @param bytes,size a hardware address
 *  @return "aa-bb-cc-dd-ee-ff", uppercase as Windows shows it; "" if empty */
std::wstring HardwareAddressText(const uint8_t* bytes, size_t size);

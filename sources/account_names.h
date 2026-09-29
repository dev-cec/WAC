/*! \file
 *  \brief Names of the SIDs, resolved OFFLINE from the examined machine's
 *         hives — never by asking the running system or the network.
 *
 *  WHY. WAC named the SIDs with LookupAccountSidW. For a domain SID that the
 *  machine does not know, that call QUERIES THE DOMAIN CONTROLLER: a trace of
 *  the collection on another machine, in its logs, plus the local LSA cache.
 *  It also made the output depend on the machine running WAC — its language
 *  ("Système" for S-1-5-18 on a French Windows), its domain, its network — so
 *  that a conversion could not be reproduced elsewhere. The names now come from
 *  the evidence alone, in this order of precedence:
 *    1. the SAM hive: local users, groups and aliases (domain of the machine
 *       SID) and built-in groups (S-1-5-32-…), through the "Names" index,
 *       where the TYPE of each name's default value is its RID — the names in
 *       the language the machine was installed in, as it knows them;
 *    2. the well-known SIDs of Windows, under their canonical names;
 *    3. the service SIDs (S-1-5-80-…), computed from the service names of the
 *       SYSTEM hive as Windows computes them: SHA-1 of the upper-case name;
 *    4. the user profiles (ProfileList): the profile folder names the account
 *       — the only offline source for a domain account.
 *  A SID none of them names is published without a name: the SID itself is
 *  the evidence, and the analyst can resolve it against the domain.
 *
 *  getNameFromSid (tools.h) reads this table.
 */
#pragma once
#include <windows.h>
#include <string>

/*! Builds the table SID -> name from the evidence. To be called once the
 *  profiles are read (loadProfileList) and conf.CurrentControlSet is open,
 *  BEFORE any artefact that names an account is read or written.
 *  @return ERROR_SUCCESS, or the error that kept the SAM from being read (the
 *          other sources are loaded all the same) */
HRESULT loadAccountNames();

/*! The service SID Windows derives from a service name: "S-1-5-80-" followed
 *  by the five little-endian 32-bit words of the SHA-1 of the name in upper
 *  case, in UTF-16LE. Checked against LookupAccountNameW("NT SERVICE\\<name>")
 *  for every service of the test machine (system_conversions_test.cpp).
 *  @param service the service name (key name under Services)
 *  @return the SID, as text */
std::wstring serviceSid(const std::wstring& service);

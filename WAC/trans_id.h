#pragma once

/*! \file
 *  \brief Lookup tables: a raw identifier -> a readable label.
 *
 *  The Windows artefacts name things by codes: a COM class GUID, a task-bar
 *  AppID, a service type code, a network provider index. Only the label makes
 *  those codes usable in a report.
 *
 *  WHERE THE LABELS COME FROM. The GUID and AppID tables are aligned on
 *  libyal's reference data (libfwsi) rather than gathered by hand: a table typed
 *  by guesswork produces labels that look plausible and are wrong, and nothing
 *  in the output would reveal it.
 *
 *  PERFORMANCE. The two large tables (16,639 GUIDs, 727 AppIDs) are indexed in
 *  an `unordered_map` built at the first call, not walked. The original version
 *  chained tens of thousands of `if` for every identifier to translate, which
 *  dominated the collection time.
 *
 *  MIND THE BIT FIELDS. Several Windows codes are not enumerations but
 *  combinable flags, and some constants are themselves combinations
 *  (SERVICE_USER_SHARE_PROCESS = 0x60 = 0x40|0x20). Comparing them by equality,
 *  or with `&` without distinguishing the elementary bits, produces
 *  contradictory labels.
 */

#include <string>
#include <regex>
#include <windows.h>



/*! Converts a service type code to a name.
* @param type the type, as a number
* @return the name of that type
*/
std::wstring serviceType_to_wstring(int type);

/*! Converts a service start type code to a name.
* @param type the type, as a number
* @return the name of that type
*/
std::wstring serviceStart_to_wstring(int type);


/*! Converts a service state code to a name.
* @param type the state, as a number
* @return the name of that state
*/
std::wstring serviceState_to_wstring(int type);

/*! Converts a logon type code to a name.
* @param type the type, as a number
* @return the name of that type
*/
std::wstring logon_type(ULONG type);

/*! Converts an OS architecture code to a name.
* @param archi the architecture, as a number
* @return the name of that architecture
*/
std::wstring os_architecture(DWORD archi);

/*! Converts an APPID to an application name.
* For instance the appId "0006f647f9488d7a" is the application "AIM 7.5.11.9
* (custom AppID + JL support)".
* @param appId identifier of the application
* @return the name of the application that AppID belongs to
*/
std::wstring from_appId(std::wstring appId);

/*! Converts a subnetwork code to a subnetwork type name.
* For instance subnetwork 1 is "Domain/WorkGroup Description".
* @param type the subnetwork code
* @return the name of that subnetwork type
*/
std::wstring networkSubType(unsigned char type);

/*! Converts a network provider code to a network provider name.
* For instance the code 0x001A0000 is the network provider "WNNC_NET_AVID".
* @param n the network provider code
* @return the name of that network provider
*/
std::wstring networkProvider_to_wstring(unsigned int n);

/*! Converts a drive type code to a drive type name.
* For instance the code 2 is "DRIVE_REMOVABLE".
* @param d the drive type code
* @return the name of that drive type
*/
std::wstring driveType_to_wstring(unsigned int d);

/*! Converts a code to a show-command name.
* For instance the code 3 is "SHOWMAXIMIZED".
* @param option the code
* @return the matching name
*/
std::wstring showCommandOption(unsigned int option);

/*! Converts a code to an index name.
* For instance the code 0 is "INTERNET_EXPLORER".
* @param i the code
* @return the matching name
*/
std::wstring sort_index(unsigned char i);

/*! Converts a shell item category code to a name.
* For instance the code 1 is "CONTROL_PANEL_CATEGORY".
* @param i the code
* @return the matching name
*/
std::wstring shell_item_class(unsigned char i);

/*! Nature of a "users property view" shell item, from its signature.
*
* WHY IT IS NECESSARY. The signature does not only serve to choose a decoder: at
* libyal (libfwsi) it IDENTIFIES the kind of item. Two of the signatures WAC
* handled under the generic name "UserPropertyView" are in fact media devices —
* an MTP volume and an MTP file entry — that is, the trace that a phone or a
* camera was connected and browsed. The generic name hid that fact completely.
*
* @param signature the signature read at offset 6 of the item
* @return the label, or "" if the signature is not listed
*/
std::wstring shell_item_signature(unsigned int signature);

/*! Converts a GUID to a name.
* For instance the guid "{2559a1f1-21d7-11d4-bdaf-00c04f60b9f0}" is "Help and
* Support".
* @param guid the GUID
* @return the matching name
*/
std::wstring trans_guid_to_wstring(std::wstring guid);

/*! Converts a GUID and a key to a name.
* For instance the guid "{4D545058-4FCE-4578-95C8-8698A9BC0F49}" and the key
* "D801" are "MTP Vendor-extended object properties".
* @param guid the GUID
* @param key the key
* @return the matching name
*/
std::wstring to_FriendlyName(std::wstring guid, unsigned int key);
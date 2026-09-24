/*! \file
 *  \brief WAC's own offline registry reader: the part of Microsoft's Offline
 *         Registry API (offreg) that WAC uses, reimplemented and linked into
 *         WAC.exe.
 *
 *  WHY. WAC loaded offreg.dll at run time, a file outside the executable —
 *  one that could be missing, replaced, or taken from the examined machine
 *  (Windows 11 has one in System32) — for EVERY registry artefact it
 *  collects. The hive format (regf)
 *  is read here directly, from the hive files WAC has already extracted.
 *
 *  SAME CONTRACT. The functions keep offreg's names and signatures, so that no
 *  caller changes, and its semantics, checked against Microsoft's DLL by
 *  offline_registry_test.cpp on whole hives (every key, every value):
 *  - lengths of names are in characters, WITHOUT the terminating zero on
 *    output, the buffer size WITH it on input;
 *  - a buffer too small gives ERROR_MORE_DATA and the size required;
 *  - a null data buffer returns the data size;
 *  - a missing key or value gives ERROR_FILE_NOT_FOUND, the end of an
 *    enumeration ERROR_NO_MORE_ITEMS, a damaged structure ERROR_BADDB.
 *  Read-only: the hive is mapped, never written.
 *
 *  Every offset read in the hive is checked against the file's real size:
 *  a hive comes from the examined machine and is hostile input.
 */
#pragma once
#include <windows.h>

#ifndef _ORHKEY_DEFINED
#define _ORHKEY_DEFINED
DECLARE_HANDLE(ORHKEY);   //!< an open hive or key
typedef ORHKEY* PORHKEY;  //!< receives an ORHKEY
#endif

/*! Opens a hive file read-only.
 *  @param lpHivePath path of the hive file
 *  @param phkResult receives the handle of its root key
 *  @return ERROR_SUCCESS, a file error, or ERROR_BADDB if it is not a hive */
DWORD OROpenHive(PCWSTR lpHivePath, PORHKEY phkResult);

/*! Opens a hive held in memory, with the same checks as OROpenHive. The
 *  bytes are not copied: they must outlive the hive. Used by the robustness
 *  test (parsers_test.cpp), which places a hive against a guard page — a
 *  mapped file cannot be, its last page being padded with zeros.
 *  @param data first byte of the hive
 *  @param size its size
 *  @param phkResult receives the handle of its root key, closed by ORCloseHive
 *  @return ERROR_SUCCESS, or ERROR_BADDB if it is not a usable hive */
DWORD openHiveBuffer(const BYTE* data, size_t size, PORHKEY phkResult);

/*! Closes a hive opened by OROpenHive. Keys opened in it must be closed first.
 *  @param Handle the handle OROpenHive returned
 *  @return ERROR_SUCCESS or ERROR_INVALID_HANDLE */
DWORD ORCloseHive(ORHKEY Handle);

/*! Opens a subkey.
 *  @param Handle an open key
 *  @param lpSubKey path relative to it, components separated by '\', case
 *         insensitive; null or empty for the key itself
 *  @param phkResult receives the new handle
 *  @return ERROR_SUCCESS, ERROR_FILE_NOT_FOUND, ERROR_BADDB */
DWORD OROpenKey(ORHKEY Handle, PCWSTR lpSubKey, PORHKEY phkResult);

/*! Closes a key opened by OROpenKey.
 *  @param Handle the key
 *  @return ERROR_SUCCESS or ERROR_INVALID_HANDLE */
DWORD ORCloseKey(ORHKEY Handle);

/*! Returns the subkey of rank `dwIndex`, in the hive's order.
 *  @param Handle an open key
 *  @param dwIndex rank of the subkey
 *  @param lpName receives its name
 *  @param lpcName in: size of lpName in characters; out: length of the name
 *  @param lpClass receives its class (may be null)
 *  @param lpcClass in/out as lpcName (may be null)
 *  @param lpftLastWriteTime receives its last write time (may be null)
 *  @return ERROR_SUCCESS, ERROR_NO_MORE_ITEMS, ERROR_MORE_DATA, ERROR_BADDB */
DWORD OREnumKey(ORHKEY Handle, DWORD dwIndex, PWSTR lpName, PDWORD lpcName,
                PWSTR lpClass, PDWORD lpcClass, PFILETIME lpftLastWriteTime);

/*! Returns the value of rank `dwIndex`.
 *  @param Handle an open key
 *  @param dwIndex rank of the value
 *  @param lpValueName receives its name
 *  @param lpcValueName in: size of lpValueName in characters; out: length
 *  @param lpType receives its type (may be null)
 *  @param lpData receives its data (may be null)
 *  @param lpcbData in: size of lpData in bytes; out: size of the data
 *  @return ERROR_SUCCESS, ERROR_NO_MORE_ITEMS, ERROR_MORE_DATA, ERROR_BADDB */
DWORD OREnumValue(ORHKEY Handle, DWORD dwIndex, PWSTR lpValueName,
                  PDWORD lpcValueName, PDWORD lpType, PBYTE lpData, PDWORD lpcbData);

/*! Reads a value.
 *  @param Handle an open key
 *  @param lpSubKey subkey holding the value (may be null)
 *  @param lpValue name of the value; null or empty for the default value
 *  @param pdwType receives its type (may be null)
 *  @param pvData receives its data (may be null: only the size is returned)
 *  @param pcbData in: size of pvData in bytes; out: size of the data
 *  @return ERROR_SUCCESS, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_BADDB */
DWORD ORGetValue(ORHKEY Handle, PCWSTR lpSubKey, PCWSTR lpValue,
                 PDWORD pdwType, PVOID pvData, PDWORD pcbData);

/*! Describes a key. Every output may be null.
 *  @param Handle an open key
 *  @param lpClass receives its class
 *  @param lpcClass in: size of lpClass in characters; out: length of the class
 *  @param lpcSubKeys number of subkeys
 *  @param lpcMaxSubKeyLen longest subkey name, in characters
 *  @param lpcMaxClassLen longest subkey class, in characters
 *  @param lpcValues number of values
 *  @param lpcMaxValueNameLen longest value name, in characters
 *  @param lpcMaxValueLen largest value data, in bytes
 *  @param lpcbSecurityDescriptor size of its security descriptor
 *  @param lpftLastWriteTime its last write time
 *  @return ERROR_SUCCESS, ERROR_MORE_DATA (class buffer), ERROR_BADDB */
DWORD ORQueryInfoKey(ORHKEY Handle, PWSTR lpClass, PDWORD lpcClass,
                     PDWORD lpcSubKeys, PDWORD lpcMaxSubKeyLen,
                     PDWORD lpcMaxClassLen, PDWORD lpcValues,
                     PDWORD lpcMaxValueNameLen, PDWORD lpcMaxValueLen,
                     PDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime);

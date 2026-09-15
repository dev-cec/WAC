/*  offreg.h — shim MinGW pour l'Offline Registry API (offreg.dll)
 *  Absent des distributions MinGW-w64. Déclare la surface utilisée par WAC.
 *  Cible x64 : convention d'appel unique, WINAPI/__stdcall sans effet.
 *  Réf. : Windows SDK <offreg.h>. Lien : offreg.dll (présent sur Windows).
 */
#pragma once
#ifndef _OFFREG_H_
#define _OFFREG_H_

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ORHKEY_DEFINED
#define _ORHKEY_DEFINED
DECLARE_HANDLE(ORHKEY);
typedef ORHKEY *PORHKEY;
#endif

/* Options de OROpenHive (offreg) — valeurs de l'API officielle. */
#define OFFREG_OPEN_READ_ONLY 0x00000001UL

DWORD WINAPI OROpenHive(PCWSTR lpHivePath, PORHKEY phkResult);
DWORD WINAPI OROpenHiveByHandle(HANDLE Handle, PORHKEY phkResult, DWORD dwFlags);
DWORD WINAPI ORCloseHive(ORHKEY Handle);
DWORD WINAPI ORSaveHive(ORHKEY Handle, PCWSTR lpHivePath,
                        DWORD dwOsMajorVersion, DWORD dwOsMinorVersion);

DWORD WINAPI OROpenKey(ORHKEY Handle, PCWSTR lpSubKey, PORHKEY phkResult);
DWORD WINAPI ORCloseKey(ORHKEY Handle);

DWORD WINAPI OREnumKey(ORHKEY Handle, DWORD dwIndex, PWSTR lpName,
                       PDWORD lpcName, PWSTR lpClass, PDWORD lpcClass,
                       PFILETIME lpftLastWriteTime);

DWORD WINAPI OREnumValue(ORHKEY Handle, DWORD dwIndex, PWSTR lpValueName,
                         PDWORD lpcValueName, PDWORD lpType, PBYTE lpData,
                         PDWORD lpcbData);

DWORD WINAPI ORGetValue(ORHKEY Handle, PCWSTR lpSubKey, PCWSTR lpValue,
                        PDWORD pdwType, PVOID pvData, PDWORD pcbData);

DWORD WINAPI ORQueryInfoKey(ORHKEY Handle, PWSTR lpClass, PDWORD lpcClass,
                            PDWORD lpcSubKeys, PDWORD lpcMaxSubKeyLen,
                            PDWORD lpcMaxClassLen, PDWORD lpcValues,
                            PDWORD lpcMaxValueNameLen, PDWORD lpcMaxValueLen,
                            PDWORD lpcbSecurityDescriptor,
                            PFILETIME lpftLastWriteTime);

#ifdef __cplusplus
}
#endif
#endif /* _OFFREG_H_ */

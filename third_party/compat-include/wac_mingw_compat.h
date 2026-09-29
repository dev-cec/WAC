/* wac_mingw_compat.h — force-included by build-windows.sh (-include), on Linux
 * and in MSYS2 alike. Fills the gaps between the Windows SDK, which WAC's code
 * was first written against, and the MinGW-w64 headers, without changing any
 * of WAC's logic. Only what the sources actually use: a definition nothing
 * uses any more is removed.
 */
#pragma once
#include <cstdlib>
#include <filesystem>   /* std::filesystem::path for wide-path fstreams */

/* NDIS constant missing from MinGW's winerror.h (used as a log tag). */
#ifndef ERROR_NDIS_BAD_VERSION
#define ERROR_NDIS_BAD_VERSION 0x80340004L
#endif

/* Service type flags missing from MinGW's winnt.h, named by trans_id.cpp. */
#ifndef SERVICE_USER_SERVICE
#define SERVICE_USER_SERVICE          0x00000040
#endif
#ifndef SERVICE_USERSERVICE_INSTANCE
#define SERVICE_USERSERVICE_INSTANCE  0x00000080
#endif
#ifndef SERVICE_PKG_SERVICE
#define SERVICE_PKG_SERVICE           0x00000200
#endif

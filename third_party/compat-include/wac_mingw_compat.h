/* wac_mingw_compat.h — force-include pour build MinGW (cross-compil Linux).
 * Comble les écarts MSVC→MinGW sans modifier la logique de WAC.
 * Injecté via -include ; ne rien mettre ici de spécifique à MSVC.
 */
#pragma once
#include <math.h>       /* pow() utilisé non qualifié dans oleparser.hpp   */
#include <cmath>
#include <cstdlib>
#include <filesystem>   /* std::filesystem::path pour les fstream à chemin large */

/* Constante NDIS absente des winerror.h MinGW (utilisée comme tag de log). */
#ifndef ERROR_NDIS_BAD_VERSION
#define ERROR_NDIS_BAD_VERSION 0x80340004L
#endif

/* Constantes de type de service absentes des winsvc.h/winnt.h MinGW (winnt.h). */
#ifndef SERVICE_USER_SERVICE
#define SERVICE_USER_SERVICE          0x00000040
#endif
#ifndef SERVICE_USERSERVICE_INSTANCE
#define SERVICE_USERSERVICE_INSTANCE  0x00000080
#endif
#ifndef SERVICE_USER_SHARE_PROCESS
#define SERVICE_USER_SHARE_PROCESS    0x00000060  /* USER_SERVICE | WIN32_SHARE_PROCESS */
#endif
#ifndef SERVICE_USER_OWN_PROCESS
#define SERVICE_USER_OWN_PROCESS      0x00000050  /* USER_SERVICE | WIN32_OWN_PROCESS   */
#endif
#ifndef SERVICE_PKG_SERVICE
#define SERVICE_PKG_SERVICE           0x00000200
#endif

/* Valeur d'énumération TASK_TRIGGER_TYPE2 absente de mingw taskschd.h. */
#ifndef TASK_TRIGGER_CUSTOM_TRIGGER_01
#define TASK_TRIGGER_CUSTOM_TRIGGER_01 12
#endif

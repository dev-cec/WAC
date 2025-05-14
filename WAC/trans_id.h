#pragma once
#include <string>
#include <regex>
#include <taskschd.h>
#include <lmaccess.h>

/*! Conversion d'un service type au format enum en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au nom du type
*/
std::wstring serviceType_to_wstring(int type);

/*! Conversion d'un service start type au format enum en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au nom du type
*/
std::wstring serviceStart_to_wstring(int type);


/*! Conversion d'un service state type au format enum en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au nom du type
*/
std::wstring serviceState_to_wstring(int type);

/*! Conversion d'un logon type au format enum en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au nom du type
*/
std::wstring logon_type(ULONG type);

/*! Conversion d'une architecture OS au format enum en nom wstring
* @param archi est l'archi au format num�rique
* @return wstring correspondant au nom de l'architecture
*/
std::wstring os_architecture(DWORD archi);

/*! Conversion d'un TASK_TRIGGER_TYPE2 en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au type
*/
std::wstring task_trigger_type(TASK_TRIGGER_TYPE2 type);

/*! Conversion d'un TASK_ACTION_TYPE en nom wstring
* @param type est le type au format num�rique
* @return wstring correspondant au type
*/
std::wstring task_action_type(TASK_ACTION_TYPE type);

/*! Conversion d'un TASK_STATE en nom wstring
* @param state est l'�tat de la t�che au format num�rique
* @return wstring correspondant � l'�tat
*/
std::wstring task_state(TASK_STATE state);

/*! Conversion d'un APPID en nom d'application
* par exemple l'appId "0006f647f9488d7a" correspond � l'application "AIM 7.5.11.9 (custom AppID + JL support)"
* @param appid id de l'application
* @return wstring correspondant au nom de l�application associ�e � l'APPID
*/
std::wstring from_appId(std::wstring appId);

/*! Conversion d'un code de sous-r�seau en nom de type sous-r�seau
* Par exemple le sous-reseau 1 correspond � "Domain/WorkGroup Description"
* @param type le code du sous-r�seau
* @return wstring correspondant au nom du type de sous-r�seau
*/
std::wstring networkSubType(unsigned char type);

/*! Conversion d'un code de provider de r�seau en nom de provider de r�seau
* Par exemple le code 0x001A0000 correspond au provider de r�seau "WNNC_NET_AVID"
* @param type le code du provider de r�seau
* @return wstring correspondant au nom du provider de r�seau
*/
std::wstring networkProvider_to_wstring(unsigned int n);

/*! Conversion d'un type de Drive en nom de type de Drive
* Par exemple le code 2 correspond au provider de r�seau "DRIVE_REMOVABLE"
* @param type le code du type de Drive
* @return wstring correspondant au nom du type de Drive
*/
std::wstring driveType_to_wstring(unsigned int d);

/*! Conversion d'un code en nom d'option
* Par exemple le code 3 correspond au nom "SHOWMAXIMIZED"
* @param type le code 
* @return wstring correspondant au nom 
*/
std::wstring showCommandOption(unsigned int option);

/*! Conversion d'un code en nom d'index
* Par exemple le code 0 correspond au nom "INTERNET_EXPLORER"
* @param type le code
* @return wstring correspondant au nom
*/
std::wstring sort_index(unsigned char i);

/*! Conversion d'un code de cat�gorie d'item shell en nom
* Par exemple le code 1 correspond au nom "CONTROL_PANEL_CATEGORY"
* @param type le code
* @return wstring correspondant au nom
*/
std::wstring shell_item_class(unsigned char i);

/*! Conversion d'un guid en nom
* Par exemple le guid "{2559a1f1-21d7-11d4-bdaf-00c04f60b9f0}") correpsond � "Help and Support";
* @param guid le guid
* @return wstring correspondant au nom
*/
std::wstring trans_guid_to_wstring(std::wstring guid);

/*! Conversion d'un guid et d'une cl� en nom
* Par exemple le guid  "{4D545058-4FCE-4578-95C8-8698A9BC0F49}" et la cl� "D801" correpsondent � "MTP Vendor-extended object properties";
* @param guid le guid
* @param key la cl�
* @return wstring correspondant au nom
*/
std::wstring to_FriendlyName(std::wstring guid, unsigned int key);
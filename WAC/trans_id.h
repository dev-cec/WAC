#pragma once

/*  trans_id.h — TABLES DE CORRESPONDANCE : identifiant brut -> libellé lisible.
 *
 *  Les artefacts Windows désignent les choses par des codes : un GUID de classe
 *  COM, un AppID de barre des tâches, un code de type de service, un index de
 *  provider réseau. Seul le libellé rend ces codes exploitables dans un rapport.
 *
 *  D'OÙ VIENNENT LES LIBELLÉS. Les tables de GUID et d'AppID sont alignées sur
 *  les données de référence de libyal (libfwsi) plutôt que relevées à la main :
 *  une table saisie au jugé produit des libellés plausibles mais faux, et rien
 *  dans la sortie ne permettrait de s'en apercevoir.
 *
 *  PERFORMANCE. Les deux grandes tables (16 639 GUID, 727 AppID) sont indexées
 *  dans une `unordered_map` construite au premier appel, pas parcourues. La
 *  version d'origine enchaînait des dizaines de milliers de `if` pour chaque
 *  identifiant à traduire, ce qui dominait le temps de collecte.
 *
 *  ATTENTION AUX CHAMPS DE BITS. Plusieurs codes Windows ne sont pas des
 *  énumérations mais des drapeaux combinables, et certaines constantes sont
 *  elles-mêmes des combinaisons (SERVICE_USER_SHARE_PROCESS = 0x60 = 0x40|0x20).
 *  Les comparer par égalité, ou par `&` sans distinguer les bits élémentaires,
 *  produit des libellés contradictoires.
 */

#include <string>
#include <regex>
#include <windows.h>



/*! Conversion d'un service type au format enum en nom wstring
* @param type est le type au format numérique
* @return wstring correspondant au nom du type
*/
std::wstring serviceType_to_wstring(int type);

/*! Conversion d'un service start type au format enum en nom wstring
* @param type est le type au format numérique
* @return wstring correspondant au nom du type
*/
std::wstring serviceStart_to_wstring(int type);


/*! Conversion d'un service state type au format enum en nom wstring
* @param type est le type au format numérique
* @return wstring correspondant au nom du type
*/
std::wstring serviceState_to_wstring(int type);

/*! Conversion d'un logon type au format enum en nom wstring
* @param type est le type au format numérique
* @return wstring correspondant au nom du type
*/
std::wstring logon_type(ULONG type);

/*! Conversion d'une architecture OS au format enum en nom wstring
* @param archi est l'archi au format numérique
* @return wstring correspondant au nom de l'architecture
*/
std::wstring os_architecture(DWORD archi);

/*! Conversion d'un APPID en nom d'application
* par exemple l'appId "0006f647f9488d7a" correspond à l'application "AIM 7.5.11.9 (custom AppID + JL support)"
* @param appId id de l'application
* @return wstring correspondant au nom de l’application associée à l'APPID
*/
std::wstring from_appId(std::wstring appId);

/*! Conversion d'un code de sous-réseau en nom de type sous-réseau
* Par exemple le sous-reseau 1 correspond à "Domain/WorkGroup Description"
* @param type le code du sous-réseau
* @return wstring correspondant au nom du type de sous-réseau
*/
std::wstring networkSubType(unsigned char type);

/*! Conversion d'un code de provider de réseau en nom de provider de réseau
* Par exemple le code 0x001A0000 correspond au provider de réseau "WNNC_NET_AVID"
* @param n le code du provider de réseau
* @return wstring correspondant au nom du provider de réseau
*/
std::wstring networkProvider_to_wstring(unsigned int n);

/*! Conversion d'un type de Drive en nom de type de Drive
* Par exemple le code 2 correspond au provider de réseau "DRIVE_REMOVABLE"
* @param d le code du type de Drive
* @return wstring correspondant au nom du type de Drive
*/
std::wstring driveType_to_wstring(unsigned int d);

/*! Conversion d'un code en nom d'option
* Par exemple le code 3 correspond au nom "SHOWMAXIMIZED"
* @param option le code 
* @return wstring correspondant au nom 
*/
std::wstring showCommandOption(unsigned int option);

/*! Conversion d'un code en nom d'index
* Par exemple le code 0 correspond au nom "INTERNET_EXPLORER"
* @param i le code
* @return wstring correspondant au nom
*/
std::wstring sort_index(unsigned char i);

/*! Conversion d'un code de catégorie d'item shell en nom
* Par exemple le code 1 correspond au nom "CONTROL_PANEL_CATEGORY"
* @param i le code
* @return wstring correspondant au nom
*/
std::wstring shell_item_class(unsigned char i);

/*! Nature d'un shell item « users property view », d'après sa signature.
*
* POURQUOI C'EST NÉCESSAIRE. La signature ne sert pas seulement à choisir un
* décodeur : chez libyal (libfwsi) elle IDENTIFIE le type d'item. Deux des
* signatures que WAC traitait sous le nom générique « UserPropertyView » sont en
* réalité des périphériques média — un volume MTP et une entrée de fichier
* MTP — c'est-à-dire la trace qu'un téléphone ou un appareil photo a été
* connecté et parcouru. Le nom générique masquait complètement ce fait.
*
* @param signature la signature lue à l'offset 6 de l'item
* @return le libellé, ou "" si la signature n'est pas répertoriée
*/
std::wstring shell_item_signature(unsigned int signature);

/*! Conversion d'un guid en nom
* Par exemple le guid "{2559a1f1-21d7-11d4-bdaf-00c04f60b9f0}") correpsond à "Help and Support";
* @param guid le guid
* @return wstring correspondant au nom
*/
std::wstring trans_guid_to_wstring(std::wstring guid);

/*! Conversion d'un guid et d'une clé en nom
* Par exemple le guid  "{4D545058-4FCE-4578-95C8-8698A9BC0F49}" et la clé "D801" correpsondent à "MTP Vendor-extended object properties";
* @param guid le guid
* @param key la clé
* @return wstring correspondant au nom
*/
std::wstring to_FriendlyName(std::wstring guid, unsigned int key);
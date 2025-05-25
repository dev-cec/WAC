#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <offreg.h>
#include <vector>
#include <time.h>
#include <comutil.h>

//constantes globales 
#define MAX_KEY_NAME 255 //!< plus longue key name en base de registre
#define MAX_VALUE_NAME 16383 //!< plus long nom de valeur en base de registre
#define MAX_DATA 1024000 //!< taille maximale des données pour une valeur en base de registre

//Type de log
#define LOG_TYPE_ARTEFACT_TYPE 0//!< log of artefact type
#define LOG_TYPE_ARTEFACT 1//!< log of new artefact
#define LOG_TYPE_INFO 2//!< log of type info to describe artefact
#define LOG_TYPE_ERROR 3//!< log of type error
#define LOG_TYPE_DEBUG 4 //!< name of function called for debug purpose

//! Structure de données contenant la configuration de l'application
struct AppliConf {
	bool _debug = false;//!< True if debug is active
	bool _dump = false;//!< True if dump is active
	bool _events = false;//!< True is events must be extracted
	std::string name = ""; //!< name of the program, obtained from command line
	std::string _outputDir = "output"; //!< directory to store output JSON
	std::wstring mountpoint = L""; //!< mount point path to access the snapshot made during execution
	ORHKEY CurrentControlSet = { 0 }; //!< Reg Key to access Current Control Set Hive
	ORHKEY System = { 0 }; //!< Reg Key to access to System Hive
	ORHKEY Software = { 0 };//!< Reg Key to access CurrentControlSet/Software hive
	std::vector<std::tuple<std::wstring, std::wstring>> profiles;//!< vector to store SID and profiles of users present on the machine
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);//!< Handle de la console
	std::wofstream log;//!< handle sur le fichier de log de sortie pour mode debug
	int loglevel = 0; //!< niveau de journalisation (0 par defaut) definit par la ligne de commande
};

extern AppliConf conf;// variable globale pour la conf de l'application

///////////////////////////////////////////////////////
// Format de données
//////////////////////////////////////////////////////

/*! structure de données  permettant de stocker les dates au format FAT DOS time
*
* Note sur les dates et heures:
* 
* DOS stocke les dates et heures de modification de fichiers comme une paire de nombre de 16-bit:
* 
* 	7 bits pour l'année, 4 bits pour le mois, 5 bits pour le jour du mois
* 	5 bits pour l'heure, 6 bits pour les minutes, 5 bits pour les secondes (x2)
* 
* Tous les systèmes de fichiers utilisent des dates relatives à une époque (heure zéro). 
* Pour DOS, l'époque est minuit, le réveillon du Nouvel An, le 1er janvier 1980. 
* Un champ de sept bits pour les années signifie que le calendrier DOS ne fonctionne que jusqu'en 2107. 
*/
struct FatDateTime {

	unsigned int i =0; //!< entier d'origine utilisé par le constructeur, correspond à la concaténation des 2 parties de 16 bits chacune
	unsigned short int date =0; //!< première partie de 16 bits consacrée à la date : 7 bits pour l'année, 4 bits pour le mois, 5 bits pour le jour du mois
	unsigned short int time =0 ; //!< seconde partie de 16 bits consacrée à l'heure : 5 bits pour l'heure, 6 bits pour les minutes, 5 bits pour les secondes (x2)

	//! constructeur à partir d'un timestamp, permet de parser la date
	FatDateTime(unsigned int _i); 
	//! conversion FAT DOS TIME vers SYSTEM TIME
	SYSTEMTIME to_systemtime(); 
	//! Conversion FAT DOS TIME vers FILETIME
	FILETIME to_filetime(); 
};

///////////////////////////////////////////////////////
//affichage
///////////////////////////////////////////////////////

//! affichage du mot OK en vert dans la console
void printSuccess();

/*! affichage du message d'erreur correspondant au résultat HRESULT en ROUGE dans la console
* @param hresult résultat retourné par un commande
* @return void
*/
void printError( HRESULT  hresult);

/*! affichage du message errortext en ROUGE dans la console
* @param errorText texte à afficher
* @return void
*/
void printError( std::wstring  errorText);

/*! extraction du message d'erreur d'un HRESULT retourné par une commande
* @param hresult résultat retourné par un commande
* @return wstring correspondant au texte associé au code erreur HRESULT
*/
std::wstring getErrorMessage(HRESULT hresult);

/*! enregistrement d'un message dans le ficier de log de sortie
* log(0, L""); => Simple message
* log(0, L"ℹ️"); => Nouveau type d'artefact
* log(1, L"➕"); => Nouvel artefact
* log(2, L"🔥"); => Error
* log(2, L"❇️"); => Identification d'un artefact
* log(3, L"🔈"); => Nom de la fonction apperlée
* @param loglevel est le niveau de log
* @param message message a enregistré dans le fichier donnant du contexte
* @param type est le type de log pour l'emoji. par defaut pas d'emoji
*/
void log(int loglevel, std::wstring message);

/*! enregistrement d'un message dans le ficier de log de  complété par un code erreur
* @param loglevel est le niveau de log
* @param message message a enregistré dans le fichier donnant du contexte
* @param type est le type de log pour l'emoji. par defaut pas d'emoji* @param type est le type de log pour l'emoji. par defaut pas d'emoji
* @param result code erreur a tranformé en message d'ereur
*/
void log(int loglevel, std::wstring message, HRESULT result);


/*! extraction du message d'erreur d'un HRESULT retourné par une commande
* @param hresult résultat retourné par un commande
* @return wstring correspondant au texte associé au code erreur HRESULT
*/
std::wstring getErrorMessage(HRESULT hresult);

/*! converti un texte ANSI vers UTF8
* @param in chaîne de caractères encodé en ANSI
* @return chaîne de caractères encodée en UTF8
*/
std::string ansi_to_utf8(std::string in);

/*! converti un texte ANSI vers UTF8
* @param in chaîne de caractères encodée en ANSI
* @return chaîne de caractères encodé en UTF8
*/
std::wstring ansi_to_utf8(std::wstring in);

/*! affiche en hexadecimal le contenu du buffer dans la console
* @param buffer pointeur sur un buffer contenu les données à afficher
* @param start indique la position du premier octet à afficher dans le buffer
* @param end indique la position du dernier octet à afficher dans le buffer. 
* @return void
*/
void dump(LPBYTE buffer, int start, int end);

/*! converti en wstring hexadecimal le contenu du buffer dans la console
* @param buffer pointeur sur un buffer contenu les données à convertir
* @param start indique la position du premier octet à traiter dans le buffer
* @param end indique la position du dernier octet à afficher dans le buffer
* @return void
*/
std::wstring dump_wstring(LPBYTE buffer, int start, int end);

///////////////////////////////////////////////////////
//chaînes
///////////////////////////////////////////////////////

/*! Dans une chaîne de caractères, remplace toutes les occurrences d'une chaîne par une autre
* @param src chaîne de départ contenant la chaîne à rechercher
* @param search représente la chaîne à rechercher dans <src>
* @param replacement chaîne à insérer en lieu et place de <search>
* @return wstring resultant du remplacement
*/
std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement);

/*! Opération ROT13 sur une chaîne de caractères
* @param source chaîne de caractère à traiter
* @return wstring resultant de l'opération
*/
std::wstring ROT13(std::wstring source);

/*! décodage d'URL
* @param encoded représente l’URL à décoder
* @return string resultant de l'opération
*/
std::string decodeURIComponent(std::string encoded);

/*! conversion d'un nombre en caractères hexadecimal
* @param i entier à transformer
* @return wstring resultant de l'opération
*/
std::wstring to_hex(long long i);

/*! insertion de n tabulations dans une chaîne de caractères. utiliser pour le formatage du json de sortie
* @param i nombre de tabulations à insérer
* @return wstring contenant le nombre de tabulations désiré
*/
std::wstring tab(int i);

///////////////////////////////////////////////////////
//conversion
///////////////////////////////////////////////////////

/*! Conversion d'un sid en nom d'utilisateur au format wstring
* @param _sid est le sid de l'utilisateur
*/
std::wstring getNameFromSid(std::wstring _sid);


/*! Conversion un booléen un wstring "true" ou "false".
* @param b booléen à convertir
* @return wstring "true" ou "false"
*/
std::wstring bool_to_wstring(bool b);

/*! Conversion un time_t en FILETIME .
* @param t time_t à convertir
* @return FILETIME issue de la conversion
*/
FILETIME timet_to_fileTime(time_t t);

/*! Conversion une chaîne de caractère représentant une date en FILETIME.
* @param input chaîne à convertir
* @return FILETIME issue de la conversion
*/
FILETIME wstring_to_filetime(std::wstring input);

/*! Conversion un FILETIME en wstring.
* @param filetime FILETIME à convertir en wstring
* @param convertUTC si true alors date sera convertie en UTC
* @return chaîne de caractères issue de la conversion
*/
std::wstring time_to_wstring(const FILETIME filetime, bool convertUtc = false);

/*! Conversion un SYSTEMTIME en wstring.
* @param filetime SYSTEMTIME à convertir en wstring
* @return chaîne de caractères issue de la conversion
*/
std::wstring time_to_wstring(const SYSTEMTIME systemtime);

/*! Conversion une chaîne de caractères wstring en chaine binaire
* @param bstr la chaîne de caractère binaire
* @return wstring issue de la conversion
*/
BSTR wstring_to_bstr(std::wstring ws);

/*! Conversion une chaîne de caractères binaire en wstring
* @param bstr la chaîne de caractère binaire
* @return wstring issue de la conversion
*/
std::wstring bstr_to_wstring(BSTR bstr);

/*! Conversion une chaîne de caractères string en wstring
* @param str pointeur sur la chaîne de caractère string
* @return wstring issue de la conversion
*/
std::wstring string_to_wstring(const std::string& str);

/*! Conversion une chaîne de caractères wstring en string
* @param wstr pointeur sur la chaîne de caractère wstring
* @return string issue de la conversion
*/
std::string wstring_to_string(const std::wstring& wstr);

/*! Conversion d'un tableau de chaîne de caractère wstring au format json
* @param vec vecteur contenant les wstring
* @return wstring issue de la conversion
*/
std::wstring multiSz_to_json(std::vector<std::wstring> vec, int niveau);

/*! Conversion un tableau de FILETIME au format json
* @param vec vecteur contenant les FILETIME. une date par ligne dans le fichier json de sortie
* @param niveau hiérarchie dans l'arborescence des objets shell, traduit en nombre de tabulations à insérer pour chaque ligne du fichier json
* @return wstring issue de la conversion
*/
std::wstring multiFiletime_to_json(std::vector<FILETIME> vec, int niveau);

/*! Conversion d'une chaîne de multiple wstring concaténés en vecteur de wstring. chaque chaîne doit être séparée de la précédente par \0
* @param data pointeur vers le tableau contenant les chaînes de caractères
* @param size taille de la chaîne de caractères contenue dans <data>
* @return vecteur issue de la conversion
*/
std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size);

/*! Conversion un GUID en wstring. La chaîne de sortie sera au format "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
* @param guid GUID à convertir
* @return wstring issue de la conversion
*/
std::wstring guid_to_wstring(GUID guid);

///////////////////////////////////////////////////////
//Registry
///////////////////////////////////////////////////////


/*! Lecture d'un SZ_VALUE en base de registre et le converti en wstring
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param ws pointeur sur un wstring contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::wstring* ws);

/*! Lecture d'un FILMETIME en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param filetime pointeur sur un FILETIME contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, FILETIME* filetime);

/*! Lecture d'une valeur binaire en base de registre
* nécessite d'utiliser delete[] pBytes pour libérer la mémoire
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param pBytes pointeur sur un tableau de BYTE contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur registre
*/
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, LPBYTE* pBytes, DWORD* dwSize);

/*! Lecture d'un booléen en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param pbool pointeur sur un booléen contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegboolValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, bool* pbool);

/*! Lecture d'un MULTISZ (multiple chaînes de caractères concaténées) en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param out pointeur sur un tableau de wstring contenant les valeurs lues en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::vector<std::wstring>* out);

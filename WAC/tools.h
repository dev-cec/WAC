#pragma once
#include <string>
#include <offreg.h>
#include <vector>
#include <time.h>


//constantes globales 
#define MAX_KEY_NAME 255 //!< plus longue key name en base de registre
#define MAX_VALUE_NAME 16383 //!< plus long nom de valeur en base de registre
#define MAX_DATA 1024000 //!< taille maximale des donn�es pour une valeur en base de registre

///////////////////////////////////////////////////////
// Format de donn�es
//////////////////////////////////////////////////////

//! structure de donn�es  permettant de stocker les dates au format FAT DOS time
/*!
* Note sur les dates et heures:
* 
* DOS stocke les dates et heures de modification de fichiers comme une paire de nombre de 16-bit:
* 
* 	7 bits pour l'ann�e, 4 bits pour le mois, 5 bits pour le jour du mois
* 	5 bits pour l'heure, 6 bits pour les minutes, 5 bits pour les secondes (x2)
* 
* Tous les syst�mes de fichiers utilisent des dates relatives � une �poque (heure z�ro). 
* Pour DOS, l'�poque est minuit, le r�veillon du Nouvel An, le 1er janvier 1980. 
* Un champ de sept bits pour les ann�es signifie que le calendrier DOS ne fonctionne que jusqu'en 2107. 
*/
struct FatDateTime {

	unsigned int i =0; //!< entier d'origine utilis� par le constructeur, correspond � la concat�nation des 2 parties de 16 bits chacune
	unsigned short int date =0; //!< premi�re partie de 16 bits consacr�e � la date : 7 bits pour l'ann�e, 4 bits pour le mois, 5 bits pour le jour du mois
	unsigned short int time =0 ; //!< seconde partie de 16 bits consacr�e � l'heure : 5 bits pour l'heure, 6 bits pour les minutes, 5 bits pour les secondes (x2)

	//! constructeur � partir d'un timestamp, permet de parser la date
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

/*! affichage du message d'erreur correspondant au r�sultat HRESULT en ROUGE dans la console
* @param hresult r�sultat retourn� par un commande
* @return void
*/
void printError(HRESULT  hresult);

/*! affichage du message errortext en ROUGE dans la console
* @param errorText texte � afficher
* @return void
*/
void printError(std::wstring  errorText);

/*! extraction du message d'erreur d'un HRESULT retourn� par une commande
* @param hresult r�sultat retourn� par un commande
* @return wstring correspondant au texte associ� au code erreur HRESULT
*/
std::wstring getErrorWstring(HRESULT hresult);

/*! converti un texte ANSI vers UTF8
* @param in cha�ne de caract�res encod� en ANSI
* @return cha�ne de caract�res encod�e en UTF8
*/
std::string ansi_to_utf8(std::string in);

/*! converti un texte ANSI vers UTF8
* @param in cha�ne de caract�res encod�e en ANSI
* @return cha�ne de caract�res encod� en UTF8
*/
std::wstring ansi_to_utf8(std::wstring in);

/*! concatenation de 2 BSTR
* @param a 1�re cha�ne de caract�res
* @param a 2nd cha�ne de caract�res
* @return cha�ne de caract�res concat�n�e
*/
BSTR bstr_concat(BSTR a, BSTR b);

/*! affiche en hexadecimal le contenu du buffer dans la console
* @param buffer pointeur sur un buffer contenu les donn�es � afficher
* @param start indique la position du premier octet � afficher dans le buffer
* @param end indique la position du dernier octet � afficher dans le buffer. 
* @return void
*/
void dump(LPBYTE buffer, int start, int end);

/*! converti en wstring hexadecimal le contenu du buffer dans la console
* @param buffer pointeur sur un buffer contenu les donn�es � convertir
* @param start indique la position du premier octet � traiter dans le buffer
* @param end indique la position du dernier octet � afficher dans le buffer
* @return void
*/
std::wstring dump_wstring(LPBYTE buffer, int start, int end);

///////////////////////////////////////////////////////
//cha�nes
///////////////////////////////////////////////////////

/*! Dans une cha�ne de caract�res, remplace toutes les occurrences d'une cha�ne par une autre
* @param src cha�ne de d�part contenant la cha�ne � rechercher
* @param search repr�sente la cha�ne � rechercher dans <src>
* @param replacement cha�ne � ins�rer en lieu et place de <search>
* @return wstring resultant du remplacement
*/
std::wstring replaceAll(std::wstring src, std::wstring search, std::wstring replacement);

/*! Op�ration ROT13 sur une cha�ne de caract�res
* @param source cha�ne de caract�re � traiter
* @return wstring resultant de l'op�ration
*/
std::wstring ROT13(std::wstring source);

/*! ensure std::wstring is printable car beaucoup de caract�re ne le sont pas et peuvent faire planter certaines op�rations sur les cha�nes ou casser le format JSON de sortie
* Les caract�res non imprimables sont remplac�s par ?
* @param source cha�ne de caract�res � traiter
* @return wstring resultant de l'op�ration
*/
void static checkWstring(wchar_t* s);

/*! d�codage d'URL
* @param encoded repr�sente l�URL � d�coder
* @return string resultant de l'op�ration
*/
std::string decodeURIComponent(std::string encoded);

/*! conversion d'un nombre en caract�res hexadecimal
* @param i entier � transformer
* @return wstring resultant de l'op�ration
*/
std::wstring to_hex(long long i);

/*! insertion de n tabulations dans une cha�ne de caract�res. utiliser pour le formatage du json de sortie
* @param i nombre de tabulations � ins�rer
* @return wstring contenant le nombre de tabulations d�sir�
*/
std::wstring tab(int i);

///////////////////////////////////////////////////////
//conversion
///////////////////////////////////////////////////////

/*! Conversion d'un sid en nom d'utilisateur au format wstring
* @param _sid est le sid de l'utilisateur
*/
std::wstring getNameFromSid(std::wstring _sid);


/*! Conversion un bool�en un wstring "true" ou "false".
* @param b bool�en � convertir
* @return wstring "true" ou "false"
*/
std::wstring bool_to_wstring(bool b);

/*! Conversion un time_t en FILETIME .
* @param t time_t � convertir
* @return FILETIME issue de la conversion
*/
FILETIME timet_to_fileTime(time_t t);

/*! Conversion une cha�ne de caract�re repr�sentant une date en FILETIME.
* @param input cha�ne � convertir
* @return FILETIME issue de la conversion
*/
FILETIME wstring_to_filetime(std::wstring input);

/*! Conversion un tableau de BYTES ne FILETIME.
* @param bytes pointeur vers le tableau contenant les BYTES � convertir. le pointeur doit repr�senter le premier octet utile � la conversion
* @return FILETIME issue de la conversion
*/
FILETIME bytes_to_filetime(LPBYTE bytes);

/*! Conversion un FILETIME en wstring.
* @param filetime FILETIME � convertir en wstring
* @param convertUTC si true alors date sera convertie en UTC
* @return cha�ne de caract�res issue de la conversion
*/
std::wstring time_to_wstring(const FILETIME filetime, bool convertUtc = false);

/*! Conversion un SYSTEMTIME en wstring.
* @param filetime SYSTEMTIME � convertir en wstring
* @return cha�ne de caract�res issue de la conversion
*/
std::wstring time_to_wstring(const SYSTEMTIME systemtime);

/*! Conversion un tableau de BYTES en int. la conversion consid�re uniquement les 4 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return int issu de la conversion
*/
int bytes_to_int(LPBYTE bytes);

/*! Conversion un tableau de BYTES en unsigned int. la conversion consid�re uniquement les 4 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return unsigned int issu de la conversion
*/
unsigned int bytes_to_unsigned_int(LPBYTE bytes);

/*! Conversion un tableau de BYTES en short int. la conversion consid�re uniquement les 2 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return short int issu de la conversion
*/
short int bytes_to_short(LPBYTE bytes);

/*! Conversion un tableau de BYTES en unsigned short int. la conversion consid�re uniquement les 2 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return unsigned short int issu de la conversion
*/
unsigned short int bytes_to_unsigned_short(LPBYTE bytes);

/*! Conversion un tableau de BYTES en double. la conversion consid�re uniquement les 8 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return double issu de la conversion
*/
double bytes_to_double(LPBYTE bytes);

/*! Conversion un tableau de BYTES en long. la conversion consid�re uniquement les 4 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return long issu de la conversion
*/
long bytes_to_long(LPBYTE bytes);

/*! Conversion un tableau de BYTES en unsigned long. la conversion consid�re uniquement les 4 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return unsigned long issu de la conversion
*/
unsigned long bytes_to_unsigned_long(LPBYTE bytes);

/*! Conversion un tableau de BYTES en unsigned long long. la conversion consid�re uniquement les 8 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return unsigned long long issu de la conversion
*/
unsigned long long bytes_to_unsigned_long_long(LPBYTE bytes);

/*! Conversion un tableau de BYTES en long long. la conversion consid�re uniquement les 8 premiers octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return long long issu de la conversion
*/
long long bytes_to_long_long(LPBYTE bytes);

/*! Conversion un tableau de BYTES en unsigned char. la conversion consid�re uniquement le premier octets du tableau pour la conversion
* @param bytes pointeur de tableau contenant les BYTE � convertir
* @return unsigned char issu de la conversion
*/
unsigned char bytes_to_unsigned_char(LPBYTE bytes);

/*! Conversion une cha�ne de caract�res binaire en wstring
* @param bstr la cha�ne de caract�re binaire
* @return wstring issue de la conversion
*/
std::wstring bstr_to_wstring(BSTR bstr);

/*! Conversion une cha�ne de caract�res string en wstring
* @param str pointeur sur la cha�ne de caract�re string
* @return wstring issue de la conversion
*/
std::wstring string_to_wstring(const std::string& str);

/*! Conversion une cha�ne de caract�res wstring en string
* @param wstr pointeur sur la cha�ne de caract�re wstring
* @return string issue de la conversion
*/
std::string wstring_to_string(const std::wstring& wstr);

/*! Conversion d'un tableau de cha�ne de caract�re wstring au format json
* @param vec vecteur contenant les wstring
* @return wstring issue de la conversion
*/
std::wstring multiSz_to_json(std::vector<std::wstring> vec, int niveau);

/*! Conversion un tableau de FILETIME au format json
* @param vec vecteur contenant les FILETIME. une date par ligne dans le fichier json de sortie
* @param niveau hi�rarchie dans l'arborescence des objets shell, traduit en nombre de tabulations � ins�rer pour chaque ligne du fichier json
* @return wstring issue de la conversion
*/
std::wstring multiFiletime_to_json(std::vector<FILETIME> vec, int niveau);

/*! Conversion d'une cha�ne de multiple wstring concat�n�s en vecteur de wstring. chaque cha�ne doit �tre s�par�e de la pr�c�dente par \0
* @param data pointeur vers le tableau contenant les cha�nes de caract�res
* @param size taille de la cha�ne de caract�res contenue dans <data>
* @return vecteur issue de la conversion
*/
std::vector<std::wstring> multiWstring_to_vector(LPBYTE data, int size);

/*! Conversion un GUID en wstring. La cha�ne de sortie sera au format "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
* @param guid GUID � convertir
* @return wstring issue de la conversion
*/
std::wstring guid_to_wstring(GUID guid);

///////////////////////////////////////////////////////
//Registry
///////////////////////////////////////////////////////


/*! Lecture d'un SZ_VALUE en base de registre et le converti en wstring
* @param key cl� de la base de registre
* @param szsubkey sous-cl� de la base de registre
* @param szvalue contient la nom de la valeur � lire en base de registre
* @param ws pointeur sur un wstring contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succ�s sinon un code erreur.
*/
HRESULT getRegSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::wstring* ws);

/*! Lecture d'un FILMETIME en base de registre
* @param key cl� de la base de registre
* @param szsubkey sous-cl� de la base de registre
* @param szvalue contient la nom de la valeur � lire en base de registre
* @param filetime pointeur sur un FILETIME contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succ�s sinon un code erreur.
*/
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, FILETIME* filetime);

/*! Lecture d'une valeur binaire en base de registre
* @param key cl� de la base de registre
* @param szsubkey sous-cl� de la base de registre
* @param szvalue contient la nom de la valeur � lire en base de registre
* @param pBytes pointeur sur un tableau de BYTE contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succ�s sinon un code erreur registre
*/
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, LPBYTE pBytes);

/*! Lecture d'un bool�en en base de registre
* @param key cl� de la base de registre
* @param szsubkey sous-cl� de la base de registre
* @param szvalue contient la nom de la valeur � lire en base de registre
* @param pbool pointeur sur un bool�en contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succ�s sinon un code erreur.
*/
HRESULT getRegboolValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, bool* pbool);

/*! Lecture d'un MULTISZ (multiple cha�nes de caract�res concat�n�es) en base de registre
* @param key cl� de la base de registre
* @param szsubkey sous-cl� de la base de registre
* @param szvalue contient la nom de la valeur � lire en base de registre
* @param out pointeur sur un tableau de wstring contenant les valeurs lues en base de registre
* @return ERROR_SUCCESS en cas de succ�s sinon un code erreur.
*/
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR szSubKey, PCWSTR szValue, std::vector<std::wstring>* out);

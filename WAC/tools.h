#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <offreg.h>
#include <vector>
#include <filesystem>
#include <time.h>
#include "json.h"

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

/*! Fuseau horaire de la machine EXAMINÉE.
*
* POURQUOI LA RUCHE PLUTÔT QUE L'API. Les artefacts Windows qui stockent une
* heure locale (dates FAT, Amcache, BAM, shimcache, USBSTOR, UserAssist) ne sont
* interprétables qu'avec le fuseau du **suspect**. `GetTimeZoneInformation()`
* rend celui de la machine qui exécute WAC : identique en collecte live, mais
* faux dès qu'on analyse une image montée ailleurs. La source d'autorité est donc
* `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` (cf. doc §7.4).
*
* Une divergence entre les deux est en soi un signal : image analysée sur une
* autre machine, ou fuseau modifié depuis la collecte. Les deux sont donc
* consignés dans `investigation.json`.
*/
struct TimeZoneInfo {
	std::wstring keyName;          //!< TimeZoneKeyName, ex. "Romance Standard Time"
	std::wstring standardName;     //!< nom en heure d'hiver
	std::wstring daylightName;     //!< nom en heure d'été
	long activeBiasMinutes = 0;    //!< minutes à AJOUTER à l'heure locale pour obtenir l'UTC
	long standardBiasMinutes = 0;  //!< décalage hors heure d'été (valeur `Bias` de la ruche)
	bool  daylightInEffect = false;//!< true si l'heure d'été était active au moment de la collecte
	bool  fromHive = false;        //!< true si relevé dans la ruche SYSTEM du suspect
	bool  valid = false;           //!< true si la lecture a abouti
};

//! Structure de données contenant la configuration de l'application
struct AppliConf {
	/*! Mode diagnostic (--debug). Active la trace détaillée du parseur NTFS
	* (résolution de chemin, blocs d'index, data runs) sur STDERR.
	* Séparé de --loglevel : celui-ci journalise la COLLECTE (quels artefacts,
	* quelles valeurs), tandis que --debug éclaire la LECTURE BAS NIVEAU du
	* volume. Confondre les deux noyait la console en usage normal, alors que
	* cette trace est précisément ce qui a permis de localiser le défaut
	* `$INDEX_ALLOCATION` éclaté (doc §14.10). */
	bool _debug = false;
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
	bool md5;//!< if true, calcul hash md5 of files in artefacts
	TimeZoneInfo timeZone; //!< fuseau de la machine examinee (ruche SYSTEM si disponible)
	/*! Lecteur système de la machine examinée, avec les deux-points ("C:").
	*
	* Relevé à l'exécution plutôt que codé en dur : Windows n'est pas toujours
	* installé sur C:. La valeur sert à la fois à l'extraction brute (lettre de
	* volume) et à restituer les chemins d'origine des artefacts. */
	std::wstring systemDrive = L"C:";
};

/*! Relève le lecteur système de la machine et renseigne `conf.systemDrive`.
* À appeler au démarrage, avant toute extraction.
* En cas d'échec, `conf.systemDrive` conserve sa valeur par défaut ("C:").
*/
void loadSystemDrive();

/*! Relève les profils utilisateurs et renseigne `conf.profiles` (SID, chemin).
*
* POURQUOI AVANT L'EXTRACTION, ET POURQUOI EN LIVE. Les ruches par utilisateur
* (`ntuser.dat`, `usrClass.dat`) vivent dans le dossier de profil : il faut donc
* connaître ces chemins AVANT de pouvoir les extraire, c'est-à-dire avant
* qu'aucune ruche ne soit disponible hors ligne. La source est
* `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, lue dans le
* registre vivant : une seule clé, en lecture, sans RPC.
*
* Remplace l'enchaînement `NetUserEnum` + `NetUserGetInfo` par utilisateur, qui
* sollicitait LSASS autant de fois qu'il y a de comptes pour obtenir la même
* liste de chemins.
*
* @return ERROR_SUCCESS si la clé a pu être énumérée, un code d'erreur sinon
*/
HRESULT loadProfileList();

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
	SYSTEMTIME toSystemTime(); 
	//! Conversion FAT DOS TIME vers FILETIME
	FILETIME toFileTime(); 
};

///////////////////////////////////////////////////////
//affichage
///////////////////////////////////////////////////////

//! affichage du mot OK en vert dans la console
void printSuccess();

/*! Affiche une ligne de progression réécrite sur place (retour chariot).
*
* POURQUOI. Sur un système réel, l'extraction d'une grosse ruche ou la lecture du
* journal System durent plusieurs minutes sans rien afficher : l'opérateur ne
* distingue pas une collecte qui avance d'une collecte bloquée, et peut
* l'interrompre — ce qui fait perdre la collecte en cours.
*
* N'écrit QUE si la sortie standard est une console : redirigée vers un fichier,
* la progression n'apporterait rien et polluerait le journal de milliers de
* lignes.
*
* La progression réécrit la LIGNE COURANTE, donc elle efface le libellé d'étape
* (ceux-ci sont écrits sans retour à la ligne, en attente de leur « OK »). C'est
* pourquoi le libellé doit être posé par printStep() : printSuccess() et
* printError() le restaurent alors automatiquement, et aucun collecteur n'a à
* s'en préoccuper.
*
* @param libelle ce qui est en cours (ex. nom de fichier ou de canal)
* @param fait quantité traitée
* @param total quantité totale attendue, ou 0 si inconnue
* @param unite unité à afficher (ex. L"Kio", L"evt")
*/
void printProgress(const std::wstring& libelle, unsigned long long fait,
                   unsigned long long total, const wchar_t* unite);

/*! Termine une ligne de progression et restaure le libellé d'étape.
* Appelée automatiquement par printSuccess() et printError() : à n'appeler
* directement que pour reprendre la main sur l'affichage en cours de traitement.
*/
void printProgressEnd();

/*! Affiche le libellé d'une étape et le mémorise.
*
* À utiliser à la place d'un wprintf direct pour toute étape susceptible
* d'afficher une progression : le libellé est réaffiché après coup, si bien que
* le « OK » ou l'erreur reste rattaché à son étape.
* @param libelle ex. L" - Extracting SHIMCACHE Registry Keys : "
*/
void printStep(const std::wstring& libelle);

/*! Progression d'un artefact, avec limitation de fréquence.
*
* Destinée aux boucles de collecte. La limitation de fréquence est faite par
* printProgress, PAR LE TEMPS : un pas fixe en nombre d'éléments ne peut pas
* convenir à la fois aux 38 shellbags de plusieurs secondes chacun et aux 3032
* entrées amcache instantanées (mesures sur un poste réel).
* @param artefact nom de l'artefact en cours
* @param fait nombre d'éléments traités
* @param total nombre total attendu, ou 0 si inconnu
*/
void printProgressStep(const std::wstring& artefact, unsigned long long fait,
                       unsigned long long total);

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
/*! Restitue une zone mémoire en hexadécimal, octet par octet.
*
* ATTENTION À LA SÉMANTIQUE, corrigée le 2026-09-15. Le troisième paramètre
* s'appelait `end` et la boucle allait jusqu'à `x <= end` — un index de fin
* INCLUS. Or les cinq appelants lui passaient tous une TAILLE : chacun lisait
* donc un octet au-delà de la zone voulue. C'est désormais une longueur, et la
* borne est exclusive.
*
* @param buffer début de la zone
* @param start décalage du premier octet à restituer
* @param longueur nombre d'octets à restituer depuis `start`
* @return les octets en hexadécimal, séparés par des espaces
*/
std::wstring dump_wstring(LPBYTE buffer, int start, int longueur);

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

///////////////////////////////////////////////////////
// Horodatages ISO 8601
///////////////////////////////////////////////////////
/*  POURQUOI CE FORMAT. Les dates étaient émises en « 15/9/2026 5h43m32s » :
 *  ni triable lexicographiquement, ni corrélable entre outils, ambigu sur le
 *  jour et le mois, et surtout MUET sur le fuseau — un horodatage sans fuseau
 *  n'est pas exploitable dans une chronologie.
 *
 *  ISO 8601 règle les quatre problèmes à la fois : « 2026-09-15T05:43:32Z »
 *  pour l'UTC, « 2026-09-15T07:43:32+02:00 » pour l'heure locale. La date porte
 *  alors son propre fuseau : plus besoin d'une convention externe pour la lire.
 *
 *  DEUX FONCTIONS, PAS UN DRAPEAU. Le suffixe (« Z » ou « +HH:MM ») doit dire
 *  la vérité sur la valeur. Seul l'appelant sait ce qu'il détient, et un
 *  paramètre à valeur par défaut produirait des dates faussement étiquetées en
 *  cas d'oubli — une faute grave en expertise. D'où deux fonctions nommées,
 *  sans défaut possible.
 *
 *  Une date nulle rend une chaîne vide, comme time_to_wstring : sans cela on
 *  émettrait « 1601-01-01T00:00:00Z » comme s'il s'agissait d'une vraie date.
 */

/*! Formate un FILETIME **déjà exprimé en UTC** au format ISO 8601, suffixe « Z ».
* @param filetime l'instant, en UTC
* @return "AAAA-MM-JJTHH:MM:SSZ", ou "" si la date est nulle
*/
std::wstring timeToIso8601Utc(const FILETIME& filetime);

/*! Formate un FILETIME **exprimé en heure locale** au format ISO 8601, avec le
* décalage du fuseau de la machine (ex. "+02:00").
* @param filetime l'instant, en heure locale de la machine examinée
* @return "AAAA-MM-JJTHH:MM:SS+HH:MM", ou "" si la date est nulle
*/
std::wstring timeToIso8601Local(const FILETIME& filetime);

/*! Convertit un FILETIME **exprimé en heure locale** vers l'UTC, puis le formate
* au format ISO 8601 avec le suffixe « Z ».
* Utile pour les artefacts qui stockent des dates en heure locale (Amcache, BAM,
* shimcache, USBSTOR, UserAssist) et dont on veut aussi la version UTC.
* @param filetimeLocal l'instant, en heure locale de la machine examinée
* @return "AAAA-MM-JJTHH:MM:SSZ", ou "" si la date est nulle
*/
std::wstring localTimeToIso8601Utc(const FILETIME& filetimeLocal);

/*! Convertit un FILETIME **exprimé en UTC** vers l'heure locale de la machine
* EXAMINÉE, puis le formate au format ISO 8601 avec le décalage du fuseau.
*
* POURQUOI PAS `FileTimeToLocalFileTime` SUIVI DE `timeToIso8601Local`. Cette
* combinaison, employée jusqu'ici, applique le décalage de la machine qui
* EXÉCUTE WAC tout en apposant l'étiquette du fuseau du SUSPECT : identique en
* collecte live, contradictoire dès qu'une image est analysée ailleurs — la
* valeur et son étiquette ne parleraient plus du même fuseau.
* Ici, le décalage appliqué et l'étiquette proviennent de la MÊME source.
*
* @param filetimeUtc l'instant, en UTC
* @return "AAAA-MM-JJTHH:MM:SS+HH:MM", ou "" si la date est nulle
*/
std::wstring utcTimeToIso8601Local(const FILETIME& filetimeUtc);

/*! Convertit un FILETIME UTC en heure locale de la machine EXAMINÉE.
*
* Remplace `FileTimeToLocalFileTime()`, qui applique le fuseau de la machine
* d'EXÉCUTION. Les deux coïncident en collecte live, mais divergent dès qu'une
* image est analysée ailleurs : l'heure serait alors décalée du fuseau de
* l'examinateur tout en portant l'étiquette du fuseau du suspect — deux fuseaux
* dans une même valeur. Un seul point de vérité, `conf.timeZone`, évite ce
* piège ; le repli sur la machine d'exécution ne s'applique que si la ruche
* SYSTEM n'a pas (encore) pu être lue.
*
* @param filetimeUtc l'instant, en UTC
* @param filetimeLocal reçoit l'instant en heure locale du suspect
* @return true si la conversion a abouti
*/
bool utcVersLocalSuspect(const FILETIME& filetimeUtc, FILETIME* filetimeLocal);

/*! Relève le fuseau de la machine examinée dans la ruche SYSTEM du suspect.
*
* Lit `Control\TimeZoneInformation` sous `conf.CurrentControlSet` et renseigne
* `conf.timeZone`. À appeler dès que `conf.CurrentControlSet` est ouverte : tous
* les horodatages locaux formatés ENSUITE porteront le décalage du suspect.
*
* En cas d'échec, `conf.timeZone.valid` reste faux et le formatage retombe sur
* `GetTimeZoneInformation()` — correct en collecte live, puisque la machine
* examinée est alors la machine d'exécution.
*
* @return ERROR_SUCCESS si le fuseau a été relevé, un code d'erreur sinon
*/
HRESULT loadSuspectTimeZone();

/*! Décalage horaire utilisé pour formater les heures locales, en "+HH:MM".
* Provient de la ruche du suspect si elle a pu être lue, sinon de la machine
* d'exécution.
* @return le décalage, ex. L"+02:00"
*/
std::wstring localUtcOffsetString();

/*! Formate un SYSTEMTIME au format ISO 8601.
* @param systemtime l'instant
* @param utc true si la valeur est en UTC (suffixe « Z »), false si elle est en
*        heure locale (suffixe du fuseau de la machine)
* @return la date formatée, ou "" si elle est nulle
*/
std::wstring timeToIso8601(const SYSTEMTIME& systemtime, bool utc);

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

/*! Passe une chaîne en minuscules, pour comparer sans tenir compte de la casse.
*
* POURQUOI C'EST NÉCESSAIRE. Windows ne s'accorde pas avec lui-même sur la
* casse : sur une VM Windows 11, l'index NTFS porte « …\Windows\Input\… »
* quand le registre écrit « …\windows\input\… ». Toute correspondance par
* chemin ou par nom de service faite à la casse échoue alors EN SILENCE — et une
* tâche sans historique se lit à tort comme « jamais exécutée ».
* @param s la chaîne à normaliser
* @return la chaîne en minuscules
*/
std::wstring enMinuscules(std::wstring s);

/*! Dit si une valeur de registre est une RÉFÉRENCE de ressource MUI plutôt
* qu'un texte lisible.
*
* Windows stocke la plupart des noms affichés sous la forme
* `@%SystemRoot%\system32\schedsvc.dll,-100` ou `@tzres.dll,-301` : un fichier
* et l'identifiant d'une chaîne à l'intérieur. Seul `LoadStringW` sur le module
* la résout — donc en chargeant ce module dans le processus de collecte, ce que
* la lecture hors ligne cherche justement à éviter.
*
* La référence est donc conservée telle quelle, mais dans un champ qui dit ce
* qu'elle est : présenter `@tzres.dll,-301` comme un nom de fuseau reviendrait à
* afficher un défaut de lecture à la place d'une donnée.
*
* @param valeur la valeur lue dans la ruche
* @return true s'il s'agit d'une référence de ressource
*/
bool estReferenceMui(const std::wstring& valeur);

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
HRESULT getRegSzValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, std::wstring* ws);

/*! Lecture d'un FILMETIME en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param filetime pointeur sur un FILETIME contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegFiletimeValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, FILETIME* filetime);

/*! Lecture d'une valeur binaire en base de registre
* nécessite d'utiliser delete[] octets pour libérer la mémoire
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param octets pointeur sur un tableau de BYTE contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur registre
*/
HRESULT getRegBinaryValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, LPBYTE* octets, DWORD* taille);

/*! Lecture d'un booléen en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param valeur pointeur sur un booléen contenant la valeur lue en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegboolValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, bool* valeur);

/*! Lit une valeur REG_DWORD (32 bits) en base de registre.
* @param key clé ouverte
* @param sousCle sous-clé (peut être NULL)
* @param nomValeur nom de la valeur
* @param pdword reçoit la valeur lue
* @return ERROR_SUCCESS, ou un code d'erreur
*/
HRESULT getRegDwordValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, DWORD* pdword);

/*! Lit une valeur REG_QWORD (64 bits) en base de registre.
* Utile pour les valeurs qui portent un FILETIME brut, comme `InstallTime` sous
* `SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
* @param key clé ouverte
* @param sousCle sous-clé (peut être NULL)
* @param nomValeur nom de la valeur
* @param pqword reçoit la valeur lue
* @return ERROR_SUCCESS, ou un code d'erreur
*/
HRESULT getRegQwordValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, unsigned long long* pqword);

/*! Lecture d'un MULTISZ (multiple chaînes de caractères concaténées) en base de registre
* @param key clé de la base de registre
* @param szsubkey sous-clé de la base de registre
* @param szvalue contient la nom de la valeur à lire en base de registre
* @param out pointeur sur un tableau de wstring contenant les valeurs lues en base de registre
* @return ERROR_SUCCESS en cas de succès sinon un code erreur.
*/
HRESULT getRegMultiSzValue(ORHKEY key, PCWSTR sousCle, PCWSTR nomValeur, std::vector<std::wstring>* out);


/*! Lecture d'un MULTISZ (multiple chaînes de caractères concaténées) en base de registre
* @param searchSerial serial du volume a rechercher
* @return wstring lettre de lecteur du point de montage du lecteur.
*/
std::wstring getVolumeLetter(std::wstring searchSerial);

/*! Écrit une valeur JSON dans <_outputDir>/<nom>, en UTF-8.
* Centralise la création du répertoire de sortie, l'encodage et le chemin, pour
* que chaque artefact n'ait plus à le refaire.
* @param nom nom du fichier (ex. "bams.json")
* @param valeur la valeur JSON racine (généralement un Json::arr())
* @return ERROR_SUCCESS, ou un code d'erreur
*/
HRESULT writeJsonFile(const std::string& nom, const Json& valeur);

/*! Écrit un artefact NON COLLECTÉ, en consignant la raison de l'échec.
*
* POURQUOI. Quand `getData()` échoue, le fichier JSON n'était pas écrit du tout.
* À l'analyse, un fichier absent ne distingue pas « la lecture a échoué » de
* « il n'y avait rien à collecter » — et un analyste peut conclure à tort à
* l'absence de trace. Écrire le fichier avec le motif lève l'ambiguïté.
*
* @param nom nom du fichier (ex. "Usbstor.json")
* @param artefact libellé de l'artefact concerné
* @param resultat code d'erreur rencontré
* @return ERROR_SUCCESS si le fichier a pu être écrit
*/
HRESULT writeNotCollected(const std::string& nom, const std::wstring& artefact,
                          HRESULT resultat);

/*! Liste les fichiers réguliers d'un répertoire, filtrés par extension.
* Ne lève jamais d'exception : un répertoire absent ou illisible rend une liste
* vide. C'est le cas nominal en collecte (tous les profils n'ont pas tous les
* dossiers, et la copie brute ne contient que ce qui a été extrait) ; une
* exception non rattrapée y interromprait toute la collecte.
* La comparaison d'extension est insensible à la casse.
* @param repertoire répertoire à parcourir (non récursif)
* @param extensions extensions acceptées, point compris (ex. { L".lnk", L".url" })
* @return chemins retenus, dans l'ordre du parcours ; éventuellement vide
*/
std::vector<std::filesystem::path> listFilesByExtension(const std::filesystem::path& repertoire,
	const std::vector<std::wstring>& extensions);

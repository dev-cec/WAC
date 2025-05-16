#pragma once
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <variant>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "trans_id.h"



/********************************************************************************************************************
* Impossible de scinder le document en plusieurs fichiers car des r�f�rences cycliques entre les types l'en emp�che
*********************************************************************************************************************/

/***************************************************************************************************
* STRUCUTRES VRTUELLES
****************************************************************************************************/
/*! Type de base virtuel pour les shell Items.
*  tous les shells items h�rite de ce type de base permettant ainsi d'inclure un type de shell virtuel dans les autres classes
*/
struct IShellItem {
public:
	int niveau = 0; //!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	bool is_zip = false; //!< utile pour les shellbags, permet de d�finir les fils comm des archive_contents
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false; //!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0) = 0;
};

/*! Type de base virtuel pour les extension Block.
*  tous les shells items h�rite de ce type de base permettant ainsi d'inclure un type de shell virtuel dans les autres classes
*/
struct IExtensionBlock {
public:
	int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	bool isPresent = false;//!< true si un block d�extension est pr�sent sinon false
	std::wstring signature = L"";//!< la signature du block d�extension, identifie sa structure d'appartenance
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false; //!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0) = 0;
};

/*! User Property View Delegate Shell Item
*/
struct UserPropertyViewDelegate {

	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0) = 0;
};

/***************************************************************************************************
* Fonctions
****************************************************************************************************/

/*! Permet d'extraire des extensionBlock d'un Buffer en fonction de leur signature
* @param buffer en entr�e contient les bits � parser des extensionblock
* @param extensionBlocks pointeur sur un vecteur de Iextensionblock utiliser pour stocker les extensionBlock extraits du buffer
* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
* @param is_zip pr�cise si le shell item est un fichier zip, utilis� dans le traitement des extensionblocks, si le fichier est un zip ou assimil� alors les fils ont un format sp�cial, ne concerne que les fichiers, certains zip sont identifi�s comme directory et dans ce cas pas de format special, ne concerne que les extensionblock beef0004
* @param is_file pr�cise si le shell item p�re est un fichier, utilis� dans le traitement des extensionblocks
* @return void
*/
void getExtensionBlock(LPBYTE buffer, std::vector<IExtensionBlock*>* extensionBlocks, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors, bool* is_zip, bool is_file);

/***************************************************************************************************
* FLAGS
****************************************************************************************************/

/*! La structure FileAttributesFlags d�finit des bits qui sp�cifient les attributs de fichier du lien cible, si la cible est un �l�ment de syst�me de fichiers. Les attributs du fichier peuvent �tre utilis�s si la cible de liaison n'est pas disponible, ou si l'acc�s � la cible serait inefficaces.
* Il est possible que les attributs d'�l�ments cibles ne soient pas synchronis�s avec cette valeur.
* Documentation � l'adresse https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/378f485c-0be9-47a4-a261-7df467c3c9c6
*/
struct FileAttributes {
	bool ReadOnly = false; //!< Le fichier est en lecture seule.
	bool Hidden = false; //!< Le fichier est masqu� et n�est donc pas compris dans un listing de r�pertoires ordinaire. 
	bool System = false; //!< le fichier est un fichier system.
	bool Directory = false; //!< Le fichier est un r�pertoire. 
	bool Archive = false; //!< Ce fichier est marqu� � inclure dans une op�ration de sauvegarde incr�mentielle.
	bool Normal = false; //!< Le fichier est un fichier standard qui n�a pas d�attributs sp�ciaux. Cet attribut est valide uniquement s�il est utilis� seul.
	bool Temporary = false; //!< e fichier est temporaire. Un fichier temporaire contient les donn�es n�cessaires quand une application s�ex�cute, mais qui ne le sont plus une fois l�ex�cution termin�e. 
	bool SparseFile = false; //!< Le fichier est un fichier partiellement allou�.Les fichiers partiellement allou�s sont g�n�ralement de gros fichiers dont les donn�es sont principalement des z�ros.
	bool ReparsePoint = false; //!< Le fichier contient un point d�analyse, qui est un bloc de donn�es d�finies par l�utilisateur associ� � un fichier ou � un r�pertoire. 
	bool Compressed = false; //!< Le fichier est compress�.
	bool Offline = false; //!< Le fichier est hors connexion. Les donn�es du fichier ne sont pas imm�diatement disponibles.
	bool NotContentIndexed = false; //!< Le fichier ne sera pas index� par le service d�indexation de contenu du syst�me d�exploitation.
	bool Encrypted = false; //!< Le fichier ou le r�pertoire est chiffr�.Cela signifie pour un fichier, que toutes ses donn�es sont chiffr�es.Pour un r�pertoire, cela signifie que tous les fichiers et r�pertoires cr��s sont chiffr�s par d�faut.


	/*! constructeur
	* @param attr entier contenant les attribut du fichier. Le constructeur extrait les attributs de cet entier � l'aide masques binaires.
	*/
	FileAttributes(unsigned int attr);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();
};

/*! La structure LinkFlags d�finit des bits qui sp�cifient quelles structures de liaison de coquille sont Pr�sents dans le format de fichier apr�s la structure ShellLinkHeader.
* Documentation � l'adresse https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af
*/
struct LinkFlags {
	bool HasLinkTargetIDList = false; //!< Le lien shell est sauvegard� avec une liste d'identification d'objets (IDList). Si Ce bit est r�gl�, une LinkTargetIDList Structure DOIT suivre la ShellLinkHeader. Si ce bit n'est pas set, cette structure NE DOIT PAS �tre pr�sente.
	bool HasLinkInfo = false; //!< La liaison shell est sauvegard�e avec des informations de lien. Si cette bit est r�gl�, un LinkInfo structure DOIT �tre pr�sent. Si ce bit n'est pas r�gl�, cette structure NE DOIT PAS �tre pr�sente.
	bool HasName = false; //!< La liaison shell est sauvegard�e avec une cha�ne de nom. Si cette bit est r�gl�, une structure de String-STRING StringData DOIT �tre pr�sent. Si ce bit n'est pas r�gl�, cette structure NE DOIT PAS �tre pr�sente.
	bool HasRelativePath = false; //!< The shell link is saved with a relative path string. If this bit is set, a RELATIVE_PATH StringData structure MUST be present. If this bit is not set, this structure MUST NOT be present.
	bool HasWorkingDir = false; //!< La liaison shell est sauvegard�e avec un r�pertoire de travail. Si ce bit est r�gl�, une structure de TRAVANT-DIR StringData DOIT �tre pr�sent. Si ce bit n'est pas r�gl�, cette structure NE DOIT PAS �tre pr�sente.
	bool HasArguments = false;  //!< La liaison shell est sauvegard�e avec des arguments de ligne de commande. Si ce bit est r�gl�, une structure de cha�ne COMMAND-LINE-ARGUMENTS DOIT �tre pr�sent. Si ce bit n'est pas r�gl�, cette structure NE DOIT PAS �tre pr�sente.
	bool HasIconLocation = false; //!< La liaison shell est sauvegard�e avec une cha�ne de localisation d'ic�ne. Si ce bit est r�gl�, une structure de strate de cha�ne ICON-LOCATIONDOIT �tre pr�sent. Si ce bit n'est pas r�gl�, cette structure NE DOIT PAS �tre pr�sente.
	bool IsUnicode = false; //!< Le lien shell contient des cha�nes cod�es Unicode. C'est ce que bit DEVRAIT �tre r�gl�. Si ce bit est d�fini, la section StringData contient Cha�nes cod�es en cod�es par un code d'Unicode; sinon, il contient des cha�nes qui sont cod�es en utilisant la page de code par d�faut du syst�me.
	bool ForceNoLinkInfo = false; //!< La structure LinkInfo est ignor�e.
	bool HasExpString = false; //!< La liaison shell est sauvegard�e avec un bloc de donn�es EnvironnementVariable
	bool RunInSeparateProcess = false; //!< La cible est ex�cut�e dans une machine virtuelle s�par�e lorsque lancement d'une cible de liaison c'est une application de 16 bits.
	bool Unused1 = false; //!< Un bit qui n'est pas d�fini et DOIT �tre ignor�.
	bool HasDarwinID = false; //!< La liaison � coque est sauvegard�e avec un DarwinDataBlock
	bool RunAsUser = false; //!< L'application est ex�cut�e en tant qu'utilisateur diff�rent lorsque le Une cible de la liaison de l'obus est activ�e.
	bool HasExpIcon = false; //!< La liaison shell est sauvegard�e avec un IconEnvironmentDataBlock
	bool NoPidlAlias = false; //! L'emplacement du syst�me de fichiers est repr�sent� dans l'espace de noms de shell lorsque le chemin � un article est analys� en une liste d'ID.
	bool Unused2 = false; //!< Un bit qui n'est pas d�fini et DOIT �tre ignor�.
	bool RunWithShimLayer = false; //!< La liaison shell est sauvegard�e avec un ShimDataBlock
	bool ForceNoLinkTrack = false; //!< Le TrackerDataBlock est ignor�e.
	bool EnableTargetMetadata = false; //!< La liaison � l'obus tente de collecter les propri�t�s cibles et les stocker dans le PropertyStoreDataBlock lorsque la cible de liaison est d�finie.
	bool DisableLinkPathTracking = false; //!< Le EnvironmentVariableDataBlock est ignor�.
	bool DisableKnownFolderTracking = false; //!< Le SpecialFolderDataBlock et le KnownFolderDataBlock sont ignor�s lors du chargement de la liaison de la coque. Si ce bit est d�fini, ces donn�es suppl�mentaires blocs NE DEVRAIT PAS �tre sauvegard�s lors de la sauvegarde de la liaison shell.
	bool DisableKnownFolderAlias = false; //!< Si le lien a une KnownFolderDataBlock, la forme nonalias de la connue IDList du dossier souhaite �tre utilis�e lors de la traduction de la cible IDList � la le temps de chargement de la liaison.
	bool AllowLinkToLink = false; //!< Cr�ation d'un lien qui fait r�f�rence � un autre lien est activ�. Sinon, en sp�cifier un lien comme IDList cible NE DEVRAIT PAS �tre autoris�s.
	bool UnaliasOnSave = false; //!< Lors de la sauvegarde d'un lien pour lequel la cible IDList est sous un dossier connu, soit la forme nonalias de ce dossier connu, soit le dossier connu de l'IDList de cible DEVRAIT �tre utilis�.
	bool PreferEnvironmentPath = false; //!< La cible L'IDLIST NE DEVRAIT PAS �tre stock�e; � la place, le chemin sp�cifi� dans le bloc de donn�es de l'environnement DEVRAIT �tre utilis� pour se r�f�rer � la cible.
	bool KeepLocalIDListForUNCTarget = false; //!< Lorsque l'objectif est un nom UNC qui fait r�f�rence � un sur une machine locale, le chemin local IDLIST dans le PropertyStoreDataBlock DEVRAIT �tre stock�, de sorte qu'il puisse �tre utilis� lorsque la liaison est charg�e sur la machine locale.

	/*! constructeur
	* @param _flags entier contenant les flags du lien. Le constructeur extrait les flags de cet entier � l'aide masques binaires.
	*/
	LinkFlags(unsigned int _flags);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();
};


/*! La structure ShellVolumeFlags d�finit des bits qui sp�cifient le type de volume shell.
*/
struct ShellVolumeFlags {
	bool None = false; //!< Pas d'information sur le volume
	bool SystemFolder = false; //!< le volume est r�pertoire system
	bool LocalDisk = false; //!< le volume et un disque local

	/*! constructeur
	* @param i octet contenant les donn�es � traiter. Le constructeur extrait les donn�es de cette valeur � l'aide masques binaires.
	*/
	ShellVolumeFlags(unsigned char i);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();
};

/*! La structure FsFlags d�finit des bits qui sp�cifient le type de lien.
*/
struct FsFlags {
	bool IS_DIRECTORY = false; //!< il s'agit d'un repertoire
	bool IS_FILE = false; //!< il s'agit dun fichier
	bool IS_UNICODE = false; //!< Les strings du lien sont au format UNICODE
	bool UNKNOWN = false; //!< le type de lien est inconnu
	bool HAS_CLSID = false; //!< le lien a un guid de classe

	/*! constructeur
	* @param i octet contenant les donn�es � traiter. Le constructeur extrait les donn�es de cette valeur � l'aide masques binaires.
	*/
	FsFlags(unsigned char i);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();
};


/***************************************************************************************************
* SPS
****************************************************************************************************/

/*! Structure repr�sentent une des valeurs d'un SPS.
*/
struct SPSValue {
	int niveau = 0; //!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int size = 0; //! taille de l'objet
	unsigned short int valueType = 0; //! identifie le type de valeur
	std::wstring guid = L""; //! guid de la valeur
	std::wstring id = L""; // id de la valeur
	std::wstring name = L""; // nom de la valeur
	std::wstring value = L""; // valeur de la valeur, peut �tre un objet auquel cas il est stock� au format json pour compatibilit� avec le format json de sortie.
	bool valueIsObject = false; // true si le contenu du champ value est un objet. Utilis� pour la mise en forme du fichier json de sortie.
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false; //!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _guid guid correspondant au SPS auquel appartient le SPSVALUE
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	SPSValue(LPBYTE buffer, std::wstring _guid, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/*! Structure repr�sentent un Serialized Property Sets.
*/
struct SPS {
	int niveau = 0; //!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int size = 0; //!< Taille de l'objet en octets
	unsigned int version = 0; //!< version de l'objet permettant de d�finir sa structure interne
	std::wstring guid = L""; //!< GUID de l'objet
	std::wstring FriendlyName = L"";//!< nom associ� au GUID
	std::vector<SPSValue> values; //!< Tableau contenant les diff�rents SPSVALUE de l'objet SPS
	bool _debug = false; //!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! constructeur par d�faut
	*/
	SPS() {};

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	SPS(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

void getShellItem(LPBYTE buffer, IShellItem** p, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors, bool Parentiszip = false);

/***************************************************************************************************
* ID LIST
****************************************************************************************************/
/*! type repr�sentant une liste de Shell Item
*/
struct IdList {
	int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int item_size = 0; //!< Taille de l'objet en octets
	unsigned char type_char = NULL; //!< Type de l'objet
	std::wstring type_hex = L""; //!< type de l'objet en hexa
	std::wstring type = L""; //!< nom correspondant au type de l'objet
	std::wstring pData = L""; //!< dump hexa de l'objet si besoin de l'include dans le json de sortie
	IShellItem* shellItem = NULL; //!< pointeur vers l'objet shell item correspondant au type
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< si true alors le fichier de sortie contiendra le dump hexa de l'objet


	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	IdList(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors, bool Parentiszip = false);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/***************************************************************************************************
* EXTENSION BLOCKS
****************************************************************************************************/
/*!  Related to CMergedFolder object
*/
struct Beef0000 : IExtensionBlock {
	std::wstring guid1 = L""; //!< identifiant GUID
	std::wstring identifier1 = L"";//!< nom correspondant au GUID
	std::wstring guid2 = L""; //!< identifiant GUID
	std::wstring identifier2 = L""; //!< nom correspondant au GUID

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0000(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*!  Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0001 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0001(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0002 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0002(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CFSFolder and CFileSysItemString object. Used for junction information?
*/
struct Beef0003 : IExtensionBlock {
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring identifier = L"";//!< nom associ� au GUID

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0003(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CFSFolder and CFileSysItem object.
	* pour les shellbags, si le p�re est un zip ou assimil� alors les fils ont un format sp�cial, il faut donc identifier si le p�re est un zip
	* ne concerne que les fichiers, certains zip sont identifi�s comme directory et dans ce cas pas de format special
	* ne concerne que les extensionblock beef0004
*/
struct Beef0004 : IExtensionBlock {
	FILETIME creationDate = { 0 }; //!< date de cr�ation
	FILETIME creationDateUtc = { 0 };//!< date de cr�ation au format UTC
	FILETIME accessedDate = { 0 }; //!< date d'acc�s
	FILETIME accessedDateUtc = { 0 }; //!< date d'acc�s au format UTC
	unsigned short int ExtensionVersion;
	std::wstring longName = L"";
	std::wstring localizedName = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	* @param is_zip est un bool�en indiquant que l'objet est une archive compress�e
	* @param is_file est un bool�en indiquant que l'objet est un fichier
	*/
	Beef0004(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors, bool* is_zip, bool is_file);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CFSFolder and CFileSysItem object. Used for personalized name?
*/
struct Beef0006 : IExtensionBlock {
	std::wstring username = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0006(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CBitBucket object.
*/
struct Beef0008 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0008(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CBitBucket object. Used for original path?
*/
struct Beef0009 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0009(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to CMergedFolder object. Used for source count or sub shell item list?
*/
struct Beef000a : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef000a(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block  related to CControlPanelFolder object. Used for display name/CPL category?
*/
struct Beef000c : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef000c(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef000e : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message � afficher dans le json
	std::wstring guid = L"";//!< Identifiant GUID
	std::wstring identifier = L"";//!< com correspondant au GUID
	std::vector<IExtensionBlock*> extensionblocks; //!< tableau d'extension blocks
	std::vector<SPS> SPSs; //! tableau de SPS
	std::vector<IShellItem*> ishellitems;//!< tableau de shellitems

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef000e(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0010 : IExtensionBlock {
	SPS sps;

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0010(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0013 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0013(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! The extension block has seen to be used with the CUri class identifier which is the GUID "df2fce13-25ec-45bb-9d4c-cecd47c2430c". The CUri data could be a Vista and/or MSIE 7 specific extension.
*/
struct Beef0014 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0014(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0016 : IExtensionBlock {
	std::wstring value = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0016(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*!  Extension block  related to Shell item from Windows 7 BagMRU (Search Home).
*/
struct Beef0017 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0017(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block  seen in  HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\{0B2BAAEB-0042-4DCA-AA4D-3EE8648D03E5}
*/
struct Beef0019 : IExtensionBlock {
	std::wstring guid1 = L""; //!< identifiant GUID
	std::wstring identifier1 = L"";//!< nom correspondant au GUID
	std::wstring guid2 = L"";//!< identifiant GUID
	std::wstring identifier2 = L"";//!< nom correspondant au GUID

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0019(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef001a : IExtensionBlock {
	std::wstring fileDocumentTypeString = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef001a(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef001b : IExtensionBlock {
	std::wstring fileDocumentTypeString = L""; //!< cha�ne indiquant le type de document

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef001b(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef001d : IExtensionBlock {
	std::wstring executable = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef001d(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef001e : IExtensionBlock {
	std::wstring pinType = L"";

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef001e(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0021 : IExtensionBlock {
	SPS sps;  //!< un objet SPS

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0021(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0024 : IExtensionBlock {
	SPS sps;  //!< un objet SPS

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0024(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0025 : IExtensionBlock {
	FILETIME filetime1 = { 0 }; //!< date au format filetime
	FILETIME filetime2 = { 0 };//!< date  au format filetime

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0025(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0026 : IExtensionBlock {
	FILETIME ctimeUtc = { 0 }; //!< date de cr�ation
	FILETIME ctime = { 0 };//!< date de cr�ation au format UTC
	FILETIME mtimeUtc = { 0 };//!< date de modification
	FILETIME mtime = { 0 };//!< date de modification au format UTC
	FILETIME atimeUtc = { 0 };//!< date d'acc�s
	FILETIME atime = { 0 };//!< date d'acc�s au format UTC
	IdList* idlist = NULL;//pointeur vers une liste de shell item (idlist)
	IShellItem* shellitem = NULL;//pointeur vers un shelitem
	SPS* sps = NULL;//pointeur vers un SPS

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0026(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0027 : IExtensionBlock {
	SPS sps; //!< un objet SPS

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0027(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Extension block related to unknown.
*/
struct Beef0029 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message � afficher dans le json

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Beef0029(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/********************************************************************************************************************
* shell items
*********************************************************************************************************************/

/*! Volume Shell Item
*/
struct VolumeShellItem : IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	ShellVolumeFlags flags = { 0 }; //!< drapeaux correspondant aux options du type de volume flags
	std::wstring name = L""; //!< nom du volume
	std::wstring guid = L""; //!< GUID du volume
	std::wstring identifier = L""; //!< nom associ� au GUID

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param type_char est le type d'objet au format character
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	VolumeShellItem(LPBYTE buffer, unsigned char type_char, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/*! Control panel Shell Item
*/
struct ControlPanel : IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L""; //!< nom associ� au GUID
	std::vector <IExtensionBlock*> extensionBlocks; //!< tableau d'Extension Block


	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param item_size est la taille totale de l'objet
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	ControlPanel(LPBYTE buffer, unsigned short int itemSize, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Control Panel Category Shell Item
*/
struct ControlPanelCategory :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring id = L""; //!< identifiant
	std::vector <IExtensionBlock*> extensionBlocks; //!< tableau d'Extension Block


	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	ControlPanelCategory(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Retourne le type de valeur de la SPSVALUE � partir du code hexa
*/
std::wstring get_type(unsigned int type);

/*!  Retourne le valeur de la SPSVALUE � partir de son type
*/
void get_value(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int niveau, std::wstring* value, bool* valueIsObject, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);

/*! Structure d�finissant le format d'un Property � l�int�rieur des UserPropertyView
*/
struct Property {
	int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int id = 0; //!< identifiant de la property
	unsigned short int type = 0; //!< type de la property
	unsigned int size = 0; //!< taille de la property
	std::wstring guid = L""; //! identifiant GUID
	std::wstring FriendlyName = L""; //!< nom associ� au guid
	std::wstring value = L"";//!< valeur de la property
	bool valueIsObject = false; //! vrai si la valeur est un objet, sinon la valeur est un string
	bool _debug = false;//!< param�tre de la ligne de commande, si true alors on sauvegarde les erreurs de traitement dans un fichier json
	bool _dump = false;//!< si true alors le fichier de sortie contiendra le dump hexa de l'objet

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	Property(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un UserPropertyView de signature 0xC01
*/
struct UserPropertyView0xC01 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring folder = L""; //!< nom du repertoire
	std::wstring fullurl = L""; //! url correspondante

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UserPropertyView0xC01(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);

};

/*! Structure d�finissant le format d'un UserPropertyView de type 0x23febee
*/
struct UserPropertyView0x23febbee : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring FriendlyName = L""; //!< nom associ� au GUID

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UserPropertyView0x23febbee(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un UserPropertyView de type 0x7192006
*/
struct UserPropertyView0x07192006 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	FILETIME modified = { 0 }; //!< date de modification
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME created = { 0 }; //!< date de cr�ation
	FILETIME createdUtc = { 0 }; //!< date de cr�ation au format UTC
	std::wstring folderName1 = L""; //!< nom du repertoire
	std::wstring folderName2 = L""; //!< nom du repertoire
	std::wstring folderIdentifier = L""; //!< identifiant du repertoire
	std::wstring guidClass = L""; //!< identifiant GUID de la classe
	std::wstring FriendlyName = L""; //!< nom associ� au GUID de la classe
	std::vector<Property> properties; //!< Tableau de Property

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UserPropertyView0x07192006(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un UserPropertyView de type 0x10312005
*/
struct UserPropertyView0x10312005 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hi�rarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring name = L"";//!< nom  de la propri�t�
	std::wstring identifier = L""; //!< identifiant de la propri�t�
	std::wstring filesystem = L"";//!< nom du syst�me de fichier
	std::wstring guidClass = L""; //!< identifiant GUID de classe
	std::wstring FriendlyName = L""; //!< nom associ� au GUID de classe
	std::vector<std::wstring> guidstrings; //!< tableau de GUID
	std::vector<Property> properties;//!< tableau de Property

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UserPropertyView0x10312005(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un UserPropertyView shell item
*/
struct UsersPropertyView :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	unsigned short int totalsize = 0; //!< taille totale de l�objet
	unsigned short int dataSize = 0; //!< taille des donn�es
	unsigned int signature = 0; //!< signature de l"objet
	unsigned short int SPSDataSize = 0; //!< taille des donn�es SPS
	unsigned short int identifierSize = 0;//!< taille de l'identifier
	unsigned int dataOffset = 0; //!< Offset des donn�es
	unsigned short int extensionOffset = 0; //!< Offset des extension blocks
	unsigned short int spsOffset = 0;//!< offset des SPS
	std::vector<SPS> SPSs; //!< tableau contenant les SPS
	std::vector<IExtensionBlock*> extensionBlocks; //!< tableau contenant les extension blocks
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L"";//!< nom associ� au GUID
	UserPropertyViewDelegate* delegate = NULL; //! UsersPropertyView d�l�gu�e

	/*! constructeur par d�faut
	*/
	UsersPropertyView() {};

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UsersPropertyView(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un RootFolder Shell Item
*/
struct RootFolder :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring sortIndex = L""; //!w index de tri
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L"";//!< nom associ� au GUID
	std::vector<SPS> SPSs; //!< tableau de SPS
	//std::vector<IExtensionBlock*> extensionBlocks; // TODO des extension blocks sont pr�sent avec le type GUID mais on retrouve les m�me datas dans les SPS donc on passe

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	RootFolder(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un Network Shell Item
*/
struct NetworkShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring subtypename = L"";//!< nom du sous-type
	std::wstring location = L"";//!< emplacement 
	std::wstring description = L"";//!< description de l'objet
	std::wstring comments = L"";//!< commentaires de l�objet
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	NetworkShellItem(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un Archive File Shell Item
*/
struct ArchiveFileContent :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring subtypename = L"";//!< nom du sous-type
	std::wstring location = L"";//!< emplacement 
	std::wstring name = L"";//!< nom de l'archive
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	ArchiveFileContent(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un URL Shell Item
*/
struct URIShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring uri = L""; //!< URI 

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	URIShellItem(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un File Entry Shell Item
*/
struct FileEntryShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	unsigned short int fsFileSize = 0; //!< taille du fichier
	FILETIME fsFileModificationUtc = { 0 };//!< date de modification UTC
	FILETIME fsFileModification = { 0 };//!< date de modification
	std::wstring fsPrimaryName = L"";//!< nom primaire
	FsFlags fsFlags = { 0 }; //!< drapeaux d�crivant les options de l'entr�e
	FileAttributes fsFileAttributes = { 0 }; //!< drapeaux d�crivant les attributs de l'entr�e
	std::vector <IExtensionBlock*> extensionBlocks; //!< tableau contenant les extension blocks

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param item_size est la taille de l'objet
	* @param shell_item_type_char est le type de shell item au format character
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	FileEntryShellItem(LPBYTE buffer, unsigned short int itemSize, unsigned char shell_item_type_char, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un Users Files Folder Shell Item
*/
struct UsersFilesFolder :IShellItem {
public:
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring primaryName = L"";//!< nom primaire
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification
	IExtensionBlock* extensionBlock; //!< block d'extension

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UsersFilesFolder(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un Favorites Shell Item
*/

struct FavoriteShellitem :IShellItem { // TODO A TESTER
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	UsersPropertyView UPV; //! Objet UsersPropertyView

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	FavoriteShellitem(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};

/*! Structure d�finissant le format d'un UNKNOWN Shell Item
*/
struct UnknownShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il pr�sent, utilis� pour le formatage du json
	std::wstring data = L"";//!< cha�ne contenant les donn�es

	/*! constructeur
	* @param buffer en entr�e contient les bits � parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'�l�ment utilis� pour la mise en forme du fichier json de sortie
	* @param pdebug est issu de la ligne de commande. Si true alors un fichier de sortie contenant les erreurs de traitement sera g�n�r�
	* @param pdump est issue de la ligne de commande. Si true le contenu du buffer sera ajout� au fichier de sortie au format hexad�cimal
	* @param errors est un pointeur sur un vecteur de wstring contenant les erreurs de traitements de la fonction
	*/
	UnknownShellItem(LPBYTE buffer, int _niveau, bool pdebug, bool pdump, std::vector<std::tuple<std::wstring, HRESULT>>* errors);
	/*! conversion de l'objet au format json
	* @param i nombre de tabulation n�cessaire en d�but de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	virtual std::wstring to_json(int i = 0);
};



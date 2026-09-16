#pragma once
#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <memory>
#include <variant>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "json.h"
#include "trans_id.h"



/********************************************************************************************************************
* Impossible de scinder le document en plusieurs fichiers car des références cycliques entre les types l'en empêche
*********************************************************************************************************************/

/***************************************************************************************************
* STRUCUTRES VRTUELLES
****************************************************************************************************/
/*! Type de base virtuel pour les shell Items.
*  tous les shells items hérite de ce type de base permettant ainsi d'inclure un type de shell virtuel dans les autres classes
*/
struct IShellItem {
public:
	/*! Destructeur virtuel : indispensable pour detruire un objet derive
	* via un pointeur de base (sinon comportement indefini). */
	virtual ~IShellItem() = default;

	int niveau = 0; //!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	bool is_zip = false; //!< utile pour les shellbags, permet de définir les fils comm des archive_contents

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	virtual Json toJson() = 0;

};

/*! Type de base virtuel pour les extension Block.
*  tous les shells items hérite de ce type de base permettant ainsi d'inclure un type de shell virtuel dans les autres classes
*/
struct IExtensionBlock {
public:
	/*! Destructeur virtuel : indispensable pour detruire un objet derive
	* via un pointeur de base (sinon comportement indefini). */
	virtual ~IExtensionBlock() = default;

	int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	bool isPresent = false;//!< true si un block d’extension est présent sinon false
	std::wstring signature = L"";//!< la signature du block d’extension, identifie sa structure d'appartenance

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	virtual Json toJson() = 0;

};

/*! User Property View Delegate Shell Item
*/
struct UserPropertyViewDelegate {
	/*! Destructeur virtuel : indispensable pour detruire un objet derive
	* via un pointeur de base (sinon comportement indefini). */
	virtual ~UserPropertyViewDelegate() = default;


	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	virtual Json toJson() = 0;

};

/***************************************************************************************************
* Fonctions
****************************************************************************************************/

/*! Permet d'extraire des extensionBlock d'un Buffer en fonction de leur signature
* @param buffer en entrée contient les bits à parser des extensionblock
* @param extensionBlocks pointeur sur un vecteur de Iextensionblock utiliser pour stocker les extensionBlock extraits du buffer
* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
* @param is_zip précise si le shell item est un fichier zip, utilisé dans le traitement des extensionblocks, si le fichier est un zip ou assimilé alors les fils ont un format spécial, ne concerne que les fichiers, certains zip sont identifiés comme directory et dans ce cas pas de format special, ne concerne que les extensionblock beef0004
* @param is_file précise si le shell item père est un fichier, utilisé dans le traitement des extensionblocks
*/
void getExtensionBlock(LPBYTE buffer, std::vector<std::unique_ptr<IExtensionBlock>>* extensionBlocks, int _niveau, bool* is_zip, bool is_file);

/***************************************************************************************************
* FLAGS
****************************************************************************************************/

/*! La structure FileAttributesFlags définit des bits qui spécifient les attributs de fichier du lien cible, si la cible est un élément de système de fichiers. Les attributs du fichier peuvent être utilisés si la cible de liaison n'est pas disponible, ou si l'accès à la cible serait inefficaces.
* Il est possible que les attributs d'éléments cibles ne soient pas synchronisés avec cette valeur.
* Documentation à l'adresse https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/378f485c-0be9-47a4-a261-7df467c3c9c6
*/
struct FileAttributes {
	bool ReadOnly = false; //!< Le fichier est en lecture seule.
	bool Hidden = false; //!< Le fichier est masqué et n’est donc pas compris dans un listing de répertoires ordinaire. 
	bool System = false; //!< le fichier est un fichier system.
	bool Directory = false; //!< Le fichier est un répertoire. 
	bool Archive = false; //!< Ce fichier est marqué à inclure dans une opération de sauvegarde incrémentielle.
	bool Normal = false; //!< Le fichier est un fichier standard qui n’a pas d’attributs spéciaux. Cet attribut est valide uniquement s’il est utilisé seul.
	bool Temporary = false; //!< e fichier est temporaire. Un fichier temporaire contient les données nécessaires quand une application s’exécute, mais qui ne le sont plus une fois l’exécution terminée. 
	bool SparseFile = false; //!< Le fichier est un fichier partiellement alloué.Les fichiers partiellement alloués sont généralement de gros fichiers dont les données sont principalement des zéros.
	bool ReparsePoint = false; //!< Le fichier contient un point d’analyse, qui est un bloc de données définies par l’utilisateur associé à un fichier ou à un répertoire. 
	bool Compressed = false; //!< Le fichier est compressé.
	bool Offline = false; //!< Le fichier est hors connexion. Les données du fichier ne sont pas immédiatement disponibles.
	bool NotContentIndexed = false; //!< Le fichier ne sera pas indexé par le service d’indexation de contenu du système d’exploitation.
	bool Encrypted = false; //!< Le fichier ou le répertoire est chiffré.Cela signifie pour un fichier, que toutes ses données sont chiffrées.Pour un répertoire, cela signifie que tous les fichiers et répertoires créés sont chiffrés par défaut.


	/*! constructeur
	* @param attr entier contenant les attribut du fichier. Le constructeur extrait les attributs de cet entier à l'aide masques binaires.
	*/
	FileAttributes(unsigned int attr);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();

};

/*! La structure LinkFlags définit des bits qui spécifient quelles structures de liaison de coquille sont Présents dans le format de fichier après la structure ShellLinkHeader.
* Documentation à l'adresse https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af
*/
struct LinkFlags {
	bool HasLinkTargetIDList = false; //!< Le lien shell est sauvegardé avec une liste d'identification d'objets (IDList). Si Ce bit est réglé, une LinkTargetIDList Structure DOIT suivre la ShellLinkHeader. Si ce bit n'est pas set, cette structure NE DOIT PAS être présente.
	bool HasLinkInfo = false; //!< La liaison shell est sauvegardée avec des informations de lien. Si cette bit est réglé, un LinkInfo structure DOIT être présent. Si ce bit n'est pas réglé, cette structure NE DOIT PAS être présente.
	bool HasName = false; //!< La liaison shell est sauvegardée avec une chaîne de nom. Si cette bit est réglé, une structure de String-STRING StringData DOIT être présent. Si ce bit n'est pas réglé, cette structure NE DOIT PAS être présente.
	bool HasRelativePath = false; //!< The shell link is saved with a relative path string. If this bit is set, a RELATIVE_PATH StringData structure MUST be present. If this bit is not set, this structure MUST NOT be present.
	bool HasWorkingDir = false; //!< La liaison shell est sauvegardée avec un répertoire de travail. Si ce bit est réglé, une structure de TRAVANT-DIR StringData DOIT être présent. Si ce bit n'est pas réglé, cette structure NE DOIT PAS être présente.
	bool HasArguments = false;  //!< La liaison shell est sauvegardée avec des arguments de ligne de commande. Si ce bit est réglé, une structure de chaîne COMMAND-LINE-ARGUMENTS DOIT être présent. Si ce bit n'est pas réglé, cette structure NE DOIT PAS être présente.
	bool HasIconLocation = false; //!< La liaison shell est sauvegardée avec une chaîne de localisation d'icône. Si ce bit est réglé, une structure de strate de chaîne ICON-LOCATIONDOIT être présent. Si ce bit n'est pas réglé, cette structure NE DOIT PAS être présente.
	bool IsUnicode = false; //!< Le lien shell contient des chaînes codées Unicode. C'est ce que bit DEVRAIT être réglé. Si ce bit est défini, la section StringData contient Chaînes codées en codées par un code d'Unicode; sinon, il contient des chaînes qui sont codées en utilisant la page de code par défaut du système.
	bool ForceNoLinkInfo = false; //!< La structure LinkInfo est ignorée.
	bool HasExpString = false; //!< La liaison shell est sauvegardée avec un bloc de données EnvironnementVariable
	bool RunInSeparateProcess = false; //!< La cible est exécutée dans une machine virtuelle séparée lorsque lancement d'une cible de liaison c'est une application de 16 bits.
	bool Unused1 = false; //!< Un bit qui n'est pas défini et DOIT être ignoré.
	bool HasDarwinID = false; //!< La liaison à coque est sauvegardée avec un DarwinDataBlock
	bool RunAsUser = false; //!< L'application est exécutée en tant qu'utilisateur différent lorsque le Une cible de la liaison de l'obus est activée.
	bool HasExpIcon = false; //!< La liaison shell est sauvegardée avec un IconEnvironmentDataBlock
	bool NoPidlAlias = false; //! L'emplacement du système de fichiers est représenté dans l'espace de noms de shell lorsque le chemin à un article est analysé en une liste d'ID.
	bool Unused2 = false; //!< Un bit qui n'est pas défini et DOIT être ignoré.
	bool RunWithShimLayer = false; //!< La liaison shell est sauvegardée avec un ShimDataBlock
	bool ForceNoLinkTrack = false; //!< Le TrackerDataBlock est ignorée.
	bool EnableTargetMetadata = false; //!< La liaison à l'obus tente de collecter les propriétés cibles et les stocker dans le PropertyStoreDataBlock lorsque la cible de liaison est définie.
	bool DisableLinkPathTracking = false; //!< Le EnvironmentVariableDataBlock est ignoré.
	bool DisableKnownFolderTracking = false; //!< Le SpecialFolderDataBlock et le KnownFolderDataBlock sont ignorés lors du chargement de la liaison de la coque. Si ce bit est défini, ces données supplémentaires blocs NE DEVRAIT PAS être sauvegardés lors de la sauvegarde de la liaison shell.
	bool DisableKnownFolderAlias = false; //!< Si le lien a une KnownFolderDataBlock, la forme nonalias de la connue IDList du dossier souhaite être utilisée lors de la traduction de la cible IDList à la le temps de chargement de la liaison.
	bool AllowLinkToLink = false; //!< Création d'un lien qui fait référence à un autre lien est activé. Sinon, en spécifier un lien comme IDList cible NE DEVRAIT PAS être autorisés.
	bool UnaliasOnSave = false; //!< Lors de la sauvegarde d'un lien pour lequel la cible IDList est sous un dossier connu, soit la forme nonalias de ce dossier connu, soit le dossier connu de l'IDList de cible DEVRAIT être utilisé.
	bool PreferEnvironmentPath = false; //!< La cible L'IDLIST NE DEVRAIT PAS être stockée; à la place, le chemin spécifié dans le bloc de données de l'environnement DEVRAIT être utilisé pour se référer à la cible.
	bool KeepLocalIDListForUNCTarget = false; //!< Lorsque l'objectif est un nom UNC qui fait référence à un sur une machine locale, le chemin local IDLIST dans le PropertyStoreDataBlock DEVRAIT être stocké, de sorte qu'il puisse être utilisé lorsque la liaison est chargée sur la machine locale.

	/*! constructeur
	* @param _flags entier contenant les flags du lien. Le constructeur extrait les flags de cet entier à l'aide masques binaires.
	*/
	LinkFlags(unsigned int _flags);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();

};


/*! La structure ShellVolumeFlags définit des bits qui spécifient le type de volume shell.
*/
struct ShellVolumeFlags {
	bool None = false; //!< Pas d'information sur le volume
	bool SystemFolder = false; //!< le volume est répertoire system
	bool LocalDisk = false; //!< le volume et un disque local

	/*! constructeur
	* @param i octet contenant les données à traiter. Le constructeur extrait les données de cette valeur à l'aide masques binaires.
	*/
	ShellVolumeFlags(unsigned char i);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	std::wstring to_wstring();

};

/*! La structure FsFlags définit des bits qui spécifient le type de lien.
*/
struct FsFlags {
	bool IS_DIRECTORY = false; //!< il s'agit d'un repertoire
	bool IS_FILE = false; //!< il s'agit dun fichier
	bool IS_UNICODE = false; //!< Les strings du lien sont au format UNICODE
	bool UNKNOWN = false; //!< le type de lien est inconnu
	bool HAS_CLSID = false; //!< le lien a un guid de classe

	/*! constructeur
	* @param i octet contenant les données à traiter. Le constructeur extrait les données de cette valeur à l'aide masques binaires.
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

/*! Structure représentent une des valeurs d'un SPS.
*/
struct SPSValue {
	int niveau = 0; //!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int size = 0; //! taille de l'objet
	unsigned short int valueType = 0; //! identifie le type de valeur
	std::wstring guid = L""; //! guid de la valeur
	std::wstring id = L""; // id de la valeur
	std::wstring name = L""; // nom de la valeur
	Json value = Json::str(L""); // valeur de la valeur, peut être un objet auquel cas il est stocké au format json pour compatibilité avec le format json de sortie.

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _guid guid correspondant au SPS auquel appartient le SPSVALUE
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	SPSValue(LPBYTE buffer, std::wstring _guid, int _niveau);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

/*! Structure représentent un Serialized Property Sets.
*/
struct SPS {
	int niveau = 0; //!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int size = 0; //!< Taille de l'objet en octets
	unsigned int version = 0; //!< version de l'objet permettant de définir sa structure interne
	std::wstring guid = L""; //!< GUID de l'objet
	std::wstring FriendlyName = L"";//!< nom associé au GUID
	std::vector<SPSValue> values; //!< Tableau contenant les différents SPSVALUE de l'objet SPS

	/*! constructeur par défaut
	*/
	SPS() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	SPS(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

std::unique_ptr<IShellItem> makeShellItem(LPBYTE buffer, int _niveau, bool Parentiszip = false);

/***************************************************************************************************
* ID LIST
****************************************************************************************************/
/*! type représentant une liste de Shell Item
*/
struct IdList {
	int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int item_size = 0; //!< Taille de l'objet en octets
	unsigned char type_char = NULL; //!< Type de l'objet
	std::wstring type_hex = L""; //!< type de l'objet en hexa
	std::wstring type = L""; //!< nom correspondant au type de l'objet
	std::wstring donnees = L""; //!< dump hexa de l'objet si besoin de l'include dans le json de sortie
	std::unique_ptr<IShellItem> shellItem; //!< pointeur vers l'objet shell item correspondant au type

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	* @param Parentiszip vrai si l'élément parent est une archive : le contenu
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	IdList(LPBYTE buffer, int _niveau, bool Parentiszip = false);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

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
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0000(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*!  Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0001 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0001(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CFileUrlStub object. Used for display name?
*/
struct Beef0002 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0002(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CFSFolder and CFileSysItemString object. Used for junction information?
*/
struct Beef0003 : IExtensionBlock {
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring identifier = L"";//!< nom associé au GUID

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0003(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CFSFolder and CFileSysItem object.
	* pour les shellbags, si le père est un zip ou assimilé alors les fils ont un format spécial, il faut donc identifier si le père est un zip
	* ne concerne que les fichiers, certains zip sont identifiés comme directory et dans ce cas pas de format special
	* ne concerne que les extensionblock beef0004
*/
struct Beef0004 : IExtensionBlock {
	FILETIME creationDate = { 0 }; //!< date de création
	FILETIME creationDateUtc = { 0 };//!< date de création au format UTC
	FILETIME accessedDate = { 0 }; //!< date d'accès
	FILETIME accessedDateUtc = { 0 }; //!< date d'accès au format UTC
	unsigned short int ExtensionVersion=0;
	/*! Identifiant interne du bloc (offset 16), lu mais jamais émis auparavant. */
	unsigned short int identifier = 0;
	/*! Référence de fichier NTFS : numéro d'entrée `$MFT` sur 48 bits et numéro
	* de séquence sur 16, présents à partir de la version 7 du bloc.
	*
	* POURQUOI C'EST IMPORTANT. Cette référence désigne l'entrée `$MFT` EXACTE du
	* fichier : elle rattache une entrée de shellbag ou de raccourci à son
	* enregistrement dans la table de fichiers, donc permet de retrouver le
	* fichier même renommé ou supprimé, et de recouper ses dates. WAC ne la
	* lisait pas, alors que la lecture brute du volume exploite déjà ces
	* références ailleurs.
	* Nuls si le bloc est d'une version antérieure à 7, ou si l'élément ne
	* provient pas d'un volume NTFS. */
	unsigned long long mftEntryNumber = 0;
	unsigned short int mftSequenceNumber = 0;
	/*! Nature déduite de la référence : "NTFS", "FAT" ou "Network/special item". */
	std::wstring mftNote;
	std::wstring longName = L"";
	std::wstring localizedName = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	* @param is_zip est un booléen indiquant que l'objet est une archive compressée
	* @param is_file est un booléen indiquant que l'objet est un fichier
	*/
	Beef0004(LPBYTE buffer, int _niveau, bool* is_zip, bool is_file);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CFSFolder and CFileSysItem object. Used for personalized name?
*/
struct Beef0006 : IExtensionBlock {
	std::wstring username = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0006(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CBitBucket object.
*/
struct Beef0008 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0008(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CBitBucket object. Used for original path?
*/
struct Beef0009 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0009(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to CMergedFolder object. Used for source count or sub shell item list?
*/
struct Beef000a : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef000a(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block  related to CControlPanelFolder object. Used for display name/CPL category?
*/
struct Beef000c : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef000c(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef000e : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block"; //!< message à afficher dans le json
	std::wstring guid = L"";//!< Identifiant GUID
	std::wstring identifier = L"";//!< com correspondant au GUID
	std::vector<std::unique_ptr<IExtensionBlock>> extensionblocks; //!< tableau d'extension blocks
	std::vector<SPS> SPSs; //! tableau de SPS
	std::vector<std::unique_ptr<IShellItem>> ishellitems;//!< tableau de shellitems

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef000e(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0010 : IExtensionBlock {
	SPS sps;

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0010(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0013 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0013(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! The extension block has seen to be used with the CUri class identifier which is the GUID "df2fce13-25ec-45bb-9d4c-cecd47c2430c". The CUri data could be a Vista and/or MSIE 7 specific extension.
*/
struct Beef0014 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0014(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0016 : IExtensionBlock {
	std::wstring value = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0016(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*!  Extension block  related to Shell item from Windows 7 BagMRU (Search Home).
*/
struct Beef0017 : IExtensionBlock {
	std::wstring message = L"Unsupported Extension block";//!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0017(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block seen in
* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderTypes\\{0B2BAAEB-0042-4DCA-AA4D-3EE8648D03E5}`
*
* Le chemin est en litteral (accents graves) : hors de ce cadre, doxygen lit
* « \\{ » comme une ouverture de groupe de membres, jamais refermee.
*/
struct Beef0019 : IExtensionBlock {
	std::wstring guid1 = L""; //!< identifiant GUID
	std::wstring identifier1 = L"";//!< nom correspondant au GUID
	std::wstring guid2 = L"";//!< identifiant GUID
	std::wstring identifier2 = L"";//!< nom correspondant au GUID

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0019(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001a : IExtensionBlock {
	std::wstring fileDocumentTypeString = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef001a(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001b : IExtensionBlock {
	std::wstring fileDocumentTypeString = L""; //!< chaîne indiquant le type de document

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef001b(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001d : IExtensionBlock {
	std::wstring executable = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef001d(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef001e : IExtensionBlock {
	std::wstring pinType = L"";

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef001e(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0021 : IExtensionBlock {
	SPS sps;  //!< un objet SPS

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0021(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0024 : IExtensionBlock {
	SPS sps;  //!< un objet SPS

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0024(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0025 : IExtensionBlock {
	FILETIME filetime1 = { 0 }; //!< date au format filetime
	FILETIME filetime2 = { 0 };//!< date  au format filetime

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0025(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0026 : IExtensionBlock {
	FILETIME ctimeUtc = { 0 }; //!< date de création
	FILETIME ctime = { 0 };//!< date de création au format UTC
	FILETIME mtimeUtc = { 0 };//!< date de modification
	FILETIME mtime = { 0 };//!< date de modification au format UTC
	FILETIME atimeUtc = { 0 };//!< date d'accès
	FILETIME atime = { 0 };//!< date d'accès au format UTC
	std::unique_ptr<IdList> idlist;//pointeur vers une liste de shell item (idlist)
	std::unique_ptr<IShellItem> shellitem;//pointeur vers un shelitem
	std::unique_ptr<SPS> sps;//pointeur vers un SPS

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0026(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
struct Beef0027 : IExtensionBlock {
	SPS sps; //!< un objet SPS

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0027(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Extension block related to unknown.
*/
/*! Bloc d'extension de signature non reconnue.
*
*  POURQUOI CETTE CLASSE. La fabrique se contentait d'écrire le dump dans le
*  JOURNAL et n'ajoutait RIEN à la liste des blocs : un bloc d'extension inconnu
*  était donc absent du JSON, et invisible sauf à relancer la collecte avec
*  `--loglevel=2`. Au niveau de journalisation par défaut, la donnée était
*  perdue sans laisser de trace.
*
*  Un objet dont on ne sait pas lire la structure doit rendre ses OCTETS : c'est
*  la seule façon qu'un analyste puisse le décoder plus tard, et la seule qui
*  distingue « WAC ne sait pas décoder ceci » de « il n'y avait rien ». C'est ce
*  que fait déjà `UnknownShellItem` ; cette classe rétablit la symétrie.
*/
struct BeefUnknown : IExtensionBlock {
	std::wstring data;        //!< contenu brut du bloc, en hexadécimal
	unsigned short size = 0;  //!< taille annoncée par le bloc

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'extension block
	* @param _niveau niveau dans l'arborescence, pour la mise en forme du json
	*/
	BeefUnknown(LPBYTE buffer, int _niveau);

	//! conversion de l'objet au format json
	Json toJson() override;
};

struct Beef0029 : IExtensionBlock {
	std::wstring message = L"The purpose of this extension block is unknown"; //!< message à afficher dans le json

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie
	*        d'un ZIP a un format propre, qui ne se devine pas depuis l'élément
	*/
	Beef0029(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/********************************************************************************************************************
* shell items
*********************************************************************************************************************/

/*! Volume Shell Item
*/
struct VolumeShellItem : IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	ShellVolumeFlags flags = { 0 }; //!< drapeaux correspondant aux options du type de volume flags
	std::wstring name = L""; //!< nom du volume
	std::wstring guid = L""; //!< GUID du volume
	std::wstring identifier = L""; //!< nom associé au GUID

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param type_char est le type d'objet au format character
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	VolumeShellItem(LPBYTE buffer, unsigned char type_char, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

/*! Control panel Shell Item
*/
struct ControlPanel : IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L""; //!< nom associé au GUID
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau d'Extension Block


	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param itemSize est la taille totale de l'objet
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	ControlPanel(LPBYTE buffer, unsigned short int itemSize, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Control Panel Category Shell Item
*/
struct ControlPanelCategory :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring id = L""; //!< identifiant
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau d'Extension Block


	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	ControlPanelCategory(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Retourne le type de valeur de la SPSVALUE à partir du code hexa
*/
std::wstring getType(unsigned int type);

/*!  Retourne le valeur de la SPSVALUE à partir de son type
*/
/*! Lit une valeur typée d'un property store.
*
* @param buffer début de l'entrée
* @param pos position de lecture dans l'entrée, avancée au fil du décodage
* @param valueType type VT_ de la valeur
* @param niveau profondeur, pour la mise en forme
* @param tailleEntree taille totale de l'entrée, utilisée pour restituer les
*        octets bruts quand le type n'est pas décodé. Zéro si elle n'est pas
*        connue de l'appelant : la valeur ressort alors sans dump.
* @param typeNonDecode mis à vrai si le type n'a pas pu être décodé. L'appelant
*        doit alors arrêter son parcours quand la taille de l'entrée n'est pas
*        annoncée, sans quoi l'entrée suivante serait lue au mauvais endroit.
* @return la valeur, ou un objet décrivant le type non pris en charge
*/
Json getValue(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int niveau,
              unsigned int tailleEntree = 0, bool* typeNonDecode = nullptr);

/*! Structure définissant le format d'un Property à l’intérieur des UserPropertyView
*/
struct Property {
	int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	unsigned int id = 0; //!< identifiant de la property
	unsigned short int type = 0; //!< type de la property
	unsigned int size = 0; //!< taille de la property
	/*! Vrai si le type de la valeur n'a pas pu être décodé.
	*
	* La taille d'une `Property` n'est pas annoncée : elle se DÉDUIT de
	* l'avancement du décodage. Un type inconnu laisse donc la position là où
	* elle était, et la propriété suivante serait lue au mauvais endroit —
	* produisant des propriétés d'apparence normale mais fausses. Les boucles
	* qui enchaînent les propriétés s'arrêtent sur ce drapeau : mieux vaut une
	* liste tronquée et signalée qu'une liste complète et inventée. */
	bool typeNonDecode = false;
	std::wstring guid = L""; //! identifiant GUID
	std::wstring FriendlyName = L""; //!< nom associé au guid
	Json value = Json::str(L"");//!< valeur de la property
	
	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	Property(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

/*! Structure définissant le format d'un UserPropertyView de signature 0xC01
*/
struct UserPropertyView0xC01 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring folder = L""; //!< nom du repertoire
	std::wstring fullurl = L""; //! url correspondante

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UserPropertyView0xC01(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();


};

/*! Structure définissant le format d'un UserPropertyView de type 0x23febee
*/
struct UserPropertyView0x23febbee : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring guid = L""; //!< identifiant GUID
	std::wstring FriendlyName = L""; //!< nom associé au GUID

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UserPropertyView0x23febbee(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

/*! Structure définissant le format d'un UserPropertyView de type 0x7192006
*/
struct UserPropertyView0x07192006 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	FILETIME modified = { 0 }; //!< date de modification
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME created = { 0 }; //!< date de création
	FILETIME createdUtc = { 0 }; //!< date de création au format UTC
	std::wstring folderName1 = L""; //!< nom du repertoire
	std::wstring folderName2 = L""; //!< nom du repertoire
	std::wstring folderIdentifier = L""; //!< identifiant du repertoire
	std::wstring guidClass = L""; //!< identifiant GUID de la classe
	std::wstring FriendlyName = L""; //!< nom associé au GUID de la classe
	std::vector<Property> properties; //!< Tableau de Property

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UserPropertyView0x07192006(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

};

/*! Structure définissant le format d'un UserPropertyView de type 0x10312005
*/
struct UserPropertyView0x10312005 : UserPropertyViewDelegate {
	unsigned int niveau = 0;//!< hiérarchie dans l'arbre des IshellItem, utiliser pour la mise en forme json
	std::wstring name = L"";//!< nom  de la propriété
	std::wstring identifier = L""; //!< identifiant de la propriété
	std::wstring filesystem = L"";//!< nom du système de fichier
	std::wstring guidClass = L""; //!< identifiant GUID de classe
	std::wstring FriendlyName = L""; //!< nom associé au GUID de classe
	std::vector<std::wstring> guidstrings; //!< tableau de GUID
	std::vector<Property> properties;//!< tableau de Property

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UserPropertyView0x10312005(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un UserPropertyView shell item
*/
struct UsersPropertyView :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	unsigned short int totalsize = 0; //!< taille totale de l’objet
	unsigned short int dataSize = 0; //!< taille des données
	unsigned int signature = 0; //!< signature de l"objet
	unsigned short int SPSDataSize = 0; //!< taille des données SPS
	unsigned short int identifierSize = 0;//!< taille de l'identifier
	unsigned int dataOffset = 0; //!< Offset des données
	unsigned short int extensionOffset = 0; //!< Offset des extension blocks
	unsigned short int spsOffset = 0;//!< offset des SPS
	std::vector<SPS> SPSs; //!< tableau contenant les SPS
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau contenant les extension blocks
	/*! Nature de l'item, déduite de sa signature.
	*
	* La signature ne choisit pas seulement un décodeur : chez libyal (libfwsi)
	* elle IDENTIFIE le type. Deux des signatures traitées ici ne désignent pas
	* des « users property view » mais des périphériques MTP — volume et entrée
	* de fichier —, soit la trace qu'un téléphone ou un appareil photo a été
	* branché et parcouru. Le nom de classe générique masquait ce fait. */
	std::wstring itemType;
	/*! Identifiant 32 bits des signatures qui en portent un (identifiant de
	* 4 octets), relevé comme le fait libfwsi. */
	unsigned int identifier32 = 0;
	bool identifier32Lu = false;
	// `guid` et `identifier` retires : jamais renseignes par le constructeur.
	// L'identification passe par la signature, `itemType` et le delegue.
	std::unique_ptr<UserPropertyViewDelegate> delegate; //! UsersPropertyView déléguée

	/*! Contenu brut, en hexadécimal, quand la signature n'est pas reconnue.
	*
	* MESURÉ SUR UNE COLLECTE RÉELLE (2026-09-15) : 75 des 89
	* `USERS_PROPERTY_VIEW` portaient une signature inconnue (`0xc1ec0c9`) et
	* ressortaient avec pour tout contenu leur type et cette signature. Le dump
	* existait, mais n'allait que dans le JOURNAL : au niveau de journalisation
	* par défaut, 75 objets disparaissaient donc entièrement de la sortie.
	* Cf. le barème de qualité : un objet non décodé rend ses octets. */
	std::wstring data;

	/*! constructeur par défaut
	*/
	UsersPropertyView() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UsersPropertyView(LPBYTE buffer, int _niveau);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un RootFolder Shell Item
*/
struct RootFolder :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring sortIndex = L""; //!w index de tri
	std::wstring guid = L"";//!< identifiant GUID
	std::wstring identifier = L"";//!< nom associé au GUID
	std::vector<SPS> SPSs; //!< tableau de SPS
	//std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; // TODO des extension blocks sont présent avec le type GUID mais on retrouve les même datas dans les SPS donc on passe

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	RootFolder(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un Network Shell Item
*/
struct NetworkShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring subtypename = L"";//!< nom du sous-type
	std::wstring location = L"";//!< emplacement 
	std::wstring description = L"";//!< description de l'objet
	std::wstring comments = L"";//!< commentaires de l’objet
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	NetworkShellItem(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un Archive File Shell Item
*/
struct ArchiveFileContent :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	// `subtypename` et `location` retires : declares ici mais jamais renseignes
	// (ils appartiennent a NetworkShellItem, qui porte les memes noms).
	std::wstring name = L"";//!< nom de l'archive
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	ArchiveFileContent(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un URL Shell Item
*/
struct URIShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring uri = L""; //!< URI 

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	URIShellItem(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un File Entry Shell Item
*/
struct FileEntryShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	unsigned short int fsFileSize = 0; //!< taille du fichier
	FILETIME fsFileModificationUtc = { 0 };//!< date de modification UTC
	FILETIME fsFileModification = { 0 };//!< date de modification
	std::wstring fsPrimaryName = L"";//!< nom primaire
	FsFlags fsFlags = { 0 }; //!< drapeaux décrivant les options de l'entrée
	FileAttributes fsFileAttributes = { 0 }; //!< drapeaux décrivant les attributs de l'entrée
	std::vector<std::unique_ptr<IExtensionBlock>> extensionBlocks; //!< tableau contenant les extension blocks

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param itemSize est la taille de l'objet
	* @param shell_item_type_char est le type de shell item au format character
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	FileEntryShellItem(LPBYTE buffer, unsigned short int itemSize, unsigned char shell_item_type_char, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un Users Files Folder Shell Item
*/
struct UsersFilesFolder :IShellItem {
public:
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring primaryName = L"";//!< nom primaire
	FILETIME modifiedUtc = { 0 };//!< date de modification au format UTC
	FILETIME modified = { 0 };//!< date de modification
	std::unique_ptr<IExtensionBlock> extensionBlock; //!< block d'extension

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UsersFilesFolder(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un Favorites Shell Item
*/

/*! Shell item de type « favori ».
*
* NON COUVERT PAR LES TESTS (vérifié le 2026-09-15) : la VM de validation ne
* produit aucun shell item de ce type, donc le parsing n'est jamais exercé.
* Pertinence forensique élevée s'il est rencontré — un favori traduit une
* ressource délibérément marquée par l'utilisateur, donc une intention — d'où
* l'intérêt de le valider plutôt que de le laisser en l'état.
* Pour l'exercer : shellbags issus d'une session interactive ayant navigué dans
* les Favoris, ou jeu de ruches de référence.
*/
struct FavoriteShellitem :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	UsersPropertyView UPV; //! Objet UsersPropertyView

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	FavoriteShellitem(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};

/*! Structure définissant le format d'un UNKNOWN Shell Item
*/
/*! Shell item d'un type reconnu par sa signature, mais sans décodeur dédié.
*
*  POURQUOI. L'identification d'un shell item ne se fait pas qu'avec l'octet de
*  classe : plusieurs types se reconnaissent à une signature placée dans les
*  données (libfwsi_item.c essaie chaque décodeur, et chacun vérifie la sienne).
*  WAC ne testait que l'octet de classe, si bien que six types documentés
*  tombaient dans « UNKNOWN » : graveur de CD, dossier de jeux, site web,
*  fichier Acronis, fichier .cpl du panneau de configuration.
*
*  Les nommer vaut mieux que « inconnu », même sans décoder tous leurs champs :
*  l'analyste sait ce qu'il a sous les yeux, et les octets restent joints.
*/
struct TypedShellItem : IShellItem {
	bool isPresent = false;   //!< présence, pour le formatage du json
	std::wstring typeName;    //!< type reconnu, ex. "CD Burn", "Game Folder"
	std::wstring data;        //!< contenu brut, en hexadécimal

	/*! constructeur
	* @param buffer données de l'item
	* @param taille taille de l'item
	* @param _typeName libellé du type reconnu
	* @param _niveau niveau dans l'arborescence
	*/
	TypedShellItem(LPBYTE buffer, unsigned short taille, const std::wstring& _typeName,
	               int _niveau);

	Json toJson() override;
};

/*! Dossier délégué (« delegate folder »).
*
*  Ce conteneur enveloppe UN SHELL ITEM COMPLET, placé à l'offset 6, et se
*  reconnaît au GUID de délégation inscrit 32 octets avant la fin
*  ({5E591A74-DF96-48D3-8D67-1733BCEE28BA}). Le GUID de la classe qui délègue
*  occupe les 16 derniers octets.
*
*  Il n'était pas reconnu du tout : l'item entier — donc le shell item qu'il
*  contient, avec son chemin, ses dates et ses property stores — était réduit à
*  un objet « UNKNOWN ». C'est le type manquant qui coûtait le plus, parce qu'il
*  est courant dans les shellbags et qu'il masque un item décodable.
*/
struct DelegateFolder : IShellItem {
	bool isPresent = false;                      //!< présence, pour le json
	std::wstring classGuid;                      //!< GUID de la classe déléguée
	std::wstring classFriendlyName;               //!< libellé de ce GUID
	std::unique_ptr<IShellItem> innerItem;        //!< shell item imbriqué
	std::wstring data;                            //!< contenu brut si non décodé

	/*! constructeur
	* @param buffer données de l'item
	* @param taille taille de l'item
	* @param _niveau niveau dans l'arborescence
	*/
	DelegateFolder(LPBYTE buffer, unsigned short taille, int _niveau);

	Json toJson() override;
};

struct UnknownShellItem :IShellItem {
	bool isPresent = false; //!< l'objet est-il présent, utilisé pour le formatage du json
	std::wstring data = L"";//!< chaîne contenant les données

	/*! constructeur
	* @param buffer en entrée contient les bits à parser de l'item
	* @param _niveau est le niveau dans l'arborescence d'élément utilisé pour la mise en forme du fichier json de sortie

	*/
	UnknownShellItem(LPBYTE buffer, int _niveau);
	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() override;

};



#pragma once

/*  recent_docs.h — DOCUMENTS RÉCENTS : les raccourcis .lnk de `\Recent`.
 *
 *  CE QUE L'ARTEFACT PROUVE. Windows crée un raccourci dans
 *  `%AppData%\Microsoft\Windows\Recent` chaque fois qu'un document est ouvert.
 *  Le raccourci survit à la suppression du document et conserve le chemin
 *  d'origine, la taille et les horodatages de la CIBLE au moment de l'ouverture :
 *  il atteste donc qu'un fichier a existé et a été ouvert, même s'il n'est plus
 *  sur le disque — y compris sur un volume amovible depuis longtemps débranché.
 *
 *  DEUX JEUX D'HORODATAGES, À NE PAS CONFONDRE
 *    - `target*` : dates de la cible, recopiées dans l'en-tête du .lnk ;
 *    - `source*` : dates du fichier .lnk lui-même, c'est-à-dire l'instant de
 *      l'ouverture.
 *  Les premières datent le document, les secondes l'ACTIVITÉ de l'utilisateur.
 *
 *  PIÈGE HORAIRE. Les trois horodatages de l'en-tête .lnk (offsets 28, 36, 44)
 *  sont en UTC — MS-SHLLINK —, malgré des noms de champs qui ne le disent
 *  pas. Les traiter comme des heures locales décalait les dates de la valeur du
 *  fuseau, sans qu'aucun contrôle de format ne puisse le voir.
 *
 *  Le contenu structuré du raccourci (liste d'ID, blocs d'extension, propriétés)
 *  est analysé par `idList.h`.
 */

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>
#include <regex>
#include "tools.h"
#include "trans_id.h"
#include "idList.h"
#include "quickdigest5.h"

/* structure représentant un document récent
*/
struct RecentDoc {
public:
	// Contient des unique_ptr (via IdList) : type deplacable, non copiable.
	// La copie est interdite explicitement pour obtenir une erreur claire
	// au site fautif plutot qu'une erreur de template.
	RecentDoc(const RecentDoc&) = delete;
	RecentDoc& operator=(const RecentDoc&) = delete;
	RecentDoc(RecentDoc&&) = default;
	RecentDoc& operator=(RecentDoc&&) = default;

	std::wstring Sid = L""; //!< SID de l'utilisateur propriétaire de l'objet
	std::wstring path_original = L"";//!< chemin d'accès à l'objet sur le disque
	std::wstring path = L"";//!< chemin d'accès à l'objet dans le snapshot
	std::wstring md5Source=L""; //!< hash md5 du fichier source
	std::wstring target = L"";//!< chemin pour accéder à l'objet d'origine
	std::wstring md5Target=L""; //!< hash md5 du fichier target
	std::wstring description = L""; //!< description du recentDoc
	std::wstring relativePath = L"";//!< chemin relatif d'accès au fichier d'origine
	std::wstring workingDirectory = L"";//!< repertoire contenant le fichier d'origine
	std::wstring arguments = L"";//!< arguments du fichier d'origine 
	std::wstring iconLocation = L"";//!< chemin de l’icône représentatif du type de fichier si différent des icônes standards
	unsigned int fileSize = 0;//!< taille du fichier d'origine
	unsigned int iconIndex = 0;//! index de l’icône
	std::wstring commandOption = L"";//!< option d'ouverture du fichier d'origine
	GUID guid = { 0 }; //!< 
	FILETIME sourceCreated = { 0 }; //!< date de création du recentdoc
	FILETIME sourceCreatedUtc = { 0 };//!< date de création du recentdoc au format UTC
	FILETIME sourceModified = { 0 };//!< date de modification du recentdoc
	FILETIME sourceModifiedUtc = { 0 };//!< date de modification du recentdoc au format UTC
	FILETIME sourceAccessed = { 0 };//!< date d'accès du recentdoc
	FILETIME sourceAccessedUtc = { 0 };//!< date d'accès du recentdoc au format UTC
	FILETIME targetCreated = { 0 };//!< date de création du fichier d'origine
	FILETIME targetCreatedUtc = { 0 };//!< date de création du fichier d'origine au format UTC
	FILETIME targetModified = { 0 };//!< date de modification du fichier d'origine
	FILETIME targetModifiedUtc = { 0 };//!< date de modification du fichier d'origine au format UTC
	FILETIME targetAccessed = { 0 };//!< date d'accès au fichier d'origine
	FILETIME targetAccessedUtc = { 0 };//!< date d'accès au fichier d'origine au format UTC
	LinkFlags flags = { 0 };//!< attributs du recentDoc
	FileAttributes attributes = { 0 };//!< attributs du fichier d'origine
	std::wstring volumeDriveType = L""; //!< type de volume de disque
	std::wstring volumeSerial = L"";//!< numéro de série du volume
	std::wstring volumeLabel = L"";//!< label du volume
	std::wstring netName = L"";//!< nom du réseau
	std::wstring netDeviceName = L"";//!< nom du périphérique réseau
	std::wstring netProviderType = L"";//!< type de provider de réseau
	std::vector<IdList> idLists;//!< tableau contenant des Idlist 

	/*! Analyse un fichier LNK.
	*
	* La TAILLE est indispensable et manquait : sans elle, aucune lecture ne
	* pouvait être bornée, et les champs StringData — dont la longueur est
	* annoncée dans le fichier lui-même — étaient lus jusqu'au premier zéro
	* rencontré, donc potentiellement hors du tampon sur un raccourci tronqué ou
	* forgé.
	*
	* @param buffer contient les données à parser
	* @param taille taille du tampon, en octets
	*/
	void parseLNK(LPBYTE buffer, size_t taille);


	/*! constructeur à partir d'un fichier
	* @param _path contient le chemin vers le fichier à parser
	* @param _sid contient le SID de l'utilisateur propriétaire du fichier

	*/
	RecentDoc(std::filesystem::path _path, std::wstring _sid);

	/*! constructeur à partir d'un buffer
	* @param buffer contient les données à parser
	* @param size taille du tampon, en octets
	* @param _path contient le chemin vers le fichier contenant le buffer
	* @param _sid contient le SID de l'utilisateur propriétaire de la donnée

	*/
	RecentDoc(LPBYTE buffer, size_t size, std::wstring _path, std::wstring _sid);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson();

	/*liberation mémoire */
	void clear();
};

/*! structure contenant l'ensemble des objets
*/
struct RecentDocs {
	std::vector<RecentDoc> recentdocs; //!< tableau contenant l'ensemble des objets

	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/*liberation mémoire */
	void clear();

};
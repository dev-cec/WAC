#pragma once
#include <memory>

#include <iostream>
#include <cstdio>
#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <stdexcept>
#include "tools.h"
#include "idList.h"
#include "recent_docs.h"

////////////////////////////////////////////////////
// Documentation : https://binaryforay.blogspot.com/2016/02/jump-lists-in-depth-understand-format.html
// Documentation : https://github.com/libyal/dtformats/blob/main/documentation/Jump%20lists%20format.asciidoc
// Documentation : https://github.com/EricZimmerman/JumpList/blob/master/JumpList/Resources/AppIDs.txt
///////////////////////////////////////////////////

/*! Représente un objet représentant un objet Custom Destination Category
*/
struct CustomDestinationCategory {
	unsigned short int nameSize = 0; //!< taille du nom de la catégorie
	std::wstring name = L""; //!< nom de la catégorie
	unsigned int nbentries = 0; //!< nombre d'entrées dans la catégorie
	std::vector<RecentDoc> recentDocs; //!< tableau des recentDoc

	/*! Constructeur par défaut
	*/
	CustomDestinationCategory() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param buffersize en entrée contient la taille du buffer
	* @param _path est le chemin contenant les custom Destinations
	* @param _sid est le SID de l'utilisateur propriétaire du LNK

	*/
	CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid);

	/*! Destructeur virtuel.
	* `toJson()` est virtuelle : sans destructeur virtuel, détruire l'objet par
	* un pointeur de base serait un comportement indéfini. Il n'existe pas
	* encore de classe dérivée, mais la classe est déclarée polymorphe et doit
	* l'être complètement.
	*/
	virtual ~CustomDestinationCategory() = default;

	virtual Json toJson();

	void clear();
};

/*! Représente un objet représentant un objet Custom Destination
*/
struct CustomDestination {
	std::wstring Sid = L""; //!< SID de l'utilisateur propriétaire du custom Destination
	std::wstring SidName = L""; //!< nom de l'utilisateur propriétaire du custom Destination
	std::wstring application = L"";//!< nom de l'application liée au Custom Destination
	std::wstring path = L"";//!< Chemin du custom Destination dans la snapshot
	std::wstring pathOriginal = L"";//!< Chemin du custom Destination sur le disque
	unsigned int typeInt = 0;//!< type de custom Destination en entier
	std::wstring type = L"";//!< nom du type de Custom Destination
	/*! Catégorie du Custom Destination, absente si le fichier ne porte pas de lnk.
	*
	* POURQUOI UN `unique_ptr`. Le pointeur était nu et n'était libéré que par
	* `CustomDestination::clear()` — que rien n'appelait : `JumplistCustoms::clear()`
	* vide le vecteur, ce qui détruit les éléments sans passer par cette méthode.
	* Chaque Custom Destination fuyait donc sa catégorie entière, avec son
	* vecteur de `RecentDoc` et les listes d'ID qu'ils contiennent. La propriété
	* est désormais portée par le type. */
	std::unique_ptr<CustomDestinationCategory> categorie;
	FILETIME created = { 0 }; //!< date de création du fichier
	FILETIME createdUtc = { 0 }; //!< date de création du fichier au format utc
	FILETIME modified = { 0 };//!< date de modification  du fichier
	FILETIME modifiedUtc = { 0 };//!< date de modification du fichier au format utc
	FILETIME accessed = { 0 };//!< date d'accès du fichier
	FILETIME accessedUtc = { 0 };//!< date d'accès du fichier au format utc

	/*! constructeur par défaut
	*/
	CustomDestination() {};

	/*! constructeur
	* @param buffer en entrée contient les bits à parser des extensionblock
	* @param _path est le chemin contenant les Automatic Destinations
	* @param _sid est le SID de l'utilisateur propriétaire du LNK

	*/
	CustomDestination(std::filesystem::path _path, std::wstring _sid);

	/*! conversion de l'objet au format json
	* @param i nombre de tabulation nécessaire en début de ligne pour la mise en form json, permet l'indentation propre du json
	* @return wstring le code json
	*/
	Json toJson();

	/* liberation mémoire */
	void clear();
};

/*! Représente un objet représentant un objet Jumplist contenant les Custom Destinations
*/
struct JumplistCustoms {
	std::vector<CustomDestination> customDestinations; //!< tableau contenant les objets
	

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
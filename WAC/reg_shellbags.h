#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <fstream>
#include "tools.h"
#include "usb.h"
#include "idList.h"

/*! structure représentant un artefact Shellbag
*/
struct Shellbag {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int Parent = 0;//!< identifiant du Parent
	unsigned int niveau = 0;//! niveau de profondeur de l'arborescence utilisé pour la mise en forme du json
	std::wstring sid = L""; //!< Sid de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L""; //!< nom de l'utilisateur propriétaire de l'objet
	std::wstring source = L""; //!< origine de l'artefact
	std::vector<std::unique_ptr<IdList>> shellitems; //!< tableau de IdList
	std::vector<Shellbag> childs; //!< tableau contenant les shellbags enfant
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() const;


};

/*! structure contenant l'ensemble des artefacts
*/
struct Shellbags {
public:
	std::vector<Shellbag> shellbags;//!< tableau contenant les objets
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	/*! Nombre de shellbags parcourus, pour la progression.
	* `parse` étant récursif, le total ne peut pas être connu d'avance : on
	* affiche donc un compteur cumulatif plutôt qu'un pourcentage. */
	unsigned long long nbParcourus = 0;


	/*! Fonction permettant de parser les objets
	* @param _niveau contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0);

	/*! Fonction permettant de parser une clé de la base de registre
	* @param hKey contient la clé à parser
	* @param sid contient le sid de l'utilisateur propriétaire de la clé
	* @param source contient l'origine de l'artefact
	* @param out reçoit les shellbags parsés
	* @param niveau profondeur dans l'arborescence, utilisée pour la mise en forme du fichier json de sortie
	* @param _Parentiszip sit le père de l'artefact est un fichier zip
	* @param Parent est le shellbag Parent si present
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Shellbag>* out, unsigned int niveau, bool _Parentiszip, unsigned int Parent = NULL);

	/*! conversion de l'objet au format json
	*/
	virtual HRESULT toJson();


	/*! Libere la memoire des artefacts (les unique_ptr sont detruits). */
	void clear();
};
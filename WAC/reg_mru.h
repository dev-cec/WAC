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

/* structure représentant l'artefact Most REcently Used
*/
struct Mru {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie
	std::wstring extension = L""; //!< extension du fichier
	std::wstring sid = L""; //!<SID de l'utilisateur ayant ouvert le fichier
	std::wstring sidName = L""; //!<nom de l'utilisateur ayant ouvert le fichier
	std::wstring source = L"";//!< provient de "OpenSavePidlMRU " ou "OpenSaveMRU"
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC
	std::vector<std::unique_ptr<IdList>> shellitems; //!< tableau contenant les Idlist

	/*! conversion de l'objet au format json */
	Json toJson() const;

};

/* Structure contenant l'ensemble des artefacts
*/
struct Mrus {
public:
	std::vector<Mru> mrus;
	/*! Nombre d'entrées parcourues, pour la progression : `parse` étant
	* récursif, le total n'est pas connu d'avance. */
	unsigned long long nbParcourus = 0; //!< contient l'ensemble des objets
	unsigned int niveau = 0; //!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie

	/*! Fonction permettant de parser les objets
	* @param conf contient les paramètres de l'application issue des paramètres de la ligne de commande
	* param _niveau est utilisé pour la mie en forme de la hiérarchie des objet dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0);

	/*! Fonction permettant de parser une clé MRUListEx
	* @param hKey contient le clé de la base de registre à parser
	* @param sid contient le sid de l'utilisateur
	* @param source contient l'origine de l’artefact (provient de "OpenSavePidlMRU " ou "OpenSaveMRU")
	* @param out reçoit les MRU parsés
	* @param niveau est utilisé par la mise en forme du json de sortie
	* @param _Parentiszip indique le Parent est un fichier zip
	* @param extension contient l'extension de fichier
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<Mru>* out, unsigned int niveau, bool _Parentiszip, std::wstring extension);

	/*! conversion de l'objet au format json
	*/

	virtual HRESULT toJson();


	/*! Libere la memoire des artefacts (les unique_ptr sont detruits). */
	void clear();
};
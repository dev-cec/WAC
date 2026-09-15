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



/*! structure représentant l'artefact MRU Application
*/
struct MruApp {
public:
	unsigned int id = 0; //!< identifiant de l'objet
	unsigned int niveau = 0;//!< profondeur de l’arborescence, utilisé pour la mise en forme de json de sortie
	std::wstring name = L"";//!w nom de l'application
	std::wstring sid = L"";//!< sid de l'utilisateur propriétaire de l'objet
	std::wstring sidName = L"";//!< nom de l'utilisateur propriétaire de l'objet
	std::wstring source = L"";//!< origine de l'artefact
	FILETIME lastWriteTime = { 0 }; //!< dernière modification de la clé
	FILETIME lastWriteTimeUtc = { 0 }; //!< dernière modification de la clé au format UTC
	std::vector<std::unique_ptr<IdList>> shellitems;//!< tableau de IdList

	/*! conversion de l'objet au format json */
	Json toJson() const;


};

/* Structure contenant l'ensemble des artefacts
*/
struct MruApps {
public:
	std::vector<MruApp> mruApps;
	/*! Nombre d'entrées parcourues, pour la progression : `parse` étant
	* récursif, le total n'est pas connu d'avance. */
	unsigned long long nbParcourus = 0; //!< contient l'ensemble des objets
	unsigned int niveau = 0;//!< profondeur dans l'arborescence utilisé pour la mise en forme du fichier json de sortie

	/*! Fonction permettant de parser les objets
	* @param _niveau profondeur dans l'arborescence, utilisée pour la mise en
	*        forme de la hiérarchie des objets dans le json de sortie
	*/
	HRESULT getData(int _niveau = 0);

	/*! Fonction permettant de parser une clé de la base de registre
	* @param hKey contient la clé à parser
	* @param sid contient le sid de l'utilisateur propriétaire de la clé
	* @param source contient l'origine de l'artefact
	* @param out reçoit les MRU parsés
	* @param niveau profondeur dans l'arborescence, utilisée pour la mise en forme du fichier json de sortie
	* @param _Parentiszip sit le père de l'artefact est un fichier zip
	*/
	HRESULT parse(ORHKEY hKey, std::wstring sid, std::wstring source, std::vector<MruApp>* out, unsigned int niveau, bool _Parentiszip);

	/*! conversion de l'objet au format json
	*/
	virtual HRESULT toJson();


	/*! Libere la memoire des artefacts (les unique_ptr sont detruits). */
	void clear();
};
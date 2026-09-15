#pragma once
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <offreg.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include "tools.h"
#include "usb.h"
#include "users.h"

/*!structure représentant un artefact Background Activity Monitor (BAM)
*/
struct Bam {
public:
	std::wstring sid = L""; //!< SID de l'utilisateur
	std::wstring sidName = L""; //!< nom de l'utilisateur
	std::wstring name = L"";//!< nom de l'objet
	std::wstring executionTime = L"";//!< date de création de l'objet
	std::wstring executionTimeUtc = L"";//!< date de création de l'objet au format UTC

	/*! Constructeur
	* @param donnees contient timestamps à transformer en datetime
	* @param nomValeur contient le nom de la clé de registre contenant le BAM
	* @param psid contient le SID de l'utilisateur
	*/
	Bam(LPBYTE donnees, std::wstring nomValeur, std::wstring psid);

	/*! conversion de l'objet au format json
	* @return wstring le code json
	*/
	Json toJson() const;

	/* liberation mémoire */
	void clear();
};

/*! *structure contenant l'ensemble des BAM
*/
struct Bams {
public:
	std::vector<Bam> bams;//!< tableau contenant tous les objets
	
	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();

	/*! conversion de l'objet au format json */
	HRESULT toJson();

	/* liberation mémoire */
	void clear();
};
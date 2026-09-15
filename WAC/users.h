#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <offreg.h>
#include "tools.h"
#include "trans_id.h"
#include "json.h"

/*! Comptes locaux de la machine examinée, lus dans la ruche SAM.
*
*  POURQUOI LA RUCHE PLUTÔT QUE netapi32 (doc §9.4ter). La version d'origine
*  appelait `NetUserEnum` puis `NetUserGetInfo` pour chaque compte : autant
*  d'allers-retours RPC vers LSASS, plus une lecture du registre vivant par
*  utilisateur. La même information est écrite dans
*  `SAM\Domains\Account\Users`, désormais extraite en brut.
*
*  CE QUE LA RUCHE AJOUTE
*    - `LastWriteTime` de la clé du compte : quand le compte a été créé ou
*      modifié — donnée qu'aucune API de netapi32 ne rend ;
*    - les comptes que LSASS refuserait d'énumérer si le service répondait mal ;
*    - une lecture qui reste possible sur une image morte.
*
*  STRUCTURE DU SAM
*  Chaque compte est une sous-clé nommée par son RID en hexadécimal sur 8
*  chiffres, portant deux valeurs binaires :
*    - `F` : champs de taille fixe — horodatages, RID, drapeaux de compte,
*      compteurs de connexion (offsets documentés ci-dessous) ;
*    - `V` : champs de taille variable — nom, nom complet, commentaire, chemins,
*      précédés d'une table d'offsets relatifs à 0xCC.
*  Les empreintes de mots de passe (`V`, offsets 0x9C et 0xA8) sont
*  DÉLIBÉRÉMENT IGNORÉES : elles n'établissent aucun fait utile à l'enquête et
*  leur présence dans un fichier de sortie créerait un risque sans contrepartie.
*
*  Le SID complet est recomposé à partir du SID de machine, lu dans la valeur
*  `V` de `SAM\Domains\Account`, et du RID du compte.
*/
struct User {
	std::wstring name;                   //!< nom de connexion
	std::wstring fullName;               //!< nom complet
	std::wstring comment;                //!< commentaire du compte
	std::wstring SID;                    //!< SID complet, recomposé
	DWORD        rid = 0;                //!< identifiant relatif
	std::wstring profile;                //!< chemin du profil (ProfileList)
	DWORD        flags = 0;              //!< drapeaux de compte (ACB)
	std::wstring flagsLibelles;          //!< drapeaux décomposés, lisibles
	unsigned     logonCount = 0;         //!< nombre de connexions réussies
	unsigned     badPasswordCount = 0;   //!< nombre d'échecs d'authentification
	FILETIME     lastLogonUtc = { 0, 0 };        //!< dernière connexion
	FILETIME     passwordLastSetUtc = { 0, 0 };  //!< dernier changement de mot de passe
	FILETIME     accountExpiresUtc = { 0, 0 };   //!< expiration du compte
	FILETIME     lastBadPasswordUtc = { 0, 0 };  //!< dernier échec d'authentification
	FILETIME     keyLastWriteUtc = { 0, 0 };     //!< création / modification du compte

	//! Conversion de l'objet au format JSON
	Json toJson() const;

	//! Libération mémoire
	void clear();
};

struct Users {
	std::vector<User> users;   //!< tableau contenant tous les comptes locaux

	/*! Relève les comptes dans la ruche SAM extraite.
	* Nécessite que `ExtractHivesRaw()` ait extrait `\Windows\System32\config\SAM`.
	*/
	HRESULT getData();

	//! Conversion de l'objet au format JSON
	HRESULT toJson();

	//! Libération mémoire
	void clear();
};

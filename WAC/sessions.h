#pragma once

#include <iostream>
#include <filesystem>
#include <fstream>
#include <windows.h>
#include <Sddl.h>
#include <wtsapi32.h>
#include <winternl.h>
#define _NTDEF_ //pour éviter les conflits de type entre ntsecapi.h et winternl.h
#include <ntsecapi.h>
#include "tools.h"
#include "json.h"
#include "trans_id.h"



/*! structure contenant les informations d'une session
*/
struct Session {

	FILETIME startTime = { 0 };
	FILETIME startTimeUtc = { 0 };
	std::wstring authenticationPackage = L"";
	std::wstring logonName = L"";
	std::wstring logonDomainName = L"";
	std::wstring logonTypeName = L"";
	ULONG logonType = 0;
	/*! SID du compte, converti en TEXTE dès la lecture.
	*
	* POURQUOI PAS UN `PSID`. Le membre était un pointeur copié depuis la
	* structure rendue par `LsaGetLogonSessionData`, laquelle est libérée par
	* `LsaFreeReturnBuffer` à la fin du constructeur. `toJson()` s'exécutant plus
	* tard, il lisait donc de la mémoire déjà rendue : un SID juste par hasard,
	* aussi longtemps que le bloc n'avait pas été réutilisé. La conversion est
	* faite pendant que la structure est encore valide. */
	std::wstring sid;
	/*! Rôle de la session quand son LUID est une valeur réservée de Windows.
	*
	* Les LUID 0x3E7 (999), 0x3E6 (998), 0x3E5 (997) et 0x3E4 (996) désignent
	* toujours les mêmes sessions de service. Les nommer évite que l'analyste
	* prenne leur `LogonType` nul — légitime pour elles — pour une lecture
	* manquée. */
	std::wstring roleConnu;
	LONGLONG sessionId = 0;
	/*! Constructeur
	* @param id est l'id de session
	*/
	Session(LUID* id);

	/*! conversion de l'objet au format json
	*/
	Json toJson() const;

	/* liberation mémoire */
	void clear();
};

/*! structure contenant les artefacts
*/
struct Sessions {
	std::vector<Session> sessions; //!< tableau contenant tout les Session


	/*! Fonction permettant de parser les objets
	*/
	HRESULT getData();
	/*! conversion de l'objet au format json
	*/
	HRESULT toJson();

	/* liberation mémoire */
	void clear();

};
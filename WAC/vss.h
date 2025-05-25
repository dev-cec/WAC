#pragma once
#include <string>
#include "stdafx.h"



/*! lib�re une interface si son identifiant n'est pas NULL
* @param unkn identifiant de l'interface
* @return void
*/
void ReleaseInterface(IVssBackupComponents* pBackup);

/*! Cr�er un snapshot temporaire et cr�er un lien symbolique pour y acc�der
* @param mountpoint point de montage du snapshots
* @param snapshotId utiliser pour r�cup�rer l'id du snapshot cr�er
* @param pBackup utilis� pour r�cup�rer une instance de l'interface IVssBackupComponents utilis�e par un demandeur pour interroger les r�dacteurs sur les status de fichiers et pour ex�cuter des op�rations de sauvegarde/restauration.
* @return HRESULT si l'op�ration r�ussi retourne ERROR_SUCCESS sinon un code d'erreur
*/
HRESULT GetSnapshots(VSS_ID* snapshotSetId, IVssBackupComponents* pBackup);

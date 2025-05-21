#pragma once
#include <string>
#include "stdafx.h"



/*! libère une interface si son identifiant n'est pas NULL
* @param unkn identifiant de l'interface
* @return void
*/
void ReleaseInterface(IVssBackupComponents* pBackup);

/*! Créer un snapshot temporaire et créer un lien symbolique pour y accéder
* @param mountpoint point de montage du snapshots
* @param snapshotId utiliser pour récupérer l'id du snapshot créer
* @param pBackup utilisé pour récupérer une instance de l'interface IVssBackupComponents utilisée par un demandeur pour interroger les rédacteurs sur les status de fichiers et pour exécuter des opérations de sauvegarde/restauration.
* @return HRESULT si l'opération réussi retourne ERROR_SUCCESS sinon un code d'erreur
*/
HRESULT GetSnapshots(VSS_ID* snapshotSetId, IVssBackupComponents* pBackup);

#include <iostream>
#include <string>
#include <windows.h>
#include <strsafe.h>
#include "vss.h"
#include "tools.h"

void ReleaseInterface(IVssBackupComponents* pBackup)
{

	if (pBackup != NULL)
		ReleaseInterface(pBackup);

}

HRESULT GetSnapshots(VSS_ID* snapshotSetId, IVssBackupComponents* pBackup)
{
	TCHAR volumeName[MAX_PATH] = TEXT("c:\\");
	// declare all the interfaces used in this program.

	IVssAsync* pAsync = NULL;
	IVssAsync* pPrepare = NULL;

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️ SNAPSHOTS");
	log(0, L"*******************************************************************************************************************");

	HRESULT result = CreateVssBackupComponents(&pBackup);
	if (result != S_OK) {
		printError(result);
		log(1, L"🔥 CreateVssBackupComponents", result);
		ReleaseInterface(pBackup);
		return S_FALSE;
	}
	if (result == S_OK)
	{
		// Initialize for backup
		result = pBackup->InitializeForBackup();
		if (result != S_OK) {
			printError(result);
			log(1, L"🔥 InitializeForBackup", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		// set the context 
		result = pBackup->SetContext(VSS_CTX_BACKUP); // Specifies an auto-release, non persistent shadow copy created without writer involvement.

		if (result != S_OK) {
			printError(result);
			log(1, L"🔥 SetContext", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		result = pBackup->StartSnapshotSet(snapshotSetId);
		if (result != S_OK) {
			printError(result);
			log(1, L"🔥 StartSnapshotSet", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		else
		{
			result = pBackup->AddToSnapshotSet(volumeName, GUID_NULL, snapshotSetId);
			if (result != S_OK) {
				printError(result);
				log(1, L"🔥 AddToSnapshotSet", result);
				ReleaseInterface(pBackup);
				return S_FALSE;
			}
			else
			{
				//
				// Configure the backup operation for Copy with no backup history
				//
				result = pBackup->SetBackupState(false, false, VSS_BT_COPY);
				if (result != S_OK) {
					printError(result);
					log(1, L"🔥 SetBackupState", result);
					ReleaseInterface(pBackup);
					return S_FALSE;
				}
				else
				{
					//
					// Make VSS generate a PrepareForBackup event
					//
					result = pBackup->PrepareForBackup(&pPrepare);
					if (result != S_OK) {
						printError(result);
						log(1, L"🔥 PrepareForBackup", result);
						ReleaseInterface(pBackup);
						return S_FALSE;
					}
					else
					{
						result = pPrepare->Wait();
						if (result != S_OK) {
							printError(result);
							log(1, L"🔥 pPrepare Wait", result);
							ReleaseInterface(pBackup);
							return S_FALSE;
						}
						else
						{
							//
							// Commit all snapshots in this set
							//
							IVssAsync* pDoShadowCopy = NULL;
							result = pBackup->DoSnapshotSet(&pDoShadowCopy);
							if (result != S_OK) {
								printError(result);
								log(1, L"🔥 DoSnapshotSet", result);
								ReleaseInterface(pBackup);
								return S_FALSE;
							}
							else
							{
								result = pDoShadowCopy->Wait();
								if (result != S_OK) {
									printError(result);
									log(1, L"🔥 pDoShadowCopy Wait", result);
									ReleaseInterface(pBackup);
									return S_FALSE;
								}
								else 
								{
									VSS_SNAPSHOT_PROP  prop;
									pBackup->GetSnapshotProperties(*snapshotSetId, &prop);

									wchar_t* snapVol = prop.m_pwszSnapshotDeviceObject;
									wcsncat(snapVol, L"\\", 1);
									OLECHAR* guidString;
									result = StringFromCLSID(prop.m_SnapshotId, &guidString);
									conf.mountpoint = std::wstring(L"C:\\Windows\\temp\\") + std::wstring(guidString);
									//*mountpoint = (std::wstring(L"C:\\windows\\temp\\") + std::wstring((wchar_t*)guidString)).c_str();
									if (CreateSymbolicLink(conf.mountpoint.c_str(), snapVol, SYMBOLIC_LINK_FLAG_DIRECTORY) == 0) {
										printError(L"Error CreateSymbolicLink : " + getErrorMessage(GetLastError()));
										log(1, L"🔥 CreateSymbolicLink", GetLastError());
									}
									VssFreeSnapshotProperties(&prop);
								}

								pDoShadowCopy->Release();
							}
						}
					}
					pPrepare->Release();
				}
			}
		}
		pBackup->FreeWriterMetadata();
		return S_OK;
	}
	return S_FALSE;
}
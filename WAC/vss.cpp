#include <iostream>
#include <string>
#include <windows.h>
#include <strsafe.h>
#include "vss.h"
#include "tools.h"

void ReleaseInterface(IVssBackupComponents* pBackup)
{
	log(3, L"🔈ReleaseInterface");
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
	log(0, L"ℹ️Snapshots :");
	log(0, L"*******************************************************************************************************************");
	log(1, L"➕Snapshot");
	log(3, L"🔈CreateVssBackupComponents");
	HRESULT result = CreateVssBackupComponents(&pBackup);
	if (result != S_OK) {
		printError(result);
		log(2, L"🔥CreateVssBackupComponents", result);
		ReleaseInterface(pBackup);
		return S_FALSE;
	}
	if (result == S_OK)
	{
		// Initialize for backup
		log(3, L"🔈InitializeForBackup");
		result = pBackup->InitializeForBackup();
		if (result != S_OK) {
			printError(result);
			log(2, L"🔥InitializeForBackup", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		// set the context 
		log(3, L"🔈SetContext");
		result = pBackup->SetContext(VSS_CTX_BACKUP); // Specifies an auto-release, non persistent shadow copy created without writer involvement.

		if (result != S_OK) {
			printError(result);
			log(2, L"🔥SetContext", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		log(3, L"🔈StartSnapshotSet");
		result = pBackup->StartSnapshotSet(snapshotSetId);
		if (result != S_OK) {
			printError(result);
			log(2, L"🔥StartSnapshotSet", result);
			ReleaseInterface(pBackup);
			return S_FALSE;
		}
		else
		{
			log(3, L"🔈AddToSnapshotSet");
			result = pBackup->AddToSnapshotSet(volumeName, GUID_NULL, snapshotSetId);
			if (result != S_OK) {
				printError(result);
				log(2, L"🔥AddToSnapshotSet", result);
				ReleaseInterface(pBackup);
				return S_FALSE;
			}
			else
			{
				//
				// Configure the backup operation for Copy with no backup history
				//
				log(3, L"🔈SetBackupState");
				result = pBackup->SetBackupState(false, false, VSS_BT_COPY);
				if (result != S_OK) {
					printError(result);
					log(2, L"🔥SetBackupState", result);
					ReleaseInterface(pBackup);
					return S_FALSE;
				}
				else
				{
					//
					// Make VSS generate a PrepareForBackup event
					//
					log(3, L"🔈PrepareForBackup");
					result = pBackup->PrepareForBackup(&pPrepare);
					if (result != S_OK) {
						printError(result);
						log(2, L"🔥PrepareForBackup", result);
						ReleaseInterface(pBackup);
						return S_FALSE;
					}
					else
					{
						log(3, L"🔈Wait pPrepare");
						result = pPrepare->Wait();
						if (result != S_OK) {
							printError(result);
							log(2, L"🔥pPrepare Wait", result);
							ReleaseInterface(pBackup);
							return S_FALSE;
						}
						else
						{
							//
							// Commit all snapshots in this set
							//
							IVssAsync* pDoShadowCopy = NULL;
							log(3, L"🔈DoSnapshotSet");
							result = pBackup->DoSnapshotSet(&pDoShadowCopy);
							if (result != S_OK) {
								printError(result);
								log(2, L"🔥DoSnapshotSet", result);
								ReleaseInterface(pBackup);
								return S_FALSE;
							}
							else
							{
								log(3, L"🔈Wait pDoShadowCopy");
								result = pDoShadowCopy->Wait();
								if (result != S_OK) {
									printError(result);
									log(2, L"🔥pDoShadowCopy Wait", result);
									ReleaseInterface(pBackup);
									return S_FALSE;
								}
								else 
								{
									VSS_SNAPSHOT_PROP  prop;
									log(3, L"🔈GetSnapshotProperties");
									pBackup->GetSnapshotProperties(*snapshotSetId, &prop);
									wchar_t* snapVol = prop.m_pwszSnapshotDeviceObject;
									wcsncat(snapVol, L"\\", 1);
									OLECHAR* guidString;
									log(3, L"🔈StringFromCLSID");
									result = StringFromCLSID(prop.m_SnapshotId, &guidString);
									log(2, L"❇️Snapshot id : " + std::wstring(guidString));
									conf.mountpoint = std::wstring(L"C:\\Windows\\temp\\") + std::wstring(guidString);
									//*mountpoint = (std::wstring(L"C:\\windows\\temp\\") + std::wstring((wchar_t*)guidString)).c_str();
									log(3, L"🔈CreateSymbolicLink");
									if (CreateSymbolicLink(conf.mountpoint.c_str(), snapVol, SYMBOLIC_LINK_FLAG_DIRECTORY) == 0) {
										log(3, L"🔈printError CreateSymbolicLink");
										printError(L"Error CreateSymbolicLink : " + getErrorMessage(GetLastError()));
										log(2, L"🔥CreateSymbolicLink", GetLastError());
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
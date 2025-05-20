#include <iostream>
#include <string>
#include <windows.h>
#include <strsafe.h>
#include "vss.h"
#include "tools.h"

void ReleaseInterface(IUnknown* unkn)
{

	if (unkn != NULL)
		unkn->Release();

}

HRESULT GetSnapshots(LPCWSTR* mountpoint, VSS_ID* snapshotSetId, IVssBackupComponents* pBackup)
{
	TCHAR volumeName[MAX_PATH]=TEXT("c:\\");
	// declare all the interfaces used in this program.
	
	IVssAsync* pAsync = NULL;
	IVssAsync* pPrepare = NULL;
	
	HRESULT result = CreateVssBackupComponents(&pBackup);
	if (result != S_OK) {
		printError(result);
		ReleaseInterface(pBackup);
		return S_FALSE;
	}
	if (result == S_OK)
	{
		// Initialize for backup
		result = pBackup->InitializeForBackup();
		// set the context 
		result = pBackup->SetContext(VSS_CTX_BACKUP); // Specifies an auto-release, non persistent shadow copy created without writer involvement.

		if (result != S_OK) { 
			printError(result);
			ReleaseInterface(pBackup); 
			return S_FALSE;
		}
		result = pBackup->StartSnapshotSet(snapshotSetId);
		if (result != S_OK) { 
			printError(result);
			ReleaseInterface(pBackup); 
			return S_FALSE;
		}
		if (result == S_OK)
		{
			result = pBackup->AddToSnapshotSet(volumeName, GUID_NULL, snapshotSetId);
			if (result != S_OK)
			{
				_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result); 
				ReleaseInterface(pBackup);
				return S_FALSE;
			}
			if (result == S_OK)
			{
				//
				// Configure the backup operation for Copy with no backup history
				//
				result = pBackup->SetBackupState(false, false, VSS_BT_COPY);
				if (result != S_OK)
				{
					_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result); 
					ReleaseInterface(pBackup);
					return S_FALSE;
				}

				if (result == S_OK)
				{
					//
					// Make VSS generate a PrepareForBackup event
					//
					result = pBackup->PrepareForBackup(&pPrepare);
					if (result != S_OK)
					{
						_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result);
						ReleaseInterface(pBackup);
						return S_FALSE;
					}
					if (result == S_OK)
					{
						result = pPrepare->Wait();
						if (result != S_OK)
						{
							_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result);
							ReleaseInterface(pBackup);
							return S_FALSE;
						}
						if (result == S_OK)
						{
							//
							// Commit all snapshots in this set
							//
							IVssAsync* pDoShadowCopy = NULL;
							result = pBackup->DoSnapshotSet(&pDoShadowCopy);
							if (result != S_OK)
							{
								_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result);
								ReleaseInterface(pBackup);
								return S_FALSE;
							}
							if (result == S_OK)
							{
								result = pDoShadowCopy->Wait();
								if (result != S_OK)
								{
									_tprintf(_T("- Returned HRESULT = 0x%08lx\n"), result);
									ReleaseInterface(pBackup);
									return S_FALSE;
								}
								if (result == S_OK) {
									VSS_SNAPSHOT_PROP  prop;
									pBackup->GetSnapshotProperties(*snapshotSetId, &prop);

									wchar_t* snapVol = prop.m_pwszSnapshotDeviceObject;
									wcsncat(snapVol, L"\\", 1);
									OLECHAR* guidString;
									result = StringFromCLSID(prop.m_SnapshotId, &guidString);
									*mountpoint = (L"C:\\windows\\temp\\" + std::wstring((LPCWSTR)guidString)).c_str();
									if (CreateSymbolicLink(*mountpoint, snapVol, SYMBOLIC_LINK_FLAG_DIRECTORY) == 0) {
										printf("Error CreateSymbolicLink\n");
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
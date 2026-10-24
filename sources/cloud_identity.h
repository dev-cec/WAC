/*! \file
 *  \brief The machine's and its users' registration with Microsoft Entra ID
 *         (backlog B-052).
 *
 *  WHAT THE ARTEFACT PROVES. A machine joined to Entra ID (formerly Azure
 *  AD), or a work account added by a user ("registered" device), keeps the
 *  tenant, the account and the device's certificate thumbprint: to which
 *  organisation the machine answers, which account opened it to the cloud
 *  — ATT&CK T1098.005 (device registration), the local side of the
 *  tenant's sign-in and audit logs, which are in the cloud.
 *
 *  WHERE, in the copied hives:
 *    - SYSTEM `Control\CloudDomainJoin\JoinInfo\<thumbprint>` (TenantId,
 *      UserEmail, IdpDomain…) and `…\TenantInfo\<tenant>` (DisplayName, the
 *      MDM enrolment URLs);
 *    - each user's NTUSER.DAT `Software\Microsoft\Windows NT\CurrentVersion\
 *      WorkplaceJoin\JoinInfo` and `…\TenantInfo`, for a registered device.
 *  Every value is given as stored.
 *
 *  The token caches the accounts leave (TokenBroker, the AAD broker
 *  plug-in) are taken raw by the collection, encrypted by DPAPI as Windows
 *  keeps them, never decrypted by WAC.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "registry_common.h"

//! The token caches of a profile, under it: taken raw, still encrypted.
extern const wchar_t* const CLOUD_TOKEN_FOLDERS[2];

/*! One registration key: a join or a tenant. */
struct CloudRegistration {
	std::wstring source;        //!< "CloudDomainJoin\\JoinInfo", "CloudDomainJoin\\TenantInfo", "WorkplaceJoin\\JoinInfo"…
	std::wstring sid;           //!< the user, for WorkplaceJoin; empty for the machine
	std::wstring keyName;       //!< the subkey: the certificate's thumbprint, or the tenant's identifier
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the subkey: the join or its last change
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, as stored
	Json toJson() const;        //!< @return the registration as a JSON object
};

//! The Entra ID registrations of the machine and of each user (cloud_identity.json).
class CloudIdentity {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any registration
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<CloudRegistration> registrations_;
};

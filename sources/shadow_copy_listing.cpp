/*! \file
 *  \brief `shadow_copies.json`: see shadow_copy_listing.h.
 */
#include "shadow_copy_listing.h"
#include "live_snapshot.h"
#include "tools.h"

HRESULT ShadowCopyListing::getData() {
	log(3, L"🔈shadow copies getData");
	Json snapshot = Json::null();
	const HRESULT hresult = readLiveSnapshot("shadow_copies.json", snapshot);
	if (hresult != ERROR_SUCCESS) return hresult;
	if (snapshot.kind() != Json::Kind::Arr) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	copies_ = std::move(snapshot);
	return ERROR_SUCCESS;
}

HRESULT ShadowCopyListing::toJson() {
	return writeJsonFile("shadow_copies.json", copies_);
}

void ShadowCopyListing::clear() {
	copies_ = Json::arr();
}

/*! \file
 *  \brief `shadow_copies.json`: see shadow_copy_listing.h.
 */
#include "shadow_copy_listing.h"
#include "live_snapshot.h"
#include "tools.h"
#include "context.h"

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
	// B-092: the volume each copy is of; listed live from VSS: no file the evidence.
	Json list = Json::arr();
	for (const auto& copy : copies_.members()) {
		Json o = copy.second;
		const Json* volume = copy.second.find(L"Volume");
		RecordContext context;
		if (volume) context.subject.path = contextPath(volume->text() + L"\\");
		addContext(o, context);
		list.push(std::move(o));
	}
	return writeJsonFile("shadow_copies.json", list);
}

void ShadowCopyListing::clear() {
	copies_ = Json::arr();
}

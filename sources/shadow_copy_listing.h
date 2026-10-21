/*! \file
 *  \brief `shadow_copies.json`: the shadow copies of the fixed NTFS volumes,
 *         as the collection read them raw (raw_collect.h,
 *         ExtractShadowCopiesRaw).
 *
 *  The catalog is read during the collection, on the examined machine: the
 *  list is recorded there as a live snapshot (`exhibits\live\
 *  shadow_copies.json`, sealed in the manifest with the catalog file itself),
 *  and the conversion publishes it. Each copy names the folder of the
 *  exhibit store its files went to (`ExhibitFolder`).
 */
#pragma once
#include <windows.h>
#include "json.h"

/*! The list of the shadow copies, from the collection's snapshot. */
class ShadowCopyListing {
public:
	/*! Reads the snapshot the collection wrote.
	 *  @return ERROR_SUCCESS, or why it could not be read */
	HRESULT getData();
	/*! Writes `shadow_copies.json`, one object per copy, oldest first per volume.
	 *  @return ERROR_SUCCESS, or the error of the write */
	HRESULT toJson();
	//! Releases the list.
	void clear();
private:
	Json copies_ = Json::arr();   //!< the copies, as the snapshot recorded them
};

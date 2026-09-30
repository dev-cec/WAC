/*! \file
 *  \brief The four link-tracking identifiers (DROID) a shortcut or a jump-list
 *  entry carries, and what their version-1 GUIDs reveal.
 *
 *  WHAT THEY PROVE. The Distributed Link Tracking service gives each file it
 *  tracks an object identifier: a volume GUID and a file GUID, the current
 *  ones (DROID) and those at the file's birth (birth DROID). The file GUID is a
 *  version-1 GUID: it holds the instant the tracking began and the hardware
 *  address of the machine that began it. A birth DROID that differs from the
 *  current one says the file was moved or copied from another volume — and
 *  the birth address, from which machine.
 *
 *  Read in two places, one layout: the TrackerDataBlock of a .lnk (MS-SHLLINK
 *  2.5.10) and the entries of a jump list's DestList. One structure, so that
 *  both give the same fields under the same names.
 */
#pragma once

#include <windows.h>
#include "json.h"

/*! The DROID and birth DROID of a tracked file. */
struct LinkTracking {
	GUID volume = { 0 };      //!< DROID: volume identifier
	GUID file = { 0 };        //!< DROID: file identifier (version-1 GUID)
	GUID birthVolume = { 0 }; //!< birth DROID: volume identifier
	GUID birthFile = { 0 };   //!< birth DROID: file identifier

	LinkTracking() {}

	/*! Reads the four GUIDs, in their on-disk order.
	 *  @param at their 64 bytes: the caller has checked they are in its buffer */
	explicit LinkTracking(const BYTE* at);

	/*! Adds the four GUIDs, and the instant and hardware address of the file
	 *  GUIDs (the birth ones only when they differ from the current ones).
	 *  @param o the object to fill */
	void addTo(Json& o) const;
};

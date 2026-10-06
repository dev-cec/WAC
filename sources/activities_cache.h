/*! \file
 *  \brief Windows Timeline: the activities of ActivitiesCache.db, per profile.
 *
 *  WHAT THE ARTEFACT PROVES. The Connected Devices Platform keeps, in
 *  `%LocalAppData%\\ConnectedDevicesPlatform\\<account>\\ActivitiesCache.db`
 *  (SQLite), what Windows 10 showed in its Timeline: each application opened,
 *  file or page viewed (its URI and title in the Payload), the time spent in
 *  focus, and — when clipboard history is on — what was copied
 *  (ClipboardPayload). `<account>` is `L.<user>` for a local account, the
 *  account's identifier for a Microsoft or Entra one. Windows 11 dropped the
 *  Timeline: the database remains, holding only the synchronised settings —
 *  still a trace of the profile's use, with its dates.
 *
 *  TWO TABLES. `Activity` holds the activities as they now stand;
 *  `ActivityOperation`, the operations not yet sent to the cloud — an
 *  activity deleted from `Activity` may remain there. Both are read, each
 *  record carrying its table.
 *
 *  EVERY COLUMN, AS DECLARED. The schema changes between versions of Windows
 *  (columns added to both tables since 1803): the rows are read whole and
 *  each column is converted by the type its schema declares, not by a list
 *  of a given version. A `DATETIME` is a Unix time in seconds, UTC — given
 *  in UTC and in the machine's local time at that date; a `GUID`, 16 bytes in
 *  the order .NET writes them (Guid.ToByteArray). A zero date or GUID is the
 *  column's filler, not a value: not emitted. A Payload in JSON is given as
 *  the JSON it is; any other blob as text when it is text, in hexadecimal
 *  otherwise. The codes (ActivityType, ActivityStatus, OperationType) are
 *  given as stored: Microsoft does not document them.
 *
 *  NOT READ. `Activity_PackageId` repeats the applications of `AppId`;
 *  `AppSettings`, `Asset`, `Metadata` hold no activity. They stay in the
 *  exhibit, copied with the database and its `-wal` (whose last activities
 *  SQLite replays on the private copy, see sqlite_reader.h).
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"

//! Folder of the Connected Devices Platform, relative to a profile.
extern const wchar_t CONNECTED_DEVICES_FOLDER[];

/*! One activity, or one pending operation, of a Timeline database. */
struct TimelineActivity {
	std::wstring sid;           //!< SID of the profile the database belongs to
	std::wstring path;          //!< the database on the examined machine
	std::wstring table;         //!< "Activity" or "ActivityOperation"
	Json columns = Json::obj(); //!< its columns, converted (see the file's header)
	//! @return the activity as a JSON object
	Json toJson() const;
};

/*! Reads the activities of one Timeline database.
 *  @param file the database in the working copy of the collection
 *  @param base sid and path of the records to add
 *  @param activities receives one record per row of Activity and ActivityOperation
 *  @return ERROR_SUCCESS, or the failure to open the database */
HRESULT readActivitiesCache(const std::wstring& file, const TimelineActivity& base,
                            std::vector<TimelineActivity>& activities);

/*! The Timeline of every profile (activities_cache.json). */
class ActivitiesCaches {
public:
	/*! Reads the databases extracted from every profile.
	 *  @return ERROR_SUCCESS, even without any database: none is an answer */
	HRESULT getData();
	/*! Writes activities_cache.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the activities read.
	void clear();
private:
	std::vector<TimelineActivity> activities_;   //!< every database's, in order
};

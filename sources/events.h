#pragma once

/*! \file
 *  \brief Windows event logs.
 *
 *  Read OFFLINE from the `.evtx` files extracted by raw reading, and no longer
 *  through the `wevtapi` API. That was the last collector to solicit a service
 *  of the examined machine (`EventLog`): that service can write its own entries
 *  while it is being queried, the call took about twenty minutes under Windows
 *  11, and the collection grew to more than a gigabyte of working set — hence
 *  paging, hence writes to the very disk one strives not to modify.
 *
 *  PROCESSING CHAIN
 *    raw_collect  extracts `\Windows\System32\winevt\Logs\*.evtx` onto the
 *                 collection medium (raw NTFS reading, no file opened)
 *    evtx.h       decodes each record into XML text
 *    xml_light    parses that XML — the same reader as the scheduled tasks,
 *                 rather than a second decoder specific to the events
 *    events.cpp   fills the structure below and writes it AS IT GOES
 *
 *  WHAT THE OFFLINE READING DOES NOT GIVE. `EvtFormatMessage` returned, for
 *  about one event in seven, the plain-text message. That text is not in the
 *  log: it comes from the provider's resource file, which would have to be
 *  parsed in its own right (the `WEVT_TEMPLATE` resource and the message table
 *  of a PE binary). The field is therefore omitted rather than written empty.
 *  All the data of the event itself — identifier, timestamp, provider, channel,
 *  SID, process, and the whole of `EventData` — are present.
 */

#include <windows.h>
#include <string>
#include <vector>
#include "tools.h"
#include "json.h"
#include "xml_light.h"

/*! One event, as it appears in a log.
 *
 *  The fields keep the names of the old collection through the API: the output
 *  schema does not change, only the source does. A value absent from the log
 *  stays `null` — it is not replaced by a zero, which would read as a value
 *  that had been read.
 */
struct Event {
	Json evtSystemProviderName = Json::null();      //!< name of the provider
	Json evtSystemProviderGuid = Json::null();      //!< GUID of the provider
	Json evtSystemEventID = Json::null();           //!< identifier of the event
	Json evtSystemQualifiers = Json::null();        //!< qualifiers (classic events)
	Json evtSystemLevel = Json::null();             //!< level
	Json evtSystemTask = Json::null();              //!< task
	Json evtSystemOpcode = Json::null();            //!< opcode
	Json evtSystemKeywords = Json::null();          //!< keywords
	Json evtSystemTimeCreated = Json::null();       //!< creation date (UTC)
	Json evtSystemEventRecordId = Json::null();     //!< identifier of the record
	Json evtSystemActivityID = Json::null();        //!< activity identifier
	Json evtSystemRelatedActivityID = Json::null(); //!< related activity identifier
	Json evtSystemProcessID = Json::null();         //!< process that emitted the event
	Json evtSystemThreadID = Json::null();          //!< thread that emitted the event
	Json evtSystemChannel = Json::null();           //!< channel
	Json evtSystemComputer = Json::null();          //!< name of the computer
	Json evtSystemUserID = Json::null();            //!< SID of the user
	Json evtSystemVersion = Json::null();           //!< version of the event's schema
	/*! Data specific to the event: an array of `{ Name, Value }` objects.
	*
	*  The name comes from the `Name` attribute of the `<Data>` — `TargetUserName`,
	*  `NewProcessId`, `CommandLine` — and it is OMITTED for classic events,
	*  whose data are purely positional. Without it, one would have to know by
	*  heart the order of the fields of every event identifier to know what one is
	*  reading.
	*/
	Json evtEventData = Json::null();
	/*! Name of the log file the event comes from.
	*
	*  PROVENANCE. One channel can be carried by several files: the current log
	*  and its archives, which a machine keeps side by side with record numbers
	*  that overlap. Without this field, two events of the same channel and the
	*  same number are indistinguishable, and nothing says which comes from
	*  where — which makes it impossible to decide between a legitimate duplicate
	*  and a reading defect.
	*/
	Json evtSourceLog = Json::null();
	/*! Plain-text message, rebuilt from the provider's resources.
	*
	*  Omitted when it could not be: provider not declared, resource binary
	*  absent, or an event the provider does not describe. An empty field would
	*  read as an event without a message, whereas the message exists and was not
	*  reached.
	*/
	Json evtEventMessage = Json::null();

	/*! Builds the event from the decoded XML of a record.
	*  @param root the `<Event>` element parsed by xml_light
	*  @param channel channel deduced from the file name, used if the XML does not
	*         carry it (archived logs sometimes omit `<Channel>`)
	*  @param id record number read in the binary header, used if the XML does not
	*         carry `<EventRecordID>`
	*  @param fileName name of the log file, recorded as the provenance
	*/
	Event(const XmlNode& root, const std::wstring& channel,
	      unsigned long long id, const std::wstring& fileName);

	/*! Values of `EventData`, in order, as they fill the %1 %2 … marks of a
	*  message template.
	*
	*  Kept apart from `evtEventData`, which has already laid them out with their
	*  names: getting them back out of the JSON would need accessors nobody else
	*  needs, to recover information one already had at hand. */
	std::vector<std::wstring> rawValues;

	/*  Fields kept in their native form for the resolution of the message.
	    The JSON versions are already formatted; decoding them back would be both
	    useless and fragile. */
	std::wstring guidPourMessage;     //!< GUID of the provider
	uint16_t     idPourMessage = 0;   //!< identifier of the event
	uint8_t      versionPourMessage = 0; //!< version of the schema

	/*! Converts the event to JSON.
*  @return its JSON object. */
	Json toJson() const;

	//! Releases the memory held by the event.
	void clear() {}
};

/*! Collection of every extracted log.
 *
 *  No array of events is kept: each one is written then forgotten (see
 *  JsonArrayWriter). That is what brings the collection of the logs down to a
 *  constant memory footprint, whatever the size of the logs.
 */
struct Events {
	unsigned long long read = 0;          //!< records written
	unsigned long long unreadable = 0;   //!< records discarded
	unsigned long long files = 0;     //!< logs walked

	/*! Reads the extracted logs and writes `events.json` as it goes.
	*  @return ERROR_SUCCESS, S_FALSE if some records were discarded, or an error
	*          code if no log could be read
	*/
	HRESULT getData();

	/*! Nothing to serialise: `getData()` has already written the file.
	*  Kept so that the sequence in main.cpp stays the same for every collector.
	*/
	HRESULT toJson() { return ERROR_SUCCESS; }

	//! Releases the memory held by the collection.
	void clear() {}
};

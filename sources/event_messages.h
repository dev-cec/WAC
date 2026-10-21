#pragma once

/*! \file
 *  \brief An event's plain-text message, without the system's API.
 *
 *  WHAT THIS MODULE REPLACES. `EvtFormatMessage` returned the readable sentence
 *  of an event by going to look, in the provider's resource file, for the
 *  matching text template. That was the last service the API rendered: the
 *  offline reading of the logs gave everything EXCEPT that text, absent for
 *  about one event in seven (14,046 out of 102,627 measured).
 *
 *  WHAT MUST BE BROUGHT TOGETHER, and where each piece is found:
 *
 *    the provider's GUID               in the event itself
 *    the path of its file              SOFTWARE hive, under
 *                                      `WINEVT\Publishers\{guid}`
 *    the message identifier            WEVT_TEMPLATE resource of that file
 *    the sentence template             MESSAGETABLE resource — not of the file
 *                                      itself, but of its satellite
 *                                      `<language>\<name>.mui` on a localised system
 *    the values to insert              the event's data
 *
 *  EXTRACTION ON DEMAND. Those resource files are not artefacts: they are
 *  ordinary system binaries, and nearly a thousand of them are declared.
 *  Extracting them all would cost hundreds of megabytes for providers most of
 *  which produced no event at all. Each file is therefore extracted at the
 *  moment an event calls for it, only once, by raw NTFS reading — like
 *  everything else. It joins the exhibit store, is identified there by its
 *  fingerprints, then is copied into the working directory before being read.
 *
 *  A provider whose file cannot be found or read is remembered as such: it is
 *  not tried again at every event, and the report records it.
 */

#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <utility>

/*! Prepares the resolution of the messages.
*  To be called once before the collection of the events. Without that call, the
*  messages are not resolved and the collection goes on normally.
*/
void MessagesInit();

/*! Plain-text message of an event.
*
*  @param providerGuid GUID of the provider, "{…}"; empty if the event does not
*         carry it — the message is then unfindable and the function returns an
*         empty string
*  @param eventId identifier of the event
*  @param version version of the event's schema
*  @param values data of the event, in order: they are what fills the %1 %2 …
*         marks of the template
*  @param names the name of each value (its Data's Name), by which it is
*         matched to its template item; may be empty
*  @param templateValues the event's values as its template instance holds
*         them, in the template's order: taken when the names do not line up
*         with the items and there is one per item; may be empty
*  @return the sentence, or an empty string if it could not be rebuilt
*/
std::wstring EventMessage(const std::wstring& providerGuid,
                              uint16_t eventId,
                              uint8_t version,
                              const std::vector<std::wstring>& values,
                              const std::vector<std::wstring>& names,
                              const std::vector<std::wstring>& templateValues = {});

/*! The message of an event that carries qualifiers — published the classic
 *  way by a provider that has a manifest —, looked up in the provider's own
 *  message table by its full identifier, qualifiers in the high word: what
 *  Windows shows for it. The manifest's message for the bare identifier may
 *  be another one (Vista's CAPI2 11, qualifiers 0xC002: "For more details
 *  for this event…" in the manifest, the cause in the table).
 *  @param providerGuid the provider's GUID
 *  @param messageId qualifiers in the high word, event identifier in the low one
 *  @param values data of the event, in order: %1, %2…
 *  @return the sentence, or an empty string if the table has no such message */
std::wstring QualifiedEventMessage(const std::wstring& providerGuid, uint32_t messageId,
                                   const std::vector<std::wstring>& values);

/*! --collect: extracts the resource files of the providers the collected
 *  logs cite — binary, its SystemResources twin, parameter file, localised
 *  .mui satellites —, of the classic sources they cite, and the system's
 *  message tables: what their conversion will look for, by the same search
 *  as on demand (the conversion then finds each file where the collection
 *  put it). Taking every declared provider instead cost 739 MiB and 61 s on
 *  the test VM for 1,426 providers (backlog B-033). Requires the SOFTWARE
 *  hive open.
 *  @param guids the providers' GUIDs the logs cite
 *  @param sources the (log, source) pairs of their events, for the classic sources
 *  @return ERROR_SUCCESS, or ERROR_FILE_NOT_FOUND without the SOFTWARE hive */
HRESULT MessagesCollect(const std::set<std::wstring>& guids,
                        const std::set<std::pair<std::wstring, std::wstring>>& sources);

/*! Summary, for the log and the report.
*  @param providers number of providers whose resources were read
*  @param failures number of providers whose file could not be read
*  @param resolved number of messages actually rebuilt
*  @param bytes volume extracted for those resources
*/
void MessagesSummary(size_t* providers, size_t* failures,
                   unsigned long long* resolved, unsigned long long* bytes);

/*! Releases the resources loaded. */
void MessagesRelease();

/*! Plain-text message of an event of a CLASSIC source (written by
*  ReportEvent: no provider GUID in the event). Its message files are those
*  `SYSTEM\CurrentControlSet\Services\EventLog\<log>\<source>` declares
*  in EventMessageFile (several, separated by semicolons, tried in order), its
*  parameter labels those of ParameterMessageFile.
*
*  @param logName the log the event is in, as the registry names it ("Application")
*  @param source the event's provider name
*  @param messageId the full identifier: qualifiers in the high word, event
*         identifier in the low one — the message table's key
*  @param values data of the event, in order
*  @return the sentence, or an empty string if it could not be rebuilt
*/
std::wstring ClassicEventMessage(const std::wstring& logName, const std::wstring& source, uint32_t messageId,
                                 const std::vector<std::wstring>& values);

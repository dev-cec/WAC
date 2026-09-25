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
*  @return the sentence, or an empty string if it could not be rebuilt
*/
std::wstring EventMessage(const std::wstring& providerGuid,
                              uint16_t eventId,
                              uint8_t version,
                              const std::vector<std::wstring>& values);

/*! --collect: extracts the resource files of EVERY provider declared in
 *  SOFTWARE\...\WINEVT\Publishers — binary, parameter file, localised .mui
 *  satellites —, since which of them the event logs cite is only known at
 *  conversion. The same search as on demand (the conversion then finds each
 *  file where the collection put it). Requires the SOFTWARE hive open.
 *  @return ERROR_SUCCESS, or the error of the hive's reading */
HRESULT MessagesCollectAll();

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

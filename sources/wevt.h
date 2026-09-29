#pragma once

/*! \file
 *  \brief An event's plain-text message, rebuilt offline.
 *
 *  THE PROBLEM. An event log does not hold sentences: it holds an event
 *  identifier and data. The text lives in the provider's resource file, and it
 *  was `EvtFormatMessage` that made the junction — at the price of a call to the
 *  examined system. Measured on a real collection: 14,046 events out of 102,627
 *  carried a message, and 97 % of them came from modern providers.
 *
 *  THE CHAIN TO WALK BACK, and why TWO resources are needed:
 *
 *      event (identifier + version)
 *          │   WEVT_TEMPLATE, in the provider's DLL
 *          ▼
 *      message identifier
 *          │   MESSAGETABLE, in the satellite <language>\<name>.mui
 *          ▼
 *      sentence template, with %1 %2 … marks
 *          │   the event's data, read in the log
 *          ▼
 *      plain-text message
 *
 *  Neither link is enough on its own: the message table does not say which text
 *  goes with which event, and the metadata hold no text.
 *
 *  THE FORMATS
 *
 *  MESSAGETABLE: a count of blocks, then blocks { first identifier, last
 *  identifier, offset }, then consecutive entries { length, flags, text }. The
 *  low-order flag says whether the text is in UTF-16 or in a code page —
 *  getting it wrong returns every other byte.
 *
 *  WEVT_TEMPLATE: a "CRIM" header, a table of providers by GUID, and for each
 *  provider blocks typed by a signature — "EVNT" for the events, "CHAN" for the
 *  channels, "TTBL" for the templates. Only EVNT is of interest here: it gives,
 *  per event, the message identifier.
 *
 *  The files come from the examined machine: every bound is checked, and a
 *  malformed resource returns an empty result rather than having memory read out
 *  of range.
 *
 *  Portable C++, no dependency (see wevt_test).
 */

#include <cstdint>
#include <map>
#include <string>
#include <vector>

/*! Message table of a binary, indexed by identifier. */
class TableMessages {
public:
	/*! Parses a MESSAGETABLE resource.
	*  @param data raw content of the resource
	*  @return the number of messages read */
	size_t analyse(const std::vector<uint8_t>& data);

	/*! Text of a message identifier.
	*  @return the template with its %1 %2… marks, or an empty string if absent */
	std::wstring text(uint32_t id) const;

	//! Number of known messages.
	size_t size() const { return messages_.size(); }

private:
	std::map<uint32_t, std::wstring> messages_;
};

/*! Event metadata of a provider (the WEVT_TEMPLATE resource). */
class WevtMetadata {
public:
	/*! Parses a WEVT_TEMPLATE resource.
	*  @param data raw content of the resource
	*  @param providerGuid GUID of the provider looked for, in the form
	*         "{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}"; empty to take the first
	*         provider described
	*  @return the number of events described */
	size_t analyse(const std::vector<uint8_t>& data,
	                const std::wstring& providerGuid = std::wstring());

	/*! Message identifier of an event.
	*
	*  The version is tried first, then the identifier alone: a provider may
	*  describe several versions of the same event, but the log does not always
	*  carry the one that served.
	*
	*  @return the message identifier, or 0 if the event is not described */
	uint32_t messageId(uint16_t eventId, uint8_t version) const;

	//! Number of events described.
	size_t size() const { return parIdEtVersion_.size(); }

private:
	std::map<uint32_t, uint32_t> parIdEtVersion_;   //!< (id << 8 | version) -> message
	std::map<uint16_t, uint32_t> parId_;            //!< id -> message (first version seen)
};

/*! Replaces the %1 %2 … marks by the event's data.
*
*  Windows writes its templates with positional marks, and sometimes with
*  layout escape sequences (`%n`, `%t`, `%%`). A mark without matching data is
*  left as it is: erasing it would suggest a complete sentence whereas a value
*  is missing.
*
*  @param messageTemplate text taken from the message table
*  @param values data of the event, in order (%1 is the first)
*  @return the sentence, or an empty string if the template is empty
*/
std::wstring formatMessage(const std::wstring& messageTemplate,
                             const std::vector<std::wstring>& values);

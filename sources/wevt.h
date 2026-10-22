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

/*! One item of an event's template: how its value is to be shown. */
struct WevtItem {
	uint8_t  inType = 0;    //!< input type (win:UInt32 = 0x08, win:HexInt64 = 0x15…)
	uint8_t  outType = 0;   //!< output type (xs:unsignedInt = 0x08, win:HexInt32 = 0x12…)
	uint32_t map = 0;       //!< offset of its value map in the resource, 0 for none
	std::wstring name;      //!< its name, as the event's Data carry it
};

/*! A value map of a provider: a value's label is a message. A VMAP labels
 *  each value, a BMAP each bit. */
struct WevtValueMap {
	bool bitmap = false;                   //!< BMAP: the value is a set of flags
	std::map<uint32_t, uint32_t> labels;   //!< value (VMAP) or flag (BMAP) -> message identifier of its label
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

	/*! The items of an event's template, in the order of its data — the
	 *  version tried first, then the identifier alone, as messageId.
	 *  @return the items, or nullptr if the event has no template */
	const std::vector<WevtItem>* items(uint16_t eventId, uint8_t version) const;

	/*! @param offset a map's offset, as an item gives it
	 *  @return the value map, or nullptr */
	const WevtValueMap* valueMap(uint32_t offset) const;

private:
	std::map<uint32_t, uint32_t> parIdEtVersion_;   //!< (id << 8 | version) -> message
	std::map<uint16_t, uint32_t> parId_;            //!< id -> message (first version seen)
	std::map<uint32_t, uint32_t> templateByIdVersion_;   //!< (id << 8 | version) -> template offset
	std::map<uint16_t, uint32_t> templateById_;          //!< id -> template offset (first version seen)
	std::map<uint32_t, std::vector<WevtItem>> templates_;   //!< template offset -> its items
	std::map<uint32_t, WevtValueMap> valueMaps_;            //!< map offset -> value map
};

/*! The system's own message tables, which give an error code its text. */
struct SystemMessages {
	const TableMessages* errors = nullptr;     //!< kernelbase's: Win32 errors and HRESULTs
	const TableMessages* ntStatus = nullptr;   //!< ntdll's: NTSTATUS codes
};

/*! An event's value as Windows shows it in the message, from its template
 *  item. Measured on the test VM against EvtFormatMessage (B-023), item
 *  types read in the providers' manifests:
 *    - a value map's label: "État : 2" -> "État : Disconnected" (Kernel-Power);
 *      a bitmap's labels of the flags set, joined by commas without space
 *      ("67108880" -> "BackgroundTaskOption,LowPriorityRequest", AppX); a
 *      bitmap's zero stays the number (Kernel-Boot 153);
 *    - a hexadecimal input type (win:HexInt32, win:HexInt64), or a
 *      hexadecimal output type of an integer, and win:ErrorCode, as 0x and
 *      upper-case digits: "0x3e7" -> "0x3E7", "2147746053" -> "0x80040105".
 *      A pointer keeps the log's form ("0x1b3c");
 *    - an error code by its text: win:Win32Error and win:HResult from the
 *      system's table ("87" -> "Paramètre incorrect."), a Win32 HRESULT
 *      (0x8007xxxx) by its Win32 code first, an unknown HRESULT "Unknown
 *      HResult Error code: 0x…" without its 0x10000000 bit, as Windows
 *      writes it; win:NTSTATUS
 *      from ntdll's ("0" -> "STATUS_SUCCESS");
 *    - binary data as xs:hexBinary: "0x" before its digits; as
 *      win:SocketAddress, an IPv4 address and its port ("127.0.0.1:58241").
 *    - a win:Double, 15 significant digits ("17.4690293241336"), where the
 *      log's XML gives the shortest exact form ("17.469029324133604"):
 *      Vista and Windows 11 render a record of Vista's ReadyBoost alike.
 *  A value that is no number, absent from its map or from the tables, stays
 *  as it is.
 *
 *  @param item the value's template item
 *  @param map its value map, or nullptr
 *  @param messages the provider's message table, where the labels are
 *  @param system the system's tables (either may be missing)
 *  @param value the value, as the log holds it (decimal, or "0x…")
 *  @param vista the messages are Vista's, which write a win:ErrorCode in
 *         decimal (UMDF 2105, a UInt32 status shown as win:ErrorCode:
 *         "3221225659" under Vista, "0xC00000BB" under Windows 7, measured)
 *  @return the value to put in the message */
std::wstring formatItemValue(const WevtItem& item, const WevtValueMap* map, const TableMessages& messages,
                             const SystemMessages& system, const std::wstring& value, bool vista = false);

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

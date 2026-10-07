/*! \file
 *  \brief The messages of a PST or OST file: folders, messages, recipients,
 *         attachments, bodies — the messaging layer on pst_file.h.
 *
 *  A message is a node of type 4 whose parent is a folder (type 2): the node
 *  B-tree gives them all, with no need for the folders' contents tables. Its
 *  properties are its property context; its recipients and its attachments
 *  are table contexts among its subnodes (0x692, 0x671), each attachment a
 *  property context of its own subnode. The folder path is built from the
 *  folders' display names up to the root folder (0x122).
 *
 *  Checked against pypff (libpff), message by message, on the test corpus:
 *  pst_test.
 */
#pragma once

#include "pst_file.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <windows.h>

/*! An attachment of a message. */
struct PstAttachment {
	std::wstring fileName;      //!< PidTagAttachLongFilename, else PidTagAttachFilename
	std::wstring mimeType;      //!< PidTagAttachMimeTag
	uint32_t method = 0;        //!< PidTagAttachMethod: 1 by value, 5 an embedded message, 6 OLE…
	std::vector<uint8_t> data;  //!< PidTagAttachDataBinary: the file attached, or the embedded object's node
	bool dataRead = false;      //!< the data was there and read
	/*! An embedded message (method 5, PidTagAttachDataObject: an appointment's
	 *  exception, a mail forwarded as attachment): its own properties. */
	PstProperties embedded;
};

/*! A recipient of a message. */
struct PstRecipient {
	std::wstring name;          //!< PidTagDisplayName
	std::wstring address;       //!< PidTagEmailAddress (SMTP or Exchange)
	uint32_t type = 0;          //!< PidTagRecipientType: 1 To, 2 Cc, 3 Bcc
};

/*! A message (or a contact, an appointment: whatever the folders hold). */
struct PstMessage {
	uint32_t nid = 0;                  //!< its node: what ties it to libpff's identifier
	std::wstring folder;               //!< folder path, display names joined by "/"
	PstProperties properties;          //!< every property read
	std::vector<PstRecipient> recipients;
	std::vector<PstAttachment> attachments;
	bool readWhole = true;             //!< false if a part (properties, a table, an attachment) did not hold

	/*! A property as text (see pstValueText), empty if absent.
	 *  @param id the property's identifier */
	std::wstring text(uint16_t id) const;
	/*! The subject, without the prefix marker some PSTs keep (U+0001 and a length). */
	std::wstring subject() const;
	/*! A time property. @param id its identifier @param utc receives it
	 *  @return false if absent or not a time */
	bool time(uint16_t id, FILETIME& utc) const;
};

/*! Every message of a file, one at a time, its attachments' data read: a
 *  mailbox of gigabytes is never held whole in memory.
 *  @param file the opened file
 *  @param onMessage called for each message, in the node tree's order; the
 *         message is released when it returns
 *  @param unreadable receives the number of messages whose properties could
 *         not be read at all (not passed to onMessage)
 *  @return false if the node tree itself could not be walked */
bool forEachPstMessage(PstFile& file, const std::function<void(PstMessage&)>& onMessage, size_t& unreadable);

// The properties read, by identifier ([MS-OXPROPS]).
const uint16_t PST_SUBJECT = 0x0037;
const uint16_t PST_MESSAGE_CLASS = 0x001A;
const uint16_t PST_CLIENT_SUBMIT_TIME = 0x0039;
const uint16_t PST_SENDER_NAME = 0x0C1A;
const uint16_t PST_SENDER_ADDRESS = 0x0C1F;
const uint16_t PST_SENT_REPRESENTING_NAME = 0x0042;
const uint16_t PST_DISPLAY_TO = 0x0E04;
const uint16_t PST_DISPLAY_CC = 0x0E03;
const uint16_t PST_DISPLAY_BCC = 0x0E02;
const uint16_t PST_DELIVERY_TIME = 0x0E06;
const uint16_t PST_MESSAGE_SIZE = 0x0E08;
const uint16_t PST_INTERNET_MESSAGE_ID = 0x1035;
const uint16_t PST_TRANSPORT_HEADERS = 0x007D;
const uint16_t PST_BODY = 0x1000;
const uint16_t PST_HTML = 0x1013;
const uint16_t PST_CREATION_TIME = 0x3007;
const uint16_t PST_LAST_MODIFICATION_TIME = 0x3008;
const uint16_t PST_DISPLAY_NAME = 0x3001;

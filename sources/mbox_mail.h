/*! \file
 *  \brief Thunderbird's mailboxes: mbox files and the MIME messages in them.
 *
 *  THE FORMAT. Thunderbird keeps each mail folder as one mbox file, without
 *  extension, in the profile's `Mail\\<account>` or `ImapMail\\<server>`
 *  folder (subfolders in a `<name>.sbd` folder beside it, the index in
 *  `<name>.msf`, not read): the messages one after the other, each preceded
 *  by a "From " line at the start of a line after an empty one. Each message
 *  is an Internet message (RFC 5322) in MIME (RFC 2045 to 2049): headers —
 *  folded lines, encoded words (RFC 2047) —, then a body, possibly multipart,
 *  its parts encoded in base64 or quoted-printable, in a character set of
 *  their own; a part with a file name (RFC 2231 included) is an attachment.
 *
 *  HOSTILE INPUT. A message is whatever its sender wrote: every boundary is
 *  looked for within the message, the nesting of multiparts is bounded, a
 *  message larger than MBOX_MESSAGE_MAX is skipped and counted, never read
 *  past. Checked against Python's own mailbox and email modules on the
 *  messages Thunderbird wrote in the test VM.
 */
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <windows.h>

//! The largest message read: a mailbox holds attachments of tens of MiB at most.
const size_t MBOX_MESSAGE_MAX = 256u * 1024 * 1024;

/*! An attachment of an Internet message. */
struct MimeAttachment {
	std::wstring fileName;       //!< from Content-Disposition, else Content-Type's name
	std::wstring mimeType;       //!< its Content-Type, lower case
	std::vector<uint8_t> data;   //!< its bytes, decoded
};

/*! An Internet message, its headers and parts decoded. */
struct MimeMessage {
	size_t offset = 0;                     //!< its position in the mbox file
	std::string headers;                   //!< the header block as written
	std::wstring from, to, cc, bcc;        //!< address fields, encoded words decoded
	std::wstring subject;                  //!< Subject, encoded words decoded
	std::wstring messageId;                //!< Message-ID
	FILETIME dateUtc{};                    //!< Date, converted to UTC; zero if absent or unreadable
	std::wstring body;                     //!< the first text/plain part, in its character set
	std::vector<uint8_t> html;             //!< the first text/html part, as written in its character set
	std::vector<MimeAttachment> attachments;
};

/*! Decodes one Internet message.
 *  @param raw the message, without its mbox "From " line
 *  @param message receives it
 *  @return false if it has no header block */
bool parseMimeMessage(const std::string& raw, MimeMessage& message);

/*! Every message of an mbox file, one at a time.
 *  @param path the file (a working copy)
 *  @param onMessage called for each message decoded
 *  @param skipped receives the number of messages larger than MBOX_MESSAGE_MAX
 *  @return false if the file could not be read, or does not start as an mbox */
bool forEachMboxMessage(const std::wstring& path, const std::function<void(MimeMessage&)>& onMessage, size_t& skipped);

/*! An RFC 5322 date ("Wed, 7 Oct 2026 19:05:00 +0200") in UTC.
 *  @param text the Date header's value
 *  @param utc receives it
 *  @return false if the text is not such a date */
bool parseMailDate(const std::string& text, FILETIME& utc);

/*! A header value with its encoded words (RFC 2047, B and Q) decoded.
 *  @param value the value as written
 *  @return the text */
std::wstring decodeEncodedWords(const std::string& value);

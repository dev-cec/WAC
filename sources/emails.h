/*! \file
 *  \brief The mail of every profile: Outlook's PST and OST files, their
 *         messages and attachments (emails.json).
 *
 *  WHAT THE ARTEFACT PROVES. What a user sent and received, to whom, when,
 *  and what was attached: a document leaving by mail, a phishing message and
 *  its attachment, an intruder's exchanges from the account.
 *
 *  THE SOURCES. Outlook keeps its mailboxes as PST files (archives, POP
 *  accounts: `Documents\\Outlook Files`) and OST files (the offline copy of an
 *  Exchange or Microsoft 365 mailbox: `AppData\\Local\\Microsoft\\Outlook`),
 *  read by pst_file.h and pst_messages.h. The files Outlook opened from a
 *  message are in `INetCache\\Content.Outlook`, the new Outlook's (olk.exe)
 *  local data in `AppData\\Local\\Microsoft\\Olk`: collected as they are,
 *  not decoded — no sample of the latter to check a decoder on.
 *  Thunderbird keeps each folder as an mbox file in its profiles
 *  (`AppData\\Roaming\\Thunderbird\\Profiles`), read by mbox_mail.h; the
 *  profiles are collected whole — the address book and the settings with the
 *  mail.
 *
 *  THE OUTPUT. A record per mailbox file — its kind, version, the number of
 *  messages read and of those that could not be — and a record per message:
 *  its folder, class, subject, sender, recipients, times, Internet message
 *  identifier and transport headers. Each body (text, HTML) and each
 *  attachment is written next to the JSON, under
 *  `emails\\<SID>\\<file>\\<message>\\`, and the JSON gives its SHA-256. The
 *  attachment's own name, chosen by whoever sent it, is never a path: the
 *  file is named by its rank, with the name's extension when it is a plain
 *  one; the name itself is in the JSON.
 */
#pragma once

#include <windows.h>
#include "tools.h"

/*! The mail of every profile (emails.json). */
class Emails {
public:
	/*! Reads the mailbox files extracted from every profile and writes their
	 *  bodies and attachments next to the JSON.
	 *  @return ERROR_SUCCESS, even without any mailbox: none is an answer */
	HRESULT getData();
	/*! Writes emails.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the records read.
	void clear();
private:
	/*! The mbox folders of one profile's Thunderbird profiles.
	 *  @param sid the Windows profile's SID
	 *  @param profile its path */
	void readThunderbird(const std::wstring& sid, const std::wstring& profile);
	Json records_ = Json::arr();
};

//! Outlook's PST folder, relative to a profile.
extern const wchar_t OUTLOOK_FILES_FOLDER[];
//! Outlook's OST (and older PST) folder, relative to a profile.
extern const wchar_t OUTLOOK_DATA_FOLDER[];
//! The files Outlook opened from a message, relative to a profile.
extern const wchar_t OUTLOOK_OPENED_FOLDER[];
//! Thunderbird's profiles, relative to a Windows profile.
extern const wchar_t THUNDERBIRD_FOLDER[];
//! The new Outlook's (olk.exe) local data, relative to a profile: collected, not decoded.
extern const wchar_t OUTLOOK_NEW_FOLDER[];

/*! A file name's extension, if it is a plain one (1 to 8 letters or digits),
 *  for naming an exported attachment; empty otherwise.
 *  @param name the attachment's name, as the message gives it
 *  @return the extension without its dot, lower case */
std::wstring plainExtension(const std::wstring& name);

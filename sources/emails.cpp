/*! \file
 *  \brief The mail of every profile (see emails.h).
 */
#include "emails.h"
#include "pst_messages.h"
#include "mbox_mail.h"
#include "conversions.h"
#include "sha.h"
#include <cwctype>
#include <filesystem>
#include <fstream>

const wchar_t OUTLOOK_FILES_FOLDER[] = L"\\Documents\\Outlook Files";
const wchar_t OUTLOOK_DATA_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Outlook";
const wchar_t OUTLOOK_OPENED_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook";
const wchar_t THUNDERBIRD_FOLDER[] = L"\\AppData\\Roaming\\Thunderbird\\Profiles";
const wchar_t OUTLOOK_NEW_FOLDER[] = L"\\AppData\\Local\\Microsoft\\Olk";

namespace {

/*! Writes an exported part next to the JSON and describes it: its path, size
 *  and SHA-256.
 *  @param folder its folder, relative to the output
 *  @param name its file name
 *  @param bytes its content
 *  @return the description; without "File" if it could not be written */
Json exported(const std::wstring& folder, const std::wstring& name, const std::vector<uint8_t>& bytes) {
	Json o = Json::obj();
	Sha256Stream digest;
	digest.update(bytes.data(), bytes.size());
	o.add(L"Size", Json::num((unsigned long long)bytes.size()));
	o.add(L"Sha256", Json::str(digest.hexDigest()));
	std::error_code ec;
	std::filesystem::create_directories(std::filesystem::path(conf._outputDir) / folder, ec);
	const std::wstring path = folder + L"\\" + name;
	std::ofstream out(std::filesystem::path(conf._outputDir) / path, std::ios::binary);
	out.write(reinterpret_cast<const char*>(bytes.data()), (std::streamsize)bytes.size());
	if (out) o.add(L"File", Json::str(path));
	else log(2, L"🔥Mail part not written: " + path);
	return o;
}

/*! An attachment exported and described: its rank, its name as the message
 *  gives it, its type, and its file named by the rank — never by that name.
 *  @param folder the message's folder, relative to the output
 *  @param rank its rank in the message, from 1
 *  @param name its name
 *  @param mime its MIME type
 *  @param data its bytes; nullptr when the data could not be read */
Json exportedAttachment(const std::wstring& folder, size_t rank, const std::wstring& name, const std::wstring& mime,
                        const std::vector<uint8_t>* data) {
	const std::wstring extension = plainExtension(name);
	Json x = data ? exported(folder, L"attachment_" + std::to_wstring(rank) + (extension.empty() ? L"" : L"." + extension), *data)
	              : Json::obj();
	x.add(L"Index", Json::num((unsigned long long)rank));
	if (!name.empty()) x.add(L"FileName", Json::str(name));
	if (!mime.empty()) x.add(L"MimeType", Json::str(mime));
	return x;
}

//! Adds a text field if the message holds it.
void addText(Json& o, const wchar_t* key, const std::wstring& text) {
	if (!text.empty()) o.add(key, Json::str(text));
}

//! Adds a time field (local and UTC) if the message holds it.
void addTime(Json& o, const wchar_t* key, const PstMessage& m, uint16_t id) {
	FILETIME t{};
	if (m.time(id, t)) addDate(o, key, t);
}

//! A message as its JSON record, its bodies and attachments exported to `folder`.
Json messageRecord(const PstMessage& m, const std::wstring& folder) {
	Json o = Json::obj();
	o.add(L"NodeId", Json::num((unsigned long long)m.nid));
	addText(o, L"Folder", m.folder);
	addText(o, L"MessageClass", m.text(PST_MESSAGE_CLASS));
	addText(o, L"Subject", m.subject());
	addText(o, L"SenderName", m.text(PST_SENDER_NAME));
	addText(o, L"SenderAddress", m.text(PST_SENDER_ADDRESS));
	addText(o, L"SentRepresentingName", m.text(PST_SENT_REPRESENTING_NAME));
	addText(o, L"DisplayTo", m.text(PST_DISPLAY_TO));
	addText(o, L"DisplayCc", m.text(PST_DISPLAY_CC));
	addText(o, L"DisplayBcc", m.text(PST_DISPLAY_BCC));
	addTime(o, L"Submitted", m, PST_CLIENT_SUBMIT_TIME);
	addTime(o, L"Delivered", m, PST_DELIVERY_TIME);
	addTime(o, L"Created", m, PST_CREATION_TIME);
	addTime(o, L"Modified", m, PST_LAST_MODIFICATION_TIME);
	addText(o, L"InternetMessageId", m.text(PST_INTERNET_MESSAGE_ID));
	addText(o, L"TransportHeaders", m.text(PST_TRANSPORT_HEADERS));
	if (!m.recipients.empty()) {
		static const wchar_t* const KINDS[] = { L"Originator", L"To", L"Cc", L"Bcc" };
		Json list = Json::arr();
		for (const PstRecipient& r : m.recipients) {
			Json x = Json::obj();
			addText(x, L"Name", r.name);
			addText(x, L"Address", r.address);
			if (r.type < 4) x.add(L"Kind", Json::str(KINDS[r.type]));
			else x.add(L"Kind", Json::num((unsigned long long)r.type));
			list.push(std::move(x));
		}
		o.add(L"Recipients", std::move(list));
	}
	const std::wstring body = m.text(PST_BODY);
	if (!body.empty()) {
		const std::string utf8 = encodeText(body, CP_UTF8);
		o.add(L"Body", exported(folder, L"body.txt", std::vector<uint8_t>(utf8.begin(), utf8.end())));
	}
	const auto html = m.properties.find(PST_HTML);
	if (html != m.properties.end() && !html->second.bytes.empty())
		o.add(L"Html", exported(folder, L"body.html", html->second.bytes));
	if (!m.attachments.empty()) {
		Json list = Json::arr();
		for (size_t k = 0; k < m.attachments.size(); ++k) {
			const PstAttachment& a = m.attachments[k];
			Json x = exportedAttachment(folder, k + 1, a.fileName, a.mimeType, a.dataRead ? &a.data : nullptr);
			if (a.method) x.add(L"Method", Json::num((unsigned long long)a.method));
			// An embedded message: what it is, from its own properties.
			const auto subject = a.embedded.find(PST_SUBJECT);
			if (subject != a.embedded.end()) addText(x, L"EmbeddedSubject", pstValueText(subject->second));
			const auto kind = a.embedded.find(PST_MESSAGE_CLASS);
			if (kind != a.embedded.end()) addText(x, L"EmbeddedMessageClass", pstValueText(kind->second));
			list.push(std::move(x));
		}
		o.add(L"Attachments", std::move(list));
	}
	if (!m.readWhole) o.add(L"ReadWhole", Json::boolean(false));
	return o;
}

/*! An mbox message as its JSON record, its body and attachments exported:
 *  the same fields as a PST message where the message has them.
 *  @param m the message
 *  @param folder its export folder, relative to the output */
Json mboxRecord(const MimeMessage& m, const std::wstring& folder) {
	Json o = Json::obj();
	o.add(L"Offset", Json::num((unsigned long long)m.offset));
	addText(o, L"Subject", m.subject);
	// "Name <address>": the two parts apart, as a PST gives them.
	const size_t open = m.from.find(L'<'), close = m.from.find(L'>', open == std::wstring::npos ? 0 : open);
	if (open != std::wstring::npos && close != std::wstring::npos) {
		std::wstring name = m.from.substr(0, open);
		while (!name.empty() && (name.back() == L' ' || name.back() == L'"')) name.pop_back();
		while (!name.empty() && (name.front() == L' ' || name.front() == L'"')) name.erase(0, 1);
		addText(o, L"SenderName", name);
		addText(o, L"SenderAddress", m.from.substr(open + 1, close - open - 1));
	}
	else addText(o, L"SenderAddress", m.from);
	addText(o, L"DisplayTo", m.to);
	addText(o, L"DisplayCc", m.cc);
	addText(o, L"DisplayBcc", m.bcc);
	if (m.dateUtc.dwHighDateTime || m.dateUtc.dwLowDateTime) addDate(o, L"Submitted", m.dateUtc);
	addText(o, L"InternetMessageId", m.messageId);
	addText(o, L"TransportHeaders", decodeText(m.headers, CP_UTF8));
	if (!m.body.empty()) {
		const std::string utf8 = encodeText(m.body, CP_UTF8);
		o.add(L"Body", exported(folder, L"body.txt", std::vector<uint8_t>(utf8.begin(), utf8.end())));
	}
	if (!m.html.empty()) o.add(L"Html", exported(folder, L"body.html", m.html));
	if (!m.attachments.empty()) {
		Json list = Json::arr();
		for (size_t k = 0; k < m.attachments.size(); ++k)
			list.push(exportedAttachment(folder, k + 1, m.attachments[k].fileName, m.attachments[k].mimeType, &m.attachments[k].data));
		o.add(L"Attachments", std::move(list));
	}
	return o;
}

} // namespace

std::wstring plainExtension(const std::wstring& name) {
	const size_t dot = name.find_last_of(L'.');
	if (dot == std::wstring::npos || name.size() - dot - 1 < 1 || name.size() - dot - 1 > 8) return L"";
	std::wstring extension = name.substr(dot + 1);
	for (wchar_t& c : extension) {
		if (!(c < 0x80 && iswalnum(c))) return L"";
		c = (wchar_t)towlower(c);
	}
	return extension;
}

HRESULT Emails::getData() {
	log(0, L"ℹ️Mail :");
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		const std::wstring sid = std::get<0>(profileEntry), profile = std::get<1>(profileEntry);
		std::vector<std::filesystem::path> files = listFilesByExtension(extractedPath(profile + OUTLOOK_FILES_FOLDER), { L".pst" });
		for (const std::filesystem::path& f : listFilesByExtension(extractedPath(profile + OUTLOOK_DATA_FOLDER), { L".pst", L".ost" }))
			files.push_back(f);
		for (const std::filesystem::path& path : files) {
			const std::wstring source = originalPath(path.wstring());
			Json store = Json::obj();
			store.add(L"Type", Json::str(L"Mailbox"));
			addUser(store, sid);
			store.add(L"Source", Json::str(source));
			PstFile file;
			std::wstring why;
			if (!file.open(path.wstring(), why)) {
				store.add(L"Error", Json::str(why));
				records_.push(std::move(store));
				log(2, L"🔥Mailbox not read (" + why + L"): " + source);
				continue;
			}
			const std::wstring base = L"emails\\" + sid + L"\\" + path.filename().wstring();
			size_t count = 0, unreadable = 0;
			const bool whole = forEachPstMessage(file, [&](PstMessage& m) {
				Json o = messageRecord(m, base + L"\\" + std::to_wstring(m.nid));
				Json record = Json::obj();
				record.add(L"Type", Json::str(L"Message"));
				addUser(record, sid);
				record.add(L"Source", Json::str(source));
				record.merge(o);
				records_.push(std::move(record));
				++count;
			}, unreadable);
			store.add(L"Kind", Json::str(file.kind()));
			store.add(L"Version", Json::num((unsigned long long)file.version()));
			store.add(L"MessageCount", Json::num((unsigned long long)count));
			if (unreadable) store.add(L"UnreadableMessages", Json::num((unsigned long long)unreadable));
			if (!whole) store.add(L"NodeTreeWhole", Json::boolean(false));
			records_.push(std::move(store));
			log(2, L"❇️" + source + L" : " + std::to_wstring(count) + L" message(s)");
		}
		readThunderbird(sid, profile);
	}
	return ERROR_SUCCESS;
}

void Emails::readThunderbird(const std::wstring& sid, const std::wstring& profile) {
	const std::filesystem::path root = extractedPath(profile + THUNDERBIRD_FOLDER);
	std::error_code ec;
	if (!std::filesystem::is_directory(root, ec)) return;
	// A folder is an mbox file without extension, under Mail or ImapMail (subfolders in <name>.sbd).
	size_t rank = 0;
	for (auto it = std::filesystem::recursive_directory_iterator(root, ec); !ec && it != std::filesystem::recursive_directory_iterator();
	     it.increment(ec)) {
		if (it.depth() > 12) { it.disable_recursion_pending(); continue; }
		if (!it->is_regular_file(ec) || it->path().has_extension()) continue;
		const std::wstring relative = it->path().lexically_relative(root).wstring();
		if (relative.find(L"\\Mail\\") == std::wstring::npos && relative.find(L"\\ImapMail\\") == std::wstring::npos) continue;
		const std::wstring source = originalPath(it->path().wstring());
		const std::wstring base = L"emails\\" + sid + L"\\mbox_" + std::to_wstring(++rank);
		size_t count = 0, skipped = 0;
		const bool mbox = forEachMboxMessage(it->path().wstring(), [&](MimeMessage& m) {
			Json record = Json::obj();
			record.add(L"Type", Json::str(L"Message"));
			addUser(record, sid);
			record.add(L"Source", Json::str(source));
			record.add(L"Folder", Json::str(relative));
			record.merge(mboxRecord(m, base + L"\\" + std::to_wstring(m.offset)));
			records_.push(std::move(record));
			++count;
		}, skipped);
		if (!mbox) continue;   // an empty folder, or a file that is not an mbox
		Json store = Json::obj();
		store.add(L"Type", Json::str(L"Mailbox"));
		addUser(store, sid);
		store.add(L"Source", Json::str(source));
		store.add(L"Kind", Json::str(L"mbox"));
		store.add(L"MessageCount", Json::num((unsigned long long)count));
		if (skipped) store.add(L"SkippedMessages", Json::num((unsigned long long)skipped));
		records_.push(std::move(store));
		log(2, L"❇️" + source + L" : " + std::to_wstring(count) + L" message(s)");
	}
}

HRESULT Emails::toJson() {
	return writeJsonFile("emails.json", records_);
}

void Emails::clear() {
	records_ = Json::arr();
}

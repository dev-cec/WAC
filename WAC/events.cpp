#include "events.h"
#include "evtx.h"
#include "event_messages.h"
#include <cwchar>

/*! \file
 *  \brief Filling of the events from the decoded XML.
 *
 *  See events.h for the processing chain and what the offline reading brings.
 *  The comments here bear on the correspondence between a record's XML and the
 *  output fields.
 */

namespace {

//! An integer returned as JSON, or `null` if the text is not one.
Json count(const std::wstring& text) {
	if (text.empty()) return Json::null();
	wchar_t* end = nullptr;
	const long long v = wcstoll(text.c_str(), &end, 10);
	if (!end || *end != L'\0') return Json::null();   // not an integer: no guessing
	return Json::num(v);
}

//! A string returned as JSON, or `null` if it is empty.
Json string(const std::wstring& text) {
	return text.empty() ? Json::null() : Json::str(text);
}

/*! Data specific to the event, as an array of values.
 *
 *  Two forms exist in the logs: `<EventData>` with `<Data>` elements (the more
 *  common one) and `<UserData>`, where the provider puts a subtree of its own.
 *
 *  The old collection through the API asked only for `Event/EventData/Data`. On
 *  an event in `UserData`, that rendering context fills nothing, and the value
 *  was read all the same: the buffer not being reset, the event inherited the
 *  data of ANOTHER event. Seen on a real collection: the clearing of a log
 *  (1102) — one of the most significant events of an intrusion — carried
 *  "C:\WINDOWS\ServiceState\wmansvc", which does not belong to it. A defect of
 *  that kind does not show: the JSON is valid, the key is the right one, only
 *  the value is wrong.
 *
 *  Both forms are now read, each from its own subtree.
 */
Json eventData(const XmlNode& root, std::vector<std::wstring>* brutes) {
	Json arr = Json::arr();

	if (const XmlNode* ed = root.child(L"EventData")) {
		/*  THE FIELD'S NAME IS HALF THE INFORMATION. Modern providers name every
		    piece of data — `TargetUserName`, `NewProcessId`, `CommandLine` — and
		    that name was thrown away: an array of raw values forces one to know
		    by heart the order of the fields of every event identifier to know
		    what one is reading. Classic events, for their part, have none: their
		    data are purely positional, and the name is then omitted rather than
		    invented. */
		for (const XmlNode* d : ed->descendants(L"Data")) {
			Json o = Json::obj();
			const std::wstring name = d->attribute(L"Name");
			if (!name.empty()) o.add(L"Name", Json::str(name));
			o.add(L"Value", Json::str(d->text));
			arr.push(std::move(o));
			if (brutes) brutes->push_back(d->text);
		}
		if (const XmlNode* bin = ed->child(L"Binary"))
			if (!bin->text.empty()) {
				Json o = Json::obj();
				o.add(L"Name",  Json::str(L"Binary"));
				o.add(L"Value", Json::str(bin->text));
				arr.push(std::move(o));
				if (brutes) brutes->push_back(bin->text);
			}
		return arr;
	}

	if (const XmlNode* ud = root.child(L"UserData")) {
		/*  A free subtree: the leaves that carry text are read, prefixed by their
		 *  element name. Without that name, "0x32cfb" on its own would not say
		 *  that it is a session identifier. */
		std::vector<const XmlNode*> pile{ ud };
		while (!pile.empty()) {
			const XmlNode* n = pile.back();
			pile.pop_back();
			if (n->children.empty()) {
				// Same form as EventData: the element's name SERVES as the field name,
				// instead of being glued to the value by an "=" that a consumer
				// would have to split again.
				if (!n->text.empty()) {
					Json o = Json::obj();
					o.add(L"Name",  Json::str(n->name));
					o.add(L"Value", Json::str(n->text));
					arr.push(std::move(o));
					if (brutes) brutes->push_back(n->text);
				}
			}
			else {
				// Document order: the stack is filled the other way round.
				for (size_t i = n->children.size(); i-- > 0;) pile.push_back(n->children[i].get());
			}
		}
		return arr;
	}
	return arr;
}

} // namespace

Event::Event(const XmlNode& root, const std::wstring& channel,
             unsigned long long id, const std::wstring& fileName) {
	evtSourceLog = string(fileName);
	const XmlNode* sys = root.child(L"System");
	if (!sys) {
		// A record without a System section: at least its number is kept, so that the
		// report does not lose it silently.
		evtSystemEventRecordId = Json::num(id);
		evtSystemChannel = string(channel);
		evtEventData = eventData(root, &rawValues);
		return;
	}

	if (const XmlNode* p = sys->child(L"Provider")) {
		evtSystemProviderName = string(p->attribute(L"Name"));
		evtSystemProviderGuid = string(p->attribute(L"Guid"));
		guidPourMessage = p->attribute(L"Guid");
		// Some classic providers carry only EventSourceName.
		if (evtSystemProviderName.kind() == Json::Kind::Null)
			evtSystemProviderName = string(p->attribute(L"EventSourceName"));
	}
	if (const XmlNode* e = sys->child(L"EventID")) {
		evtSystemEventID = count(e->text);
		evtSystemQualifiers = count(e->attribute(L"Qualifiers"));
		idPourMessage = (uint16_t)wcstoul(e->text.c_str(), nullptr, 10);
	}
	evtSystemLevel   = count(sys->textOf(L"Level"));
	evtSystemTask    = count(sys->textOf(L"Task"));
	evtSystemOpcode  = count(sys->textOf(L"Opcode"));
	evtSystemVersion = count(sys->textOf(L"Version"));
	versionPourMessage = (uint8_t)wcstoul(sys->textOf(L"Version").c_str(), nullptr, 10);
	// Keywords: kept as text, as written in the log — it is a bit field, whose
	// numeric value says nothing more.
	evtSystemKeywords = string(sys->textOf(L"Keywords"));

	if (const XmlNode* t = sys->child(L"TimeCreated"))
		evtSystemTimeCreated = string(t->attribute(L"SystemTime"));

	// The binary header carries the same number: it serves as a fallback, and it is
	// always present even when the event's XML does not write it.
	evtSystemEventRecordId = count(sys->textOf(L"EventRecordID"));
	if (evtSystemEventRecordId.kind() == Json::Kind::Null)
		evtSystemEventRecordId = Json::num(id);

	if (const XmlNode* c = sys->child(L"Correlation")) {
		evtSystemActivityID = string(c->attribute(L"ActivityID"));
		evtSystemRelatedActivityID = string(c->attribute(L"RelatedActivityID"));
	}
	if (const XmlNode* x = sys->child(L"Execution")) {
		evtSystemProcessID = count(x->attribute(L"ProcessID"));
		evtSystemThreadID  = count(x->attribute(L"ThreadID"));
	}
	evtSystemChannel  = string(sys->textOf(L"Channel"));
	if (evtSystemChannel.kind() == Json::Kind::Null) evtSystemChannel = string(channel);
	evtSystemComputer = string(sys->textOf(L"Computer"));
	if (const XmlNode* s = sys->child(L"Security"))
		evtSystemUserID = string(s->attribute(L"UserID"));

	evtEventData = eventData(root, &rawValues);
}

Json Event::toJson() const {
	Json o = Json::obj();
	o.add(L"EvtSystemProviderName",      evtSystemProviderName);
	o.add(L"EvtSystemProviderGuid",      evtSystemProviderGuid);
	o.add(L"EvtSystemEventID",           evtSystemEventID);
	o.add(L"EvtSystemQualifiers",        evtSystemQualifiers);
	o.add(L"EvtSystemLevel",             evtSystemLevel);
	o.add(L"EvtSystemTask",              evtSystemTask);
	o.add(L"EvtSystemOpcode",            evtSystemOpcode);
	o.add(L"EvtSystemKeywords",          evtSystemKeywords);
	o.add(L"EvtSystemTimeCreated",       evtSystemTimeCreated);
	o.add(L"EvtSystemEventRecordId",     evtSystemEventRecordId);
	o.add(L"EvtSystemActivityID",        evtSystemActivityID);
	o.add(L"EvtSystemRelatedActivityID", evtSystemRelatedActivityID);
	o.add(L"EvtSystemProcessID",         evtSystemProcessID);
	o.add(L"EvtSystemThreadID",          evtSystemThreadID);
	o.add(L"EvtSystemChannel",           evtSystemChannel);
	o.add(L"EvtSystemComputer",          evtSystemComputer);
	o.add(L"EvtSystemUserID",            evtSystemUserID);
	o.add(L"EvtSystemVersion",           evtSystemVersion);
	o.add(L"EvtEventData",               evtEventData);
	o.add(L"EvtSourceLog",               evtSourceLog);
	o.add(L"EvtEventMessage",            evtEventMessage);
	return o;
}

HRESULT Events::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Events : ");
	log(0, L"*******************************************************************************************************************");

	const std::wstring directory =
		extractedPath(L"\\Windows\\System32\\winevt\\Logs");
	const std::vector<std::filesystem::path> logs =
		listFilesByExtension(directory, { L".evtx" });

	if (logs.empty()) {
		/* No log extracted. This is NOT "no event": it is an extraction that did not
		   happen, and the report must tell the two apart. */
		log(2, L"🔥No .evtx log extracted under " + directory, ERROR_FILE_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	MessagesInit();

	JsonArrayWriter output("events.json");
	if (!output.isOpen()) return E_FAIL;

	unsigned long long unreadableLogs = 0, incomplete = 0;
	size_t iFile = 0;
	for (const std::filesystem::path& logFile : logs) {
		const std::wstring fileName = logFile.filename().wstring();
		const std::wstring channel = EvtxChannelFromFileName(fileName);
		printProgressStep(L"EventLog " + channel, ++iFile, logs.size());
		log(1, L"➕Journal");
		log(2, L"❇️Journal : " + channel);

		EvtxSummary summary;
		const HRESULT hr = EvtxReadFile(logFile.wstring(),
			[&](const EvtxRecord& e) {
				const std::unique_ptr<XmlNode> root = xmlParse(e.xml);
				if (!root) {
					/* The XML is rebuilt by evtx.cpp: if it cannot be parsed, it is the
					   decoding that went wrong, not the log. That is reported
					   without stopping the reading. */
					++unreadable;
					log(3, L"🔈Event " + std::to_wstring(e.id)
					       + L": XML cannot be parsed (" + channel + L")");
					return true;
				}
				Event ev(*root, channel, e.id, fileName);
				/*  PLAIN-TEXT MESSAGE. Rebuilt from the provider's resources, which
				    only the API could do until now. The resource file is
				    extracted on demand, once per provider (see
				    event_messages.h). */
				if (!ev.guidPourMessage.empty() && ev.idPourMessage != 0) {
					const std::wstring phrase = EventMessage(
						ev.guidPourMessage, ev.idPourMessage, ev.versionPourMessage,
						ev.rawValues);
					if (!phrase.empty()) ev.evtEventMessage = Json::str(phrase);
				}
				/*  A record whose System section is incomplete is the sign of a
				    decoding that went wrong on THAT record. The raw XML goes to
				    the log: without it, the event reads as poor in data whereas
				    it is badly read — and the defect stays impossible to
				    diagnose. */
				if (ev.evtSystemProviderName.kind() == Json::Kind::Null
				    || ev.evtSystemTimeCreated.kind() == Json::Kind::Null) {
					++incomplete;
					log(2, L"🔥Event " + std::to_wstring(e.id) + L" de "
					     + fileName + L" : section System incomplete");
					log(3, L"🔈XML : " + e.xml.substr(0, 2000));
				}
				output.add(ev.toJson());
				++read;
				return true;
			}, &summary);

		unreadable += summary.unreadable;
		if (FAILED(hr)) {
			++unreadableLogs;
			log(2, L"🔥Log unreadable: " + fileName, hr);
		}
		else ++files;
		// The per-log diagnosis makes it possible to tell an empty channel from a
		// channel that was not read — two situations that "0 events" confuses.
		log(2, L"❇️" + channel + L" : " + summary.diagnostic);
	}
	printProgressEnd();

	const HRESULT closing = output.close();
	log(2, L"❇️Events written: " + std::to_wstring(read)
	       + L" (" + std::to_wstring(files) + L"/"
	       + std::to_wstring(logs.size()) + L" logs)");
	if (unreadable)
		log(2, L"🔥Records discarded: " + std::to_wstring(unreadable));
	if (incomplete)
		log(2, L"🔥Records with an incomplete System section: "
		     + std::to_wstring(incomplete));

	{
		size_t nbF = 0, failuresF = 0;
		unsigned long long resolved = 0, bytes = 0;
		MessagesSummary(&nbF, &failuresF, &resolved, &bytes);
		log(2, L"❇️Messages resolved: " + std::to_wstring(resolved) + L" out of "
		     + std::to_wstring(read) + L" event(s), "
		     + std::to_wstring(nbF) + L" provider(s) consulted, "
		     + std::to_wstring(failuresF) + L" without resources, "
		     + std::to_wstring(bytes / 1024 / 1024) + L" MiB extracted");
		MessagesRelease();
	}

	if (FAILED(closing)) return closing;
	if (files == 0) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	return (unreadable || unreadableLogs) ? S_FALSE : ERROR_SUCCESS;
}

#include "events.h"
#include "evtx.h"
#include "event_messages.h"
#include <cwchar>

/*  events.cpp — remplissage des événements depuis le XML décodé.
 *
 *  Voir events.h pour la chaîne de traitement et ce que la lecture hors ligne
 *  apporte. Les commentaires ici portent sur la correspondance entre le XML d'un
 *  enregistrement et les champs de sortie.
 */

namespace {

//! Nombre entier rendu en JSON, ou `null` si le texte n'en est pas un.
Json count(const std::wstring& text) {
	if (text.empty()) return Json::null();
	wchar_t* end = nullptr;
	const long long v = wcstoll(text.c_str(), &end, 10);
	if (!end || *end != L'\0') return Json::null();   // pas un entier : on ne devine pas
	return Json::num(v);
}

//! Chaîne rendue en JSON, ou `null` si elle est vide.
Json string(const std::wstring& text) {
	return text.empty() ? Json::null() : Json::str(text);
}

/*! Données propres à l'événement, sous forme de tableau de valeurs.
 *
 *  Deux formes existent dans les journaux : `<EventData>` avec des `<Data>`
 *  (la plus courante) et `<UserData>`, où le fournisseur place un sous-arbre de
 *  son cru.
 *
 *  L'ancienne collecte par API ne demandait que `Event/EventData/Data`. Sur un
 *  événement en `UserData`, ce contexte de rendu ne remplit rien, et la valeur
 *  était lue quand même : le tampon n'étant pas réinitialisé, l'événement
 *  héritait de la donnée d'un AUTRE événement. Relevé sur une collecte réelle :
 *  l'effacement d'un journal (1102) — l'un des événements les plus
 *  significatifs d'une intrusion — portait « C:\WINDOWS\ServiceState\wmansvc »,
 *  qui ne lui appartient pas. Un défaut de ce genre ne se voit pas : le JSON est
 *  valide, la clé est la bonne, seule la valeur est fausse.
 *
 *  Les deux formes sont désormais lues, chacune depuis son propre sous-arbre.
 */
Json eventData(const XmlNode& root, std::vector<std::wstring>* brutes) {
	Json arr = Json::arr();

	if (const XmlNode* ed = root.child(L"EventData")) {
		/*  LE NOM DU CHAMP EST LA MOITIÉ DE L'INFORMATION. Les fournisseurs
		    modernes nomment chaque donnée — `TargetUserName`, `NewProcessId`,
		    `CommandLine` — et ce nom était jeté : un tableau de valeurs brutes
		    oblige à connaître par cœur l'ordre des champs de chaque identifiant
		    d'événement pour savoir ce qu'on lit. Les événements classiques, eux,
		    n'en ont pas : leurs données sont purement positionnelles, et le nom
		    est alors omis plutôt qu'inventé. */
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
		/*  Sous-arbre libre : on relève les feuilles porteuses de texte, en les
		 *  préfixant de leur nom d'élément. Sans ce nom, « 0x32cfb » seul ne
		 *  dirait pas qu'il s'agit d'un identifiant de session. */
		std::vector<const XmlNode*> pile{ ud };
		while (!pile.empty()) {
			const XmlNode* n = pile.back();
			pile.pop_back();
			if (n->children.empty()) {
				// Meme forme que EventData : le nom de l'element FAIT office de
				// nom de champ, au lieu d'etre colle a la valeur par un « = »
				// qu'un consommateur devrait redecouper.
				if (!n->text.empty()) {
					Json o = Json::obj();
					o.add(L"Name",  Json::str(n->name));
					o.add(L"Value", Json::str(n->text));
					arr.push(std::move(o));
					if (brutes) brutes->push_back(n->text);
				}
			}
			else {
				// Ordre du document : la pile est remplie à l'envers.
				for (size_t i = n->children.size(); i-- > 0;) pile.push_back(n->children[i].get());
			}
		}
		return arr;
	}
	return arr;
}

} // namespace

Event::Event(const XmlNode& root, const std::wstring& canal,
             unsigned long long id, const std::wstring& fileName) {
	evtSourceLog = string(fileName);
	const XmlNode* sys = root.child(L"System");
	if (!sys) {
		// Enregistrement sans section System : on garde au moins son numéro,
		// pour que le rapport ne le perde pas silencieusement.
		evtSystemEventRecordId = Json::num(id);
		evtSystemChannel = string(canal);
		evtEventData = eventData(root, &rawValues);
		return;
	}

	if (const XmlNode* p = sys->child(L"Provider")) {
		evtSystemProviderName = string(p->attribute(L"Name"));
		evtSystemProviderGuid = string(p->attribute(L"Guid"));
		guidPourMessage = p->attribute(L"Guid");
		// Certains fournisseurs classiques ne portent que EventSourceName.
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
	// Mots clés : conservés en texte, tels qu'écrits dans le journal — c'est un
	// champ de bits, dont la valeur numérique ne dit rien de plus.
	evtSystemKeywords = string(sys->textOf(L"Keywords"));

	if (const XmlNode* t = sys->child(L"TimeCreated"))
		evtSystemTimeCreated = string(t->attribute(L"SystemTime"));

	// L'en-tête binaire porte le même numéro : il sert de recours, et il est
	// toujours présent même quand le XML de l'événement ne l'écrit pas.
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
	if (evtSystemChannel.kind() == Json::Kind::Null) evtSystemChannel = string(canal);
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
		/* Aucun journal extrait. Ce n'est PAS « aucun événement » : c'est une
		   extraction qui n'a pas eu lieu, et le rapport doit les distinguer. */
		log(2, L"🔥Aucun journal .evtx extrait sous " + directory, ERROR_FILE_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	MessagesInit();

	JsonArrayWriter output("events.json");
	if (!output.open()) return E_FAIL;

	unsigned long long unreadableLogs = 0, incomplete = 0;
	size_t iFile = 0;
	for (const std::filesystem::path& logFile : logs) {
		const std::wstring fileName = logFile.filename().wstring();
		const std::wstring canal = EvtxChannelFromFileName(fileName);
		printProgressStep(L"EventLog " + canal, ++iFile, logs.size());
		log(1, L"➕Journal");
		log(2, L"❇️Journal : " + canal);

		EvtxSummary summary;
		const HRESULT hr = EvtxReadFile(logFile.wstring(),
			[&](const EvtxRecord& e) {
				const std::unique_ptr<XmlNode> root = xmlParse(e.xml);
				if (!root) {
					/* Le XML est reconstruit par evtx.cpp : s'il n'est pas
					   analysable, c'est le décodage qui a dérivé, pas le
					   journal. On le signale sans arrêter la lecture. */
					++unreadable;
					log(3, L"🔈Evenement " + std::to_wstring(e.id)
					       + L" : XML non analysable (" + canal + L")");
					return true;
				}
				Event ev(*root, canal, e.id, fileName);
				/*  MESSAGE EN CLAIR. Reconstitué depuis les ressources du
				    fournisseur, ce que seule l'API savait faire jusqu'ici. Le
				    fichier de ressources est extrait à la demande, une fois par
				    fournisseur (cf. event_messages.h). */
				if (!ev.guidPourMessage.empty() && ev.idPourMessage != 0) {
					const std::wstring phrase = EventMessage(
						ev.guidPourMessage, ev.idPourMessage, ev.versionPourMessage,
						ev.rawValues);
					if (!phrase.empty()) ev.evtEventMessage = Json::str(phrase);
				}
				/*  Un enregistrement dont la section System est incomplete est le
				    signe d'un decodage qui a devie sur CE record. Le XML brut part
				    au journal : sans lui, l'evenement se lit comme pauvre en
				    donnees alors qu'il est mal lu — et le defaut reste
				    indiagnosticable. */
				if (ev.evtSystemProviderName.kind() == Json::Kind::Null
				    || ev.evtSystemTimeCreated.kind() == Json::Kind::Null) {
					++incomplete;
					log(2, L"🔥Evenement " + std::to_wstring(e.id) + L" de "
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
			log(2, L"🔥Journal illisible : " + fileName, hr);
		}
		else ++files;
		// Le diagnostic par journal permet de distinguer un canal vide d'un
		// canal non lu — deux situations que « 0 événement » confond.
		log(2, L"❇️" + canal + L" : " + summary.diagnostic);
	}
	printProgressEnd();

	const HRESULT closing = output.close();
	log(2, L"❇️Evenements ecrits : " + std::to_wstring(read)
	       + L" (" + std::to_wstring(files) + L"/"
	       + std::to_wstring(logs.size()) + L" journaux)");
	if (unreadable)
		log(2, L"🔥Enregistrements ecartes : " + std::to_wstring(unreadable));
	if (incomplete)
		log(2, L"🔥Enregistrements a section System incomplete : "
		     + std::to_wstring(incomplete));

	{
		size_t nbF = 0, failuresF = 0;
		unsigned long long resolved = 0, bytes = 0;
		MessagesSummary(&nbF, &failuresF, &resolved, &bytes);
		log(2, L"❇️Messages resolus : " + std::to_wstring(resolved) + L" sur "
		     + std::to_wstring(read) + L" evenement(s), "
		     + std::to_wstring(nbF) + L" fournisseur(s) consulte(s), "
		     + std::to_wstring(failuresF) + L" sans ressources, "
		     + std::to_wstring(bytes / 1024 / 1024) + L" Mio extraits");
		MessagesRelease();
	}

	if (FAILED(closing)) return closing;
	if (files == 0) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	return (unreadable || unreadableLogs) ? S_FALSE : ERROR_SUCCESS;
}

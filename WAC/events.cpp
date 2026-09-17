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
Json nombre(const std::wstring& texte) {
	if (texte.empty()) return Json::null();
	wchar_t* fin = nullptr;
	const long long v = wcstoll(texte.c_str(), &fin, 10);
	if (!fin || *fin != L'\0') return Json::null();   // pas un entier : on ne devine pas
	return Json::num(v);
}

//! Chaîne rendue en JSON, ou `null` si elle est vide.
Json chaine(const std::wstring& texte) {
	return texte.empty() ? Json::null() : Json::str(texte);
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
Json donneesEvenement(const XmlNode& racine, std::vector<std::wstring>* brutes) {
	Json arr = Json::arr();

	if (const XmlNode* ed = racine.enfant(L"EventData")) {
		/*  LE NOM DU CHAMP EST LA MOITIÉ DE L'INFORMATION. Les fournisseurs
		    modernes nomment chaque donnée — `TargetUserName`, `NewProcessId`,
		    `CommandLine` — et ce nom était jeté : un tableau de valeurs brutes
		    oblige à connaître par cœur l'ordre des champs de chaque identifiant
		    d'événement pour savoir ce qu'on lit. Les événements classiques, eux,
		    n'en ont pas : leurs données sont purement positionnelles, et le nom
		    est alors omis plutôt qu'inventé. */
		for (const XmlNode* d : ed->descendants(L"Data")) {
			Json o = Json::obj();
			const std::wstring nom = d->attribut(L"Name");
			if (!nom.empty()) o.add(L"Name", Json::str(nom));
			o.add(L"Value", Json::str(d->texte));
			arr.push(std::move(o));
			if (brutes) brutes->push_back(d->texte);
		}
		if (const XmlNode* bin = ed->enfant(L"Binary"))
			if (!bin->texte.empty()) {
				Json o = Json::obj();
				o.add(L"Name",  Json::str(L"Binary"));
				o.add(L"Value", Json::str(bin->texte));
				arr.push(std::move(o));
				if (brutes) brutes->push_back(bin->texte);
			}
		return arr;
	}

	if (const XmlNode* ud = racine.enfant(L"UserData")) {
		/*  Sous-arbre libre : on relève les feuilles porteuses de texte, en les
		 *  préfixant de leur nom d'élément. Sans ce nom, « 0x32cfb » seul ne
		 *  dirait pas qu'il s'agit d'un identifiant de session. */
		std::vector<const XmlNode*> pile{ ud };
		while (!pile.empty()) {
			const XmlNode* n = pile.back();
			pile.pop_back();
			if (n->enfants.empty()) {
				// Meme forme que EventData : le nom de l'element FAIT office de
				// nom de champ, au lieu d'etre colle a la valeur par un « = »
				// qu'un consommateur devrait redecouper.
				if (!n->texte.empty()) {
					Json o = Json::obj();
					o.add(L"Name",  Json::str(n->nom));
					o.add(L"Value", Json::str(n->texte));
					arr.push(std::move(o));
					if (brutes) brutes->push_back(n->texte);
				}
			}
			else {
				// Ordre du document : la pile est remplie à l'envers.
				for (size_t i = n->enfants.size(); i-- > 0;) pile.push_back(n->enfants[i].get());
			}
		}
		return arr;
	}
	return arr;
}

} // namespace

Event::Event(const XmlNode& racine, const std::wstring& canal,
             unsigned long long identifiant, const std::wstring& nomFichier) {
	evtSourceLog = chaine(nomFichier);
	const XmlNode* sys = racine.enfant(L"System");
	if (!sys) {
		// Enregistrement sans section System : on garde au moins son numéro,
		// pour que le rapport ne le perde pas silencieusement.
		evtSystemEventRecordId = Json::num(identifiant);
		evtSystemChannel = chaine(canal);
		evtEventData = donneesEvenement(racine, &valeursBrutes);
		return;
	}

	if (const XmlNode* p = sys->enfant(L"Provider")) {
		evtSystemProviderName = chaine(p->attribut(L"Name"));
		evtSystemProviderGuid = chaine(p->attribut(L"Guid"));
		guidPourMessage = p->attribut(L"Guid");
		// Certains fournisseurs classiques ne portent que EventSourceName.
		if (evtSystemProviderName.kind() == Json::Kind::Null)
			evtSystemProviderName = chaine(p->attribut(L"EventSourceName"));
	}
	if (const XmlNode* e = sys->enfant(L"EventID")) {
		evtSystemEventID = nombre(e->texte);
		evtSystemQualifiers = nombre(e->attribut(L"Qualifiers"));
		idPourMessage = (uint16_t)wcstoul(e->texte.c_str(), nullptr, 10);
	}
	evtSystemLevel   = nombre(sys->texteDe(L"Level"));
	evtSystemTask    = nombre(sys->texteDe(L"Task"));
	evtSystemOpcode  = nombre(sys->texteDe(L"Opcode"));
	evtSystemVersion = nombre(sys->texteDe(L"Version"));
	versionPourMessage = (uint8_t)wcstoul(sys->texteDe(L"Version").c_str(), nullptr, 10);
	// Mots clés : conservés en texte, tels qu'écrits dans le journal — c'est un
	// champ de bits, dont la valeur numérique ne dit rien de plus.
	evtSystemKeywords = chaine(sys->texteDe(L"Keywords"));

	if (const XmlNode* t = sys->enfant(L"TimeCreated"))
		evtSystemTimeCreated = chaine(t->attribut(L"SystemTime"));

	// L'en-tête binaire porte le même numéro : il sert de recours, et il est
	// toujours présent même quand le XML de l'événement ne l'écrit pas.
	evtSystemEventRecordId = nombre(sys->texteDe(L"EventRecordID"));
	if (evtSystemEventRecordId.kind() == Json::Kind::Null)
		evtSystemEventRecordId = Json::num(identifiant);

	if (const XmlNode* c = sys->enfant(L"Correlation")) {
		evtSystemActivityID = chaine(c->attribut(L"ActivityID"));
		evtSystemRelatedActivityID = chaine(c->attribut(L"RelatedActivityID"));
	}
	if (const XmlNode* x = sys->enfant(L"Execution")) {
		evtSystemProcessID = nombre(x->attribut(L"ProcessID"));
		evtSystemThreadID  = nombre(x->attribut(L"ThreadID"));
	}
	evtSystemChannel  = chaine(sys->texteDe(L"Channel"));
	if (evtSystemChannel.kind() == Json::Kind::Null) evtSystemChannel = chaine(canal);
	evtSystemComputer = chaine(sys->texteDe(L"Computer"));
	if (const XmlNode* s = sys->enfant(L"Security"))
		evtSystemUserID = chaine(s->attribut(L"UserID"));

	evtEventData = donneesEvenement(racine, &valeursBrutes);
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

	const std::wstring repertoire =
		cheminExtrait(L"\\Windows\\System32\\winevt\\Logs");
	const std::vector<std::filesystem::path> journaux =
		listFilesByExtension(repertoire, { L".evtx" });

	if (journaux.empty()) {
		/* Aucun journal extrait. Ce n'est PAS « aucun événement » : c'est une
		   extraction qui n'a pas eu lieu, et le rapport doit les distinguer. */
		log(2, L"🔥Aucun journal .evtx extrait sous " + repertoire, ERROR_FILE_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	}

	MessagesInitialiser();

	EcrivainJsonTableau sortie("events.json");
	if (!sortie.ouvert()) return E_FAIL;

	unsigned long long journauxIllisibles = 0, incomplets = 0;
	size_t iFichier = 0;
	for (const std::filesystem::path& journal : journaux) {
		const std::wstring nomFichier = journal.filename().wstring();
		const std::wstring canal = EvtxCanalDepuisNomFichier(nomFichier);
		printProgressStep(L"EventLog " + canal, ++iFichier, journaux.size());
		log(1, L"➕Journal");
		log(2, L"❇️Journal : " + canal);

		EvtxBilan bilan;
		const HRESULT hr = EvtxLireFichier(journal.wstring(),
			[&](const EvtxEnregistrement& e) {
				const std::unique_ptr<XmlNode> racine = xmlAnalyser(e.xml);
				if (!racine) {
					/* Le XML est reconstruit par evtx.cpp : s'il n'est pas
					   analysable, c'est le décodage qui a dérivé, pas le
					   journal. On le signale sans arrêter la lecture. */
					++illisibles;
					log(3, L"🔈Evenement " + std::to_wstring(e.identifiant)
					       + L" : XML non analysable (" + canal + L")");
					return true;
				}
				Event ev(*racine, canal, e.identifiant, nomFichier);
				/*  MESSAGE EN CLAIR. Reconstitué depuis les ressources du
				    fournisseur, ce que seule l'API savait faire jusqu'ici. Le
				    fichier de ressources est extrait à la demande, une fois par
				    fournisseur (cf. event_messages.h). */
				if (!ev.guidPourMessage.empty() && ev.idPourMessage != 0) {
					const std::wstring phrase = MessageEvenement(
						ev.guidPourMessage, ev.idPourMessage, ev.versionPourMessage,
						ev.valeursBrutes);
					if (!phrase.empty()) ev.evtEventMessage = Json::str(phrase);
				}
				/*  Un enregistrement dont la section System est incomplete est le
				    signe d'un decodage qui a devie sur CE record. Le XML brut part
				    au journal : sans lui, l'evenement se lit comme pauvre en
				    donnees alors qu'il est mal lu — et le defaut reste
				    indiagnosticable. */
				if (ev.evtSystemProviderName.kind() == Json::Kind::Null
				    || ev.evtSystemTimeCreated.kind() == Json::Kind::Null) {
					++incomplets;
					log(2, L"🔥Evenement " + std::to_wstring(e.identifiant) + L" de "
					     + nomFichier + L" : section System incomplete");
					log(3, L"🔈XML : " + e.xml.substr(0, 2000));
				}
				sortie.ajouter(ev.toJson());
				++lus;
				return true;
			}, &bilan);

		illisibles += bilan.illisibles;
		if (FAILED(hr)) {
			++journauxIllisibles;
			log(2, L"🔥Journal illisible : " + nomFichier, hr);
		}
		else ++fichiers;
		// Le diagnostic par journal permet de distinguer un canal vide d'un
		// canal non lu — deux situations que « 0 événement » confond.
		log(2, L"❇️" + canal + L" : " + bilan.diagnostic);
	}
	printProgressEnd();

	const HRESULT fermeture = sortie.fermer();
	log(2, L"❇️Evenements ecrits : " + std::to_wstring(lus)
	       + L" (" + std::to_wstring(fichiers) + L"/"
	       + std::to_wstring(journaux.size()) + L" journaux)");
	if (illisibles)
		log(2, L"🔥Enregistrements ecartes : " + std::to_wstring(illisibles));
	if (incomplets)
		log(2, L"🔥Enregistrements a section System incomplete : "
		     + std::to_wstring(incomplets));

	{
		size_t nbF = 0, echecsF = 0;
		unsigned long long resolus = 0, octets = 0;
		MessagesBilan(&nbF, &echecsF, &resolus, &octets);
		log(2, L"❇️Messages resolus : " + std::to_wstring(resolus) + L" sur "
		     + std::to_wstring(lus) + L" evenement(s), "
		     + std::to_wstring(nbF) + L" fournisseur(s) consulte(s), "
		     + std::to_wstring(echecsF) + L" sans ressources, "
		     + std::to_wstring(octets / 1024 / 1024) + L" Mio extraits");
		MessagesLiberer();
	}

	if (FAILED(fermeture)) return fermeture;
	if (fichiers == 0) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
	return (illisibles || journauxIllisibles) ? S_FALSE : ERROR_SUCCESS;
}

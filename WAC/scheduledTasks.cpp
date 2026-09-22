/*  scheduledTasks.cpp — voir scheduledTasks.h. */
#include "scheduledTasks.h"
#include "xml_light.h"
#include <filesystem>
#include <map>
#include <sddl.h>

namespace {

//! Racine des définitions de tâches, relative au point d'extraction.
const wchar_t* SOUS_DOSSIER_TASKS = L"\\Windows\\System32\\Tasks";

/*! Historique d'exécution d'une tâche, lu dans TaskCache. */
struct Historique {
	FILETIME derniereExecutionUtc = { 0 };
	LONG     dernierResultat = 0;
	bool     trouve = false;
};

/*! Décode la valeur binaire `DynamicInfo` du TaskCache.
 *
 *  Disposition (stable depuis Vista, longueur variable selon la version) :
 *    0x00 version (4)
 *    0x04 dernière inscription       (FILETIME, 8)
 *    0x0C dernière exécution         (FILETIME, 8)
 *    0x14 code de retour             (4)
 *    0x18 inconnu                    (4)
 *    0x1C dernière exécution réussie (FILETIME, 8) — versions récentes
 *
 *  La taille est vérifiée avant lecture : la valeur vient du registre de la
 *  machine examinée, donc d'une source non fiable.
 */
Historique decoderDynamicInfo(const BYTE* donnees, DWORD taille) {
	Historique h;
	if (!donnees || taille < 0x18) return h;
	const ULONGLONG brut = *reinterpret_cast<const ULONGLONG*>(donnees + 0x0C);
	h.derniereExecutionUtc.dwLowDateTime  = (DWORD)(brut & 0xFFFFFFFFULL);
	h.derniereExecutionUtc.dwHighDateTime = (DWORD)(brut >> 32);
	h.dernierResultat = *reinterpret_cast<const LONG*>(donnees + 0x14);
	h.trouve = true;
	return h;
}

/*! Parcourt `TaskCache\Tree` et relève le GUID de chaque tâche.
 *
 *  L'arbre reproduit l'arborescence des dossiers de tâches : le parcours est donc
 *  récursif, avec un garde-fou de profondeur (un index de registre corrompu
 *  pourrait boucler).
 */
void parcourirArbre(ORHKEY cle, const std::wstring& chemin,
                    std::map<std::wstring, std::wstring>& idParChemin,
                    unsigned profondeurRestante) {
	if (!cle || profondeurRestante == 0) return;

	// Une feuille porte la valeur Id ; une branche porte des sous-clés.
	std::wstring id;
	if (getRegSzValue(cle, L"", L"Id", &id) == ERROR_SUCCESS && !id.empty())
		idParChemin.emplace(enMinuscules(chemin), id);

	DWORD nSousCles = 0;
	if (ORQueryInfoKey(cle, NULL, NULL, &nSousCles, NULL, NULL, NULL,
	                   NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
		return;

	for (DWORD i = 0; i < nSousCles; ++i) {
		WCHAR nom[MAX_KEY_NAME] = L"";
		DWORD taille = MAX_KEY_NAME;
		if (OREnumKey(cle, i, nom, &taille, NULL, NULL, NULL) != ERROR_SUCCESS) continue;
		ORHKEY sousCle = NULL;
		if (OROpenKey(cle, nom, &sousCle) != ERROR_SUCCESS) continue;
		parcourirArbre(sousCle, chemin + L"\\" + nom, idParChemin, profondeurRestante - 1);
		ORCloseKey(sousCle);
	}
}

/*! Lit le TaskCache : chemin de tâche -> historique d'exécution. */
std::map<std::wstring, Historique> lireTaskCache() {
	std::map<std::wstring, Historique> resultat;
	if (!conf.Software) {
		log(2, L"🔥TaskCache : ruche SOFTWARE indisponible, historique non collecte");
		return resultat;
	}

	const std::wstring racine = L"Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache";
	ORHKEY cleArbre = NULL;
	if (OROpenKey(conf.Software, (racine + L"\\Tree").c_str(), &cleArbre) != ERROR_SUCCESS) {
		log(2, L"🔥TaskCache\\Tree introuvable : historique d'execution non collecte");
		return resultat;
	}

	std::map<std::wstring, std::wstring> idParChemin;
	parcourirArbre(cleArbre, L"", idParChemin, 16);
	ORCloseKey(cleArbre);
	log(2, L"❇️TaskCache : " + std::to_wstring(idParChemin.size()) + L" tache(s) referencee(s)");

	for (const std::pair<const std::wstring, std::wstring>& e : idParChemin) {
		const std::wstring cleTache = racine + L"\\Tasks\\" + e.second;
		LPBYTE donnees = NULL;
		DWORD taille = 0;
		if (getRegBinaryValue(conf.Software, cleTache.c_str(), L"DynamicInfo",
		                      &donnees, &taille) == ERROR_SUCCESS) {
			resultat.emplace(e.first, decoderDynamicInfo(donnees, taille));
			delete[] donnees;
		}
	}
	return resultat;
}

//! Vrai si la chaîne ressemble à un SID (« S-1-… »).
bool estUnSid(const std::wstring& v) {
	return v.size() > 2 && (v[0] == L'S' || v[0] == L's') && v[1] == L'-';
}

/*! Remplit une tâche depuis son document XML. */
void lireDefinition(const XmlNode& racine, ScheduledTask& t) {
	if (const XmlNode* info = racine.enfant(L"RegistrationInfo")) {
		t.author           = info->texteDe(L"Author");
		t.description      = info->texteDe(L"Description");
		t.registrationDate = info->texteDe(L"Date");
	}

	// Principal : compte d'exécution. UserId contient un nom OU un SID.
	for (const XmlNode* p : racine.descendants(L"Principal")) {
		const std::wstring userId = p->texteDe(L"UserId");
		if (userId.empty()) continue;
		if (estUnSid(userId)) {
			t.runAsSid = userId;
			t.runAs    = getNameFromSid(userId);   // résolution mise en cache
		}
		else t.runAs = userId;
		break;
	}
	if (t.runAs.empty()) t.runAs = racine.texteDe(L"Principals/Principal/GroupId");

	// Settings\Enabled vaut « true » par défaut quand l'élément est absent.
	t.enabled = (racine.texteDe(L"Settings/Enabled") != L"false");
	t.state   = t.enabled ? L"Enabled" : L"Disabled";

	// Actions : Exec (exécutable) ou ComHandler (CLSID).
	for (const XmlNode* a : racine.descendants(L"Exec")) {
		Action act;
		act.type       = L"Exec";
		act.command    = a->texteDe(L"Command");
		act.arguments  = a->texteDe(L"Arguments");
		act.workingDir = a->texteDe(L"WorkingDirectory");
		if (conf.binary && !act.command.empty()) {
			/* Le chemin peut être entre guillemets et contenir des variables.
			   Il était développé avec ExpandEnvironmentStringsW — l'environnement
			   de WAC, qui tourne en SYSTEM — et son existence testée par l'API :
			   deux lectures de la machine vivante. La normalisation commune
			   développe les variables système depuis le lecteur détecté.
			   Un nom nu (« cmd.exe ») est cherché comme Windows le ferait en
			   premier, dans System32. Un exécutable absent n'est pas une
			   anomalie ici (logiciel désinstallé) : Command le montre. */
			const std::wstring commande = replaceAll(act.command, L"\"", L"");
			std::wstring chemin = normaliserCheminFichier(commande);
			if (chemin.empty() && commande.find(L'\\') == std::wstring::npos
			    && commande.find(L'%') == std::wstring::npos)
				chemin = conf.systemDrive + L"\\Windows\\System32\\" + commande;
			if (!chemin.empty()) act.empreinte = EmpreinteFichier(chemin);
		}
		t.actions.push_back(std::move(act));
	}
	for (const XmlNode* a : racine.descendants(L"ComHandler")) {
		Action act;
		act.type    = L"ComHandler";
		act.classId = a->texteDe(L"ClassId");
		act.data    = a->texteDe(L"Data");
		t.actions.push_back(std::move(act));
	}

	// Déclencheurs : chaque enfant de <Triggers> porte son type dans son nom.
	if (const XmlNode* trigs = racine.enfant(L"Triggers")) {
		for (const std::unique_ptr<XmlNode>& n : trigs->enfants) {
			Trigger tr;
			tr.type     = n->nom;                       // TimeTrigger, LogonTrigger…
			tr.debut    = n->texteDe(L"StartBoundary");
			tr.actif    = (n->texteDe(L"Enabled") != L"false");
			tr.interval = n->texteDe(L"Repetition/Interval");
			t.triggers.push_back(std::move(tr));
		}
	}
}

} // namespace

Json ScheduledTask::toJson() const {
	log(3, L"🔈Scheduled task");
	Json o = Json::obj();
	o.add(L"Name",               Json::str(name));
	o.add(L"Description",        Json::str(description));
	o.add(L"Author",             Json::str(author));
	o.add(L"Enabled",            Json::boolean(enabled));
	o.add(L"RunAs",              Json::str(runAs));
	o.add(L"RunAsSID",           Json::str(runAsSid));
	o.add(L"Path",               Json::str(path));               // chemin BRUT
	o.add(L"State",              Json::str(state));
	o.add(L"LastRun",            Json::str(timeToIso8601Local(lastRunTime)));
	o.add(L"LastRunUtc",         Json::str(timeToIso8601Utc(lastRunTimeUtc)));
	o.add(L"LastTaskResult",     Json::num((long long)lastTaskResult));
	o.add(L"RegistrationDate",   Json::str(registrationDate));
	o.add(L"SourceXml",          Json::str(sourceXml));   // traçabilité de la source

	Json jsonActions = Json::arr();
	for (const Action& a : actions) {
		Json j = Json::obj();
		j.add(L"Type", Json::str(a.type));
		if (a.type == L"Exec") {
			ajouterEmpreintes(j, a.empreinte);
			j.add(L"Command",          Json::str(a.command));
			j.add(L"Arguments",        Json::str(a.arguments));
			j.add(L"WorkingDirectory", Json::str(a.workingDir));
		}
		else {
			/* « ClassId Name » portait une espace, et « data » était la seule clé
			   en minuscules de toute la sortie : deux formes qu'un outil de
			   requête traite mal et qui ne suivent pas le nommage commun. */
			j.add(L"ClassId",     Json::str(a.classId));
			j.add(L"ClassIdName", Json::str(trans_guid_to_wstring(a.classId)));
			j.add(L"Data",        Json::str(a.data));
		}
		jsonActions.push(std::move(j));
	}
	o.add(L"Actions", std::move(jsonActions));

	Json jsonTriggers = Json::arr();
	for (const Trigger& t : triggers) {
		Json j = Json::obj();
		j.add(L"Type",     Json::str(t.type));
		j.add(L"Enabled",  Json::boolean(t.actif));
		j.add(L"Start",    Json::str(t.debut));
		j.add(L"Interval", Json::str(t.interval));
		jsonTriggers.push(std::move(j));
	}
	o.add(L"Triggers", std::move(jsonTriggers));

	return o;
}

void ScheduledTask::clear() {
	log(3, L"🔈Scheduled task clear");
	actions.clear();
	triggers.clear();
}

HRESULT ScheduledTasks::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Scheduled tasks (offline) :");
	log(0, L"*******************************************************************************************************************");

	const std::filesystem::path racine = conf.mountpoint + SOUS_DOSSIER_TASKS;
	std::error_code ec;
	if (!std::filesystem::exists(racine, ec)) {
		log(2, L"🔥Definitions de taches absentes : " + racine.wstring(), ERROR_PATH_NOT_FOUND);
		return ERROR_PATH_NOT_FOUND;
	}

	// Historique d'abord : il est rattaché ensuite à chaque tâche par son chemin.
	const std::map<std::wstring, Historique> historiques = lireTaskCache();

	// Les définitions sont des fichiers SANS extension, rangés en arborescence.
	std::vector<std::filesystem::path> fichiers;
	for (std::filesystem::recursive_directory_iterator it(racine, ec), fin;
	     it != fin && !ec; it.increment(ec)) {
		std::error_code ecFichier;
		if (it->is_regular_file(ecFichier) && !ecFichier) fichiers.push_back(it->path());
	}
	log(2, L"❇️" + std::to_wstring(fichiers.size()) + L" definition(s) de tache trouvee(s)");

	scheduledTasks.reserve(fichiers.size());
	size_t iFichier = 0, ignores = 0;
	for (const std::filesystem::path& fichier : fichiers) {
		printProgressStep(L"ScheduledTask", ++iFichier, fichiers.size());

		std::unique_ptr<XmlNode> racineXml = xmlLireFichier(fichier.wstring());
		if (!racineXml || racineXml->nom != L"Task") {
			/* Un fichier sous Tasks\ qui n'est pas une définition de tâche est
			   signalé plutôt que de produire une entrée vide : l'analyste doit
			   pouvoir distinguer « pas de tâche » de « tâche non décodée ». */
			++ignores;
			log(2, L"🔥Definition illisible ou inattendue : " + fichier.wstring());
			continue;
		}

		ScheduledTask t;
		t.name = fichier.filename().wstring();
		// Chemin tel que le planificateur le présente : relatif à Tasks\,
		// antislashs, préfixé d'un antislash — c'est aussi la clé du TaskCache.
		t.path = L"\\" + std::filesystem::relative(fichier, racine, ec).wstring();
		t.sourceXml = cheminOriginal(fichier.wstring());
		log(1, L"➕ScheduledTask");
		log(2, L"❇️Task : " + t.path);

		lireDefinition(*racineXml, t);

		const std::map<std::wstring, Historique>::const_iterator h =
			historiques.find(enMinuscules(t.path));
		if (h != historiques.end() && h->second.trouve) {
			t.lastRunTimeUtc = h->second.derniereExecutionUtc;
			t.lastTaskResult = h->second.dernierResultat;
			utcVersLocalSuspect(t.lastRunTimeUtc, &t.lastRunTime);
		}
		scheduledTasks.push_back(std::move(t));
	}
	if (ignores)
		log(2, L"❇️" + std::to_wstring(ignores) + L" fichier(s) ignore(s) sous Tasks\\");
	return ERROR_SUCCESS;
}

HRESULT ScheduledTasks::toJson() {
	log(3, L"🔈ScheduledTasks toJson");
	Json arr = Json::arr();
	for (const ScheduledTask& t : scheduledTasks) arr.push(t.toJson());
	return writeJsonFile("ScheduledTasks.json", arr);
}

void ScheduledTasks::clear() {
	log(3, L"🔈ScheduledTasks clear");
	scheduledTasks.clear();   // detruit les elements -> libere reellement
}

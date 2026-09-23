#include "event_messages.h"
#include "tools.h"
#include "consigne.h"
#include "raw_hive.h"
#include "pe_resource.h"
#include "wevt.h"
#include "audit.h"
#include <filesystem>
#include <map>
#include <memory>
#include <fstream>
#include <vector>

/*  event_messages.cpp — voir event_messages.h pour la chaîne à réunir.
 *  Ici, la mécanique : recherche du fichier, extraction à la demande, cache.
 */

namespace {

//! Ce qu'on sait d'un fournisseur, une fois ses ressources lues (ou non).
struct Provider {
	bool usable = false;         //!< les deux ressources ont été chargées
	WevtMetadata metadata;     //!< événement -> identifiant de message
	TableMessages   messages;        //!< identifiant de message -> modèle
	/*! Table du fichier de paramètres (ParameterFileName) : libellés des valeurs « %%nnnn ». Pour
	 *  Security-Auditing, c'est msobjs.dll, et non le binaire du fournisseur. */
	TableMessages   parameters;
	std::wstring    file;         //!< chemin d'origine du binaire de ressources
	std::wstring    reason;           //!< pourquoi il est inutilisable
};

std::map<std::wstring, std::unique_ptr<Provider>> g_cache;   // guid -> fournisseur
bool g_ready = false;
size_t g_failures = 0;
unsigned long long g_resolved = 0, g_bytes = 0;

//! GUID en minuscules, accolades comprises : la clé de registre l'écrit ainsi.
std::wstring normalizeGuid(const std::wstring& g) {
	std::wstring r;
	for (wchar_t c : g) r += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
	if (!r.empty() && r.front() != L'{') r = L"{" + r + L"}";
	return r;
}

//! Vrai si le fichier commence par la signature d'un binaire PE.
bool isValidPe(const std::wstring& path) {
	std::ifstream f(std::filesystem::path(path), std::ios::binary);
	if (!f) return false;
	char head[2] = { 0, 0 };
	f.read(head, 2);
	return f.gcount() == 2 && head[0] == 'M' && head[1] == 'Z';
}

/*! Extrait un fichier du volume vers la consigne, puis le recopie dans le
 *  travail, et rend le chemin de travail.
 *
 *  La discipline de la consigne s'applique à ces binaires comme au reste : la
 *  copie brute est identifiée par ses empreintes et n'est jamais relue en
 *  écriture ; c'est la copie de travail qu'on ouvre.
 *
 *  Windows 10 et 11 compressent leurs binaires système avec WOF — « Compact
 *  OS » : l'attribut `$DATA` est creux et la charge utile vit dans le flux nommé
 *  `WofCompressedData`. La lecture brute le détend (cf. xpress.h) ; rien n'est
 *  ouvert par l'API sur le système examiné.
 *
 *  CANDIDATS ABSENTS. Les satellites `.mui` se cherchent langue par langue :
 *  la plupart des candidats n'existent pas, et ce n'est pas un échec de
 *  collecte. Ils ne sont donc pas inscrits à la consigne — 136 « pièces en
 *  échec » y figuraient pour des langues simplement non installées, noyant les
 *  vrais échecs. Seul un fichier présent mais illisible y est consigné.
 *
 *  @return le chemin lisible, ou chaîne vide en cas d'échec
 */
std::wstring extractResource(const std::wstring& absolutePath) {
	const std::wstring working = extractedPath(absolutePath);
	std::error_code ec;
	if (std::filesystem::exists(working, ec)) return working;   // deja extrait

	const std::wstring volume  = volumeOfPath(absolutePath);
	const std::wstring relative = pathRelativeToVolume(absolutePath);
	const std::wstring target   = pathUnder(exhibitStoreFolder(), absolutePath);
	/* Déjà en consigne — prélevé comme binaire cité par un artefact (--binary), et
	   pas encore recopié vers le travail : on ne le réextrait pas, ce qui
	   réécrirait une pièce scellée et la déclarerait deux fois. */
	if (std::filesystem::exists(target, ec)) {
		if (!isValidPe(target)) return std::wstring();
		std::filesystem::create_directories(std::filesystem::path(working).parent_path(), ec);
		std::filesystem::copy_file(target, working, std::filesystem::copy_options::skip_existing, ec);
		return ec ? std::wstring() : working;
	}
	std::filesystem::create_directories(std::filesystem::path(target).parent_path(), ec);

	std::vector<HRESULT> res;
	std::vector<RawHiveExtraction> reading;
	const HRESULT hr = ExtractFilesRaw(volume, { { relative, target } }, &res, &reading);
	const bool absent = !res.empty()
	                 && (res[0] == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)
	                  || res[0] == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND));
	if (absent) {
		// Candidat inexistant : ni pièce, ni répertoire vide dans la consigne.
		std::filesystem::remove(std::filesystem::path(target).parent_path(), ec);
		return std::wstring();
	}
	ExhibitStoreAdd(reading, L"Lecture brute NTFS (\\\\.\\" + volume
	                        + L": — fichier de ressources d'un fournisseur d'evenements)");
	const bool brutOk = SUCCEEDED(hr) && !res.empty() && SUCCEEDED(res[0]);
	if (!brutOk)
		log(3, L"🔈Lecture brute infructueuse, repli attendu : " + absolutePath);
	else
		for (const RawHiveExtraction& e : reading) g_bytes += e.fingerprints.bytes;

	/*  AUCUN REPLI PAR L'API. Ces binaires sont compresses par WOF
	    (« Compact OS ») : leur attribut $DATA est creux et le contenu vit dans un
	    flux nomme. La lecture brute les traite desormais entierement
	    (cf. xpress.h), et rien n'est donc ouvert sur le systeme examine.
	    Un fichier qui reste illisible l'est pour une autre raison — absent, ou
	    compresse en LZX, que WAC ne detend pas — et il est signale comme tel
	    plutot que lu par une voie qui laisserait une trace. */
	if (!brutOk || !isValidPe(target)) {
		log(2, L"🔥Binaire de ressources illisible en lecture brute : " + absolutePath);
		return std::wstring();
	}

	// Copie vers le travail : c'est là que la lecture aura lieu.
	std::filesystem::create_directories(std::filesystem::path(working).parent_path(), ec);
	std::filesystem::copy_file(target, working,
	                           std::filesystem::copy_options::overwrite_existing, ec);
	if (ec) {
		log(2, L"🔥Copie de travail impossible : " + working);
		return std::wstring();
	}
	return working;
}

/*! Langues d'interface à essayer pour trouver un satellite, dans l'ordre.
 *
 *  Relevées UNE FOIS : `PreferredUILanguages` est une valeur MULTI_SZ — la lire
 *  comme une chaîne simple ne rendait que la première langue, ou rien. Les
 *  candidats usuels ne servent qu'en dernier recours, et tenter cinq langues
 *  pour chacun des quelque cent fournisseurs d'une collecte coûte cinq cents
 *  résolutions de chemin pour rien.
 */
const std::vector<std::wstring>& interfaceLanguages() {
	static std::vector<std::wstring> languages;
	static bool done = false;
	if (done) return languages;
	done = true;

	std::vector<std::wstring> declared;
	if (conf.Software && getRegMultiSzValue(conf.Software,
	        L"Microsoft\\Windows\\CurrentVersion\\MUI\\Settings",
	        L"PreferredUILanguages", &declared) == ERROR_SUCCESS)
		for (const std::wstring& l : declared)
			if (!l.empty()) languages.push_back(l);

	for (PCWSTR l : { L"en-US", L"fr-FR", L"de-DE", L"es-ES", L"it-IT" }) {
		bool already = false;
		for (const std::wstring& d : languages) if (d == l) { already = true; break; }
		if (!already) languages.push_back(l);
	}
	log(2, L"❇️Langues d'interface essayees pour les satellites .mui : "
	     + std::to_wstring(languages.size()) + L" (" + (languages.empty() ? L"-" : languages[0]) + L"…)");
	return languages;
}

/*! Cherche le satellite localisé d'un binaire de ressources.
 *
 *  Sur un système localisé, la table des messages n'est PAS dans la DLL : elle
 *  est dans `<répertoire>\<langue>\<nom>.mui`. La langue n'étant pas connue
 *  d'avance, les candidats les plus courants sont essayés, puis la langue
 *  relevée dans la ruche si elle y figure.
 *
 *  @return le chemin de travail du .mui, ou chaîne vide s'il n'y en a pas
 */
std::wstring findMui(const std::wstring& absolutePath) {
	const std::filesystem::path p = absolutePath;
	const std::wstring directory = p.parent_path().wstring();
	const std::wstring name = p.filename().wstring();

	const std::vector<std::wstring>& languages = interfaceLanguages();

	for (const std::wstring& l : languages) {
		if (l.empty()) continue;
		const std::wstring candidate = directory + L"\\" + l + L"\\" + name + L".mui";
		const std::wstring working = extractResource(candidate);
		if (!working.empty()) return working;
	}
	return std::wstring();
}

/*! Charge les ressources d'un fournisseur, une seule fois. */
/*! Chemins où chercher un fichier déclaré dans une clé de fournisseur.
 *
 *  DEUX CANDIDATS. Un chemin RELATIF dans une clé de fournisseur est relatif à
 *  `System32`, alors que pour un service il l'est à `%SystemRoot%` —
 *  `cheminBinaire` applique cette seconde règle. Constaté : un
 *  « storagewmi.dll » nu donnait « C:\Windows\storagewmi.dll », introuvable,
 *  au lieu de « C:\Windows\System32\storagewmi.dll ». */
std::vector<std::wstring> candidatesFor(const std::wstring& declare) {
	const std::wstring resolved = binaryPath(declare);
	std::vector<std::wstring> candidates;
	if (!resolved.empty()) candidates.push_back(resolved);
	const std::filesystem::path p = resolved.empty() ? declare : resolved;
	const std::wstring nameOnly = p.filename().wstring();
	if (!nameOnly.empty())
		candidates.push_back(conf.systemDrive + L"\\Windows\\System32\\" + nameOnly);
	return candidates;
}

/*! Charge la table de messages d'un fichier déclaré : dans le binaire, sinon
 *  dans son satellite localisé. Rend le nombre de messages. */
size_t loadTable(const std::wstring& declare, TableMessages& table, std::wstring* file) {
	for (const std::wstring& c : candidatesFor(declare)) {
		const std::wstring working = extractResource(c);
		if (working.empty()) continue;
		if (file) *file = c;
		PeResource pe;
		size_t n = pe.open(working) ? table.analyse(pe.resource(PE_RT_MESSAGETABLE)) : 0;
		if (n == 0) {
			const std::wstring mui = findMui(c);
			PeResource peMui;
			if (!mui.empty() && peMui.open(mui))
				n = table.analyse(peMui.resource(PE_RT_MESSAGETABLE));
		}
		return n;
	}
	return 0;
}

Provider* load(const std::wstring& guid) {
	const std::map<std::wstring, std::unique_ptr<Provider>>::iterator it = g_cache.find(guid);
	if (it != g_cache.end()) return it->second.get();

	std::unique_ptr<Provider> f = std::make_unique<Provider>();

	// 1. Le chemin du fichier de ressources, dans la ruche SOFTWARE.
	const std::wstring key = L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + guid;
	std::wstring path;
	if (getRegSzValue(conf.Software, key.c_str(), L"ResourceFileName", &path) != ERROR_SUCCESS
	    || path.empty()) {
		if (getRegSzValue(conf.Software, key.c_str(), L"MessageFileName", &path) != ERROR_SUCCESS
		    || path.empty()) {
			f->reason = L"aucun fichier de ressources declare";
			++g_failures;
			log(2, L"🔥Fournisseur " + guid + L" : " + f->reason);
			Provider* brut = f.get();
			g_cache.emplace(guid, std::move(f));
			return brut;
		}
	}
	// `%SystemRoot%`, `%windir%` et consorts, et chemin relatif à System32.
	const std::wstring resolved = binaryPath(path);
	const std::vector<std::wstring> candidates = candidatesFor(path);

	// 2. Les métadonnées, dans le binaire lui-même.
	std::wstring workingDll;
	for (const std::wstring& c : candidates) {
		workingDll = extractResource(c);
		if (!workingDll.empty()) { f->file = c; break; }
	}
	if (workingDll.empty()) {
		f->file = resolved;
		f->reason = L"binaire de ressources illisible";
		++g_failures;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->reason + L" — candidats : "
		     + (candidates.empty() ? L"(aucun)" : candidates[0])
		     + (candidates.size() > 1 ? L" ; " + candidates[1] : L""));
		Provider* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	PeResource pe;
	if (!pe.open(workingDll)) {
		f->reason = L"PE illisible : " + pe.error();
		++g_failures;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->reason + L" (" + workingDll + L")");
		Provider* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	f->metadata.analyse(pe.namedResource(L"WEVT_TEMPLATE"), guid);

	// 3. Les textes : d'abord dans le satellite localisé, sinon dans le binaire.
	size_t nbMessages = f->messages.analyse(pe.resource(PE_RT_MESSAGETABLE));
	if (nbMessages == 0) {
		const std::wstring mui = findMui(f->file);
		if (!mui.empty()) {
			PeResource peMui;
			if (peMui.open(mui))
				nbMessages = f->messages.analyse(peMui.resource(PE_RT_MESSAGETABLE));
		}
	}

	/* FICHIER DE PARAMÈTRES. Les valeurs énumérées d'un événement s'écrivent
	   « %%nnnn » dans ses DONNÉES, et Windows les résout dans le fichier de
	   paramètres du fournisseur. Les chercher dans sa propre table
	   laissait 8 337 références brutes dans 3 700 messages de Security —
	   « Elevated Token: %%1842 » au lieu de « Oui ». */
	{
		/* Le nom de la valeur est « ParameterFileName » dans la clé WINEVT du
		   fournisseur ; « ParameterMessageFile » est celui de l'ancienne clé du
		   service EventLog. Chercher le second seul ne trouvait rien : Security
		   déclare le sien sous le premier (msobjs.dll). */
		std::wstring declare;
		if ((getRegSzValue(conf.Software, key.c_str(), L"ParameterFileName", &declare) == ERROR_SUCCESS
		     && !declare.empty())
		    || (getRegSzValue(conf.Software, key.c_str(), L"ParameterMessageFile", &declare) == ERROR_SUCCESS
		     && !declare.empty())) {
			std::wstring parameterFile;
			const size_t n = loadTable(declare, f->parameters, &parameterFile);
			log(2, L"❇️Fournisseur " + guid + L" : " + std::to_wstring(n)
			     + L" libelle(s) de parametre — " + (parameterFile.empty() ? declare : parameterFile));
		}
	}

	f->usable = (f->metadata.size() > 0 && nbMessages > 0);
	if (!f->usable) {
		f->reason = L"metadonnees ou table de messages absentes ("
		         + std::to_wstring(f->metadata.size()) + L" evenement(s), "
		         + std::to_wstring(nbMessages) + L" message(s))";
		++g_failures;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->reason + L" — " + f->file);
	}
	else {
		log(2, L"❇️Fournisseur " + guid + L" : " + std::to_wstring(f->metadata.size())
		     + L" evenement(s), " + std::to_wstring(nbMessages) + L" message(s) — "
		     + f->file);
	}
	Provider* brut = f.get();
	g_cache.emplace(guid, std::move(f));
	return brut;
}

} // namespace

void MessagesInit() {
	g_cache.clear();
	g_failures = 0;
	g_resolved = 0;
	g_bytes = 0;
	// Sans la ruche SOFTWARE, aucun fournisseur n'est localisable : on le dit
	// une fois plutôt qu'à chaque événement.
	g_ready = (conf.Software != NULL);
	if (!g_ready)
		log(2, L"🔥Ruche SOFTWARE indisponible : les messages d'evenements ne seront pas resolus");
}

std::wstring EventMessage(const std::wstring& providerGuid,
                              uint16_t eventId,
                              uint8_t version,
                              const std::vector<std::wstring>& values) {
	if (!g_ready || providerGuid.empty()) return std::wstring();

	Provider* f = load(normalizeGuid(providerGuid));
	if (!f || !f->usable) return std::wstring();

	const uint32_t idMessage = f->metadata.messageId(eventId, version);
	if (idMessage == 0) return std::wstring();
	const std::wstring messageTemplate = f->messages.text(idMessage);
	if (messageTemplate.empty()) return std::wstring();

	/*  Une donnée de la forme « %%1234 » n'est pas un texte mais une RÉFÉRENCE
	    vers un autre message de la même table — c'est ainsi que Windows encode
	    les valeurs énumérées. Sans cette résolution, le message final afficherait
	    « %%1234 » au lieu du libellé. */
	std::vector<std::wstring> resolved;
	resolved.reserve(values.size());
	for (const std::wstring& v : values) {
		if (v.size() > 2 && v[0] == L'%' && v[1] == L'%') {
			bool digits = true;
			for (size_t i = 2; i < v.size(); ++i)
				if (v[i] < L'0' || v[i] > L'9') { digits = false; break; }
			if (digits) {
				const uint32_t id = (uint32_t)wcstoul(v.c_str() + 2, nullptr, 10);
				std::wstring t = f->parameters.text(id);           // d'abord : comme Windows
				if (t.empty()) t = f->messages.text(id);
				// Un libellé de table finit par « \r\n » : inséré dans une phrase,
				// il la couperait.
				while (!t.empty() && (t.back() == L'\n' || t.back() == L'\r' || t.back() == L' '))
					t.pop_back();
				resolved.push_back(t.empty() ? v : t);
				continue;
			}
		}
		resolved.push_back(v);
	}

	const std::wstring phrase = formatMessage(messageTemplate, resolved);
	if (!phrase.empty()) ++g_resolved;
	return phrase;
}

void MessagesSummary(size_t* providers, size_t* failures,
                   unsigned long long* resolved, unsigned long long* bytes) {
	if (providers) *providers = g_cache.size();
	if (failures)       *failures = g_failures;
	if (resolved)      *resolved = g_resolved;
	if (bytes)       *bytes = g_bytes;
}

void MessagesRelease() {
	g_cache.clear();
}

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
struct Fournisseur {
	bool utilisable = false;         //!< les deux ressources ont été chargées
	MetadonneesWevt metadonnees;     //!< événement -> identifiant de message
	TableMessages   messages;        //!< identifiant de message -> modèle
	std::wstring    fichier;         //!< chemin d'origine du binaire de ressources
	std::wstring    motif;           //!< pourquoi il est inutilisable
};

std::map<std::wstring, std::unique_ptr<Fournisseur>> g_cache;   // guid -> fournisseur
bool g_pret = false;
size_t g_echecs = 0;
unsigned long long g_resolus = 0, g_octets = 0;

//! GUID en minuscules, accolades comprises : la clé de registre l'écrit ainsi.
std::wstring normaliserGuid(const std::wstring& g) {
	std::wstring r;
	for (wchar_t c : g) r += (c >= L'A' && c <= L'Z') ? (wchar_t)(c - L'A' + L'a') : c;
	if (!r.empty() && r.front() != L'{') r = L"{" + r + L"}";
	return r;
}

//! Vrai si le fichier commence par la signature d'un binaire PE.
bool estPeValide(const std::wstring& chemin) {
	std::ifstream f(std::filesystem::path(chemin), std::ios::binary);
	if (!f) return false;
	char tete[2] = { 0, 0 };
	f.read(tete, 2);
	return f.gcount() == 2 && tete[0] == 'M' && tete[1] == 'Z';
}

/*! Extrait un fichier du volume vers la consigne, puis le recopie dans le
 *  travail, et rend le chemin de travail.
 *
 *  La discipline de la consigne s'applique à ces binaires comme au reste : la
 *  copie brute est identifiée par ses empreintes et n'est jamais relue en
 *  écriture ; c'est la copie de travail qu'on ouvre.
 *
 *  REPLI SUR L'API DE FICHIERS, et pourquoi il est nécessaire. Windows 10 et 11
 *  compressent leurs binaires système avec WOF — « Compact OS » : l'attribut
 *  `$DATA` du fichier est CREUX, et la charge utile vit dans un flux de données
 *  nommé `WofCompressedData`, comprimé en XPRESS ou LZX. Une lecture brute rend
 *  donc un fichier de la bonne taille, entièrement à zéro. Mesuré sur une VM
 *  Windows 11 : les 121 binaires de fournisseurs extraits étaient tous vides, et
 *  aucun message n'était résolu.
 *
 *  Quand la copie brute n'est pas un PE valide, le fichier est donc relu par
 *  l'API. Ce n'est PAS une pièce à conviction : c'est un binaire du système
 *  d'exploitation, identique sur toute machine de la même version, qui ne sert
 *  qu'à traduire un identifiant en phrase. Le coût d'empreinte se limite à une
 *  ouverture en lecture — dont Windows ne met pas à jour la date d'accès par
 *  défaut — et chaque repli est consigné au journal d'investigation.
 *
 *  @return le chemin lisible, ou chaîne vide en cas d'échec
 */
std::wstring extraireRessource(const std::wstring& cheminAbsolu) {
	const std::wstring travail = cheminExtrait(cheminAbsolu);
	std::error_code ec;
	if (std::filesystem::exists(travail, ec)) return travail;   // deja extrait

	const std::wstring volume  = volumeDuChemin(cheminAbsolu);
	const std::wstring relatif = cheminRelatifAuVolume(cheminAbsolu);
	const std::wstring cible   = cheminSous(dossierConsigne(), cheminAbsolu);
	std::filesystem::create_directories(std::filesystem::path(cible).parent_path(), ec);

	std::vector<HRESULT> res;
	std::vector<RawHiveExtrait> releve;
	const HRESULT hr = ExtractFilesRaw(volume, { { relatif, cible } }, &res, &releve);
	ConsigneAjouter(releve, L"Lecture brute NTFS (\\\\.\\" + volume
	                        + L": — fichier de ressources d'un fournisseur d'evenements)");
	const bool brutOk = SUCCEEDED(hr) && !res.empty() && SUCCEEDED(res[0]);
	if (!brutOk)
		log(3, L"🔈Lecture brute infructueuse, repli attendu : " + cheminAbsolu);
	else
		for (const RawHiveExtrait& e : releve) g_octets += e.empreintes.octets;

	/*  AUCUN REPLI PAR L'API. Ces binaires sont compresses par WOF
	    (« Compact OS ») : leur attribut $DATA est creux et le contenu vit dans un
	    flux nomme. La lecture brute les traite desormais entierement
	    (cf. xpress.h), et rien n'est donc ouvert sur le systeme examine.
	    Un fichier qui reste illisible l'est pour une autre raison — absent, ou
	    compresse en LZX, que WAC ne detend pas — et il est signale comme tel
	    plutot que lu par une voie qui laisserait une trace. */
	if (!brutOk || !estPeValide(cible)) {
		log(2, L"🔥Binaire de ressources illisible en lecture brute : " + cheminAbsolu);
		return std::wstring();
	}

	// Copie vers le travail : c'est là que la lecture aura lieu.
	std::filesystem::create_directories(std::filesystem::path(travail).parent_path(), ec);
	std::filesystem::copy_file(cible, travail,
	                           std::filesystem::copy_options::overwrite_existing, ec);
	if (ec) {
		log(2, L"🔥Copie de travail impossible : " + travail);
		return std::wstring();
	}
	return travail;
}

/*! Langues d'interface à essayer pour trouver un satellite, dans l'ordre.
 *
 *  Relevées UNE FOIS : `PreferredUILanguages` est une valeur MULTI_SZ — la lire
 *  comme une chaîne simple ne rendait que la première langue, ou rien. Les
 *  candidats usuels ne servent qu'en dernier recours, et tenter cinq langues
 *  pour chacun des quelque cent fournisseurs d'une collecte coûte cinq cents
 *  résolutions de chemin pour rien.
 */
const std::vector<std::wstring>& languesInterface() {
	static std::vector<std::wstring> langues;
	static bool faites = false;
	if (faites) return langues;
	faites = true;

	std::vector<std::wstring> declarees;
	if (conf.Software && getRegMultiSzValue(conf.Software,
	        L"Microsoft\\Windows\\CurrentVersion\\MUI\\Settings",
	        L"PreferredUILanguages", &declarees) == ERROR_SUCCESS)
		for (const std::wstring& l : declarees)
			if (!l.empty()) langues.push_back(l);

	for (PCWSTR l : { L"en-US", L"fr-FR", L"de-DE", L"es-ES", L"it-IT" }) {
		bool deja = false;
		for (const std::wstring& d : langues) if (d == l) { deja = true; break; }
		if (!deja) langues.push_back(l);
	}
	log(2, L"❇️Langues d'interface essayees pour les satellites .mui : "
	     + std::to_wstring(langues.size()) + L" (" + (langues.empty() ? L"-" : langues[0]) + L"…)");
	return langues;
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
std::wstring trouverMui(const std::wstring& cheminAbsolu) {
	const std::filesystem::path p = cheminAbsolu;
	const std::wstring repertoire = p.parent_path().wstring();
	const std::wstring nom = p.filename().wstring();

	const std::vector<std::wstring>& langues = languesInterface();

	for (const std::wstring& l : langues) {
		if (l.empty()) continue;
		const std::wstring candidat = repertoire + L"\\" + l + L"\\" + nom + L".mui";
		const std::wstring travail = extraireRessource(candidat);
		if (!travail.empty()) return travail;
	}
	return std::wstring();
}

/*! Charge les ressources d'un fournisseur, une seule fois. */
Fournisseur* charger(const std::wstring& guid) {
	const std::map<std::wstring, std::unique_ptr<Fournisseur>>::iterator it = g_cache.find(guid);
	if (it != g_cache.end()) return it->second.get();

	std::unique_ptr<Fournisseur> f = std::make_unique<Fournisseur>();

	// 1. Le chemin du fichier de ressources, dans la ruche SOFTWARE.
	const std::wstring cle = L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + guid;
	std::wstring chemin;
	if (getRegSzValue(conf.Software, cle.c_str(), L"ResourceFileName", &chemin) != ERROR_SUCCESS
	    || chemin.empty()) {
		if (getRegSzValue(conf.Software, cle.c_str(), L"MessageFileName", &chemin) != ERROR_SUCCESS
		    || chemin.empty()) {
			f->motif = L"aucun fichier de ressources declare";
			++g_echecs;
			log(2, L"🔥Fournisseur " + guid + L" : " + f->motif);
			Fournisseur* brut = f.get();
			g_cache.emplace(guid, std::move(f));
			return brut;
		}
	}
	// `%SystemRoot%`, `%windir%` et consorts : même résolution que les services.
	const std::wstring resolu = cheminBinaire(chemin);

	/*  DEUX CANDIDATS. Un chemin RELATIF dans une clé de fournisseur est
	    relatif à `System32`, alors que pour un service il l'est à `%SystemRoot%`
	    — `cheminBinaire` applique cette seconde règle. Constaté : un
	    « storagewmi.dll » nu donnait « C:\Windows\storagewmi.dll », introuvable,
	    au lieu de « C:\Windows\System32\storagewmi.dll ». */
	std::vector<std::wstring> candidats;
	if (!resolu.empty()) candidats.push_back(resolu);
	{
		const std::filesystem::path p = resolu.empty() ? chemin : resolu;
		const std::wstring nomSeul = p.filename().wstring();
		if (!nomSeul.empty())
			candidats.push_back(conf.systemDrive + L"\\Windows\\System32\\" + nomSeul);
	}

	// 2. Les métadonnées, dans le binaire lui-même.
	std::wstring travailDll;
	for (const std::wstring& c : candidats) {
		travailDll = extraireRessource(c);
		if (!travailDll.empty()) { f->fichier = c; break; }
	}
	if (travailDll.empty()) {
		f->fichier = resolu;
		f->motif = L"binaire de ressources illisible";
		++g_echecs;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->motif + L" — candidats : "
		     + (candidats.empty() ? L"(aucun)" : candidats[0])
		     + (candidats.size() > 1 ? L" ; " + candidats[1] : L""));
		Fournisseur* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	PeResource pe;
	if (!pe.ouvrir(travailDll)) {
		f->motif = L"PE illisible : " + pe.erreur();
		++g_echecs;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->motif + L" (" + travailDll + L")");
		Fournisseur* brut = f.get();
		g_cache.emplace(guid, std::move(f));
		return brut;
	}
	f->metadonnees.analyser(pe.ressourceNommee(L"WEVT_TEMPLATE"), guid);

	// 3. Les textes : d'abord dans le satellite localisé, sinon dans le binaire.
	size_t nbMessages = f->messages.analyser(pe.ressource(PE_RT_MESSAGETABLE));
	if (nbMessages == 0) {
		const std::wstring mui = trouverMui(f->fichier);
		if (!mui.empty()) {
			PeResource peMui;
			if (peMui.ouvrir(mui))
				nbMessages = f->messages.analyser(peMui.ressource(PE_RT_MESSAGETABLE));
		}
	}

	f->utilisable = (f->metadonnees.taille() > 0 && nbMessages > 0);
	if (!f->utilisable) {
		f->motif = L"metadonnees ou table de messages absentes ("
		         + std::to_wstring(f->metadonnees.taille()) + L" evenement(s), "
		         + std::to_wstring(nbMessages) + L" message(s))";
		++g_echecs;
		log(2, L"🔥Fournisseur " + guid + L" : " + f->motif + L" — " + f->fichier);
	}
	else {
		log(2, L"❇️Fournisseur " + guid + L" : " + std::to_wstring(f->metadonnees.taille())
		     + L" evenement(s), " + std::to_wstring(nbMessages) + L" message(s) — "
		     + f->fichier);
	}
	Fournisseur* brut = f.get();
	g_cache.emplace(guid, std::move(f));
	return brut;
}

} // namespace

void MessagesInitialiser() {
	g_cache.clear();
	g_echecs = 0;
	g_resolus = 0;
	g_octets = 0;
	// Sans la ruche SOFTWARE, aucun fournisseur n'est localisable : on le dit
	// une fois plutôt qu'à chaque événement.
	g_pret = (conf.Software != NULL);
	if (!g_pret)
		log(2, L"🔥Ruche SOFTWARE indisponible : les messages d'evenements ne seront pas resolus");
}

std::wstring MessageEvenement(const std::wstring& guidFournisseur,
                              uint16_t identifiantEvenement,
                              uint8_t version,
                              const std::vector<std::wstring>& valeurs) {
	if (!g_pret || guidFournisseur.empty()) return std::wstring();

	Fournisseur* f = charger(normaliserGuid(guidFournisseur));
	if (!f || !f->utilisable) return std::wstring();

	const uint32_t idMessage = f->metadonnees.identifiantMessage(identifiantEvenement, version);
	if (idMessage == 0) return std::wstring();
	const std::wstring modele = f->messages.texte(idMessage);
	if (modele.empty()) return std::wstring();

	/*  Une donnée de la forme « %%1234 » n'est pas un texte mais une RÉFÉRENCE
	    vers un autre message de la même table — c'est ainsi que Windows encode
	    les valeurs énumérées. Sans cette résolution, le message final afficherait
	    « %%1234 » au lieu du libellé. */
	std::vector<std::wstring> resolues;
	resolues.reserve(valeurs.size());
	for (const std::wstring& v : valeurs) {
		if (v.size() > 2 && v[0] == L'%' && v[1] == L'%') {
			bool chiffres = true;
			for (size_t i = 2; i < v.size(); ++i)
				if (v[i] < L'0' || v[i] > L'9') { chiffres = false; break; }
			if (chiffres) {
				const std::wstring t = f->messages.texte((uint32_t)wcstoul(v.c_str() + 2, nullptr, 10));
				resolues.push_back(t.empty() ? v : t);
				continue;
			}
		}
		resolues.push_back(v);
	}

	const std::wstring phrase = formaterMessage(modele, resolues);
	if (!phrase.empty()) ++g_resolus;
	return phrase;
}

void MessagesBilan(size_t* fournisseurs, size_t* echecs,
                   unsigned long long* resolus, unsigned long long* octets) {
	if (fournisseurs) *fournisseurs = g_cache.size();
	if (echecs)       *echecs = g_echecs;
	if (resolus)      *resolus = g_resolus;
	if (octets)       *octets = g_octets;
}

void MessagesLiberer() {
	g_cache.clear();
}

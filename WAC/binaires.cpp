/*  binaires.cpp — voir binaires.h. */
#include "binaires.h"
#include <map>
#include <memory>
#include <filesystem>
#include "tools.h"
#include "raw_hive.h"
#include "consigne.h"
#include "authenticode.h"
#include <set>
#include <vector>

namespace {

std::unique_ptr<LecteurBrut> g_lecteur;
std::map<std::wstring, EmpreinteBinaire> g_cache;      // clé : chemin en minuscules
std::map<std::wstring, std::wstring> g_parContenu;    // SHA-256 -> pièce en consigne
size_t g_lus = 0, g_preleves = 0, g_sansPlace = 0, g_doublons = 0;
unsigned long long g_octets = 0, g_octetsEvites = 0;
size_t g_authentifies = 0, g_cataloguesLus = 0;
unsigned long long g_octetsAuthentifies = 0;
std::set<std::wstring> g_cataloguesUtilises;
const size_t CATALOGUE_MAX = 64 * 1024 * 1024;       // un catalogue au-delà : ignoré
unsigned long long g_entrant = 0;                      // compteur de fichiers d'arrivée

/*! Répertoire d'ARRIVÉE, sur le support de collecte mais hors consigne.
 *
 *  DÉDOUBLONNAGE. Le contenu d'un fichier n'est connu qu'après l'avoir lu. Il
 *  est donc écrit ici d'abord, haché au passage, puis RENOMMÉ dans la consigne
 *  s'il est nouveau, ou supprimé s'il y est déjà sous un autre chemin. La
 *  consigne ne reçoit ainsi que des pièces définitives : rien n'y est écrit
 *  puis effacé, et une collecte interrompue n'y laisse pas de fichier
 *  temporaire. Une seule lecture du volume par fichier. */
std::wstring dossierArrivee() {
	return dossierConsigne() + L".arrivee";
}

/*! Réserve laissée libre sur le support de collecte : en deçà, les fichiers
 *  sont hachés sans être copiés. Chaque pièce est écrite deux fois (consigne
 *  puis travail), et les journaux d'événements, traités en dernier, doivent
 *  encore trouver leur place. */
const unsigned long long RESERVE = 1ULL << 30;

/*! Ce qui se prélève : exécutables, bibliothèques, pilotes, les scripts
 *  qu'une tâche ou une clé Run peut lancer, et les documents Office CAPABLES DE
 *  PORTER DES MACROS.
 *
 *  DOCUMENTS À MACROS. Un document piégé est un vecteur d'intrusion aussi
 *  courant qu'un exécutable, et il apparaît dans les traces : cible d'un
 *  raccourci ou d'une liste de sauts, fichier chargé par WINWORD.EXE ou
 *  EXCEL.EXE dans leur Prefetch. Ne sont retenus que les formats où du VBA peut
 *  vivre : les formats binaires anciens (.doc, .xls, .ppt…), les formats « m »
 *  (.docm, .xlsm…), .xlsb, les modèles et compléments, Publisher, Visio et
 *  Access. Les .docx/.xlsx/.pptx ne peuvent pas contenir de VBA : ils restent
 *  seulement hachés, comme tout document — les copier ferait de la collecte une
 *  copie des fichiers de l'utilisateur. */
bool aPrelever(const std::wstring& chemin) {
	const size_t point = chemin.find_last_of(L'.');
	if (point == std::wstring::npos || chemin.find(L'\\', point) != std::wstring::npos) return false;
	static const wchar_t* const extensions[] = {
		// exécutables, bibliothèques, pilotes
		L"exe", L"dll", L"sys", L"ocx", L"cpl", L"scr", L"drv", L"efi", L"com", L"msi",
		// scripts
		L"ps1", L"psm1", L"bat", L"cmd", L"vbs", L"vbe", L"js", L"jse", L"wsf", L"wsh", L"hta",
		// Word
		L"doc", L"docm", L"dot", L"dotm",
		// Excel (xll et wll sont des DLL chargées par Excel et Word)
		L"xls", L"xlsm", L"xlsb", L"xlt", L"xltm", L"xla", L"xlam", L"xll", L"wll",
		// PowerPoint
		L"ppt", L"pptm", L"pot", L"potm", L"pps", L"ppsm", L"ppa", L"ppam",
		// Publisher, Visio, Access
		L"pub", L"vsd", L"vsdm", L"vstm", L"vssm", L"mdb", L"accdb", L"accde",
	};
	const std::wstring ext = enMinuscules(chemin.substr(point + 1));
	for (const wchar_t* e : extensions) if (ext == e) return true;
	return false;
}

} // namespace

namespace {

/*! Tampon qui garde ce qu'on lui écrit : lecture d'un catalogue en mémoire. */
class Collecteur : public std::streambuf {
public:
	std::vector<uint8_t> octets;
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) octets.push_back((uint8_t)c);
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		if (octets.size() + (size_t)n <= CATALOGUE_MAX) octets.insert(octets.end(), s, s + n);
		return n;
	}
};

/*! Transmet ce qu'il reçoit à deux tampons : l'analyse d'un PE, et, pour un
 *  script PowerShell, la copie en mémoire de son texte. */
class Duplicateur : public std::streambuf {
public:
	Duplicateur(std::streambuf* a, std::streambuf* b) : a_(a), b_(b) {}
protected:
	int overflow(int c) override {
		if (c != traits_type::eof()) { a_->sputc((char)c); if (b_) b_->sputc((char)c); }
		return traits_type::not_eof(c);
	}
	std::streamsize xsputn(const char* s, std::streamsize n) override {
		a_->sputn(s, n);
		if (b_) b_->sputn(s, n);
		return n;
	}
private:
	std::streambuf* a_;
	std::streambuf* b_;
};

//! Scripts dont la signature intégrée est vérifiée (cf. EvaluerScriptPowerShell).
bool estScriptPowerShell(const std::wstring& chemin) {
	const size_t point = chemin.find_last_of(L'.');
	if (point == std::wstring::npos) return false;
	const std::wstring ext = enMinuscules(chemin.substr(point + 1));
	return ext == L"ps1" || ext == L"psm1" || ext == L"psd1" || ext == L"ps1xml"
	    || ext == L"psc1" || ext == L"cdxml";
}

//! Empreinte hexadécimale (64 caractères) -> 32 octets.
bool octetsDeHexa(const std::wstring& hexa, uint8_t sortie[32]) {
	if (hexa.size() != 64) return false;
	for (size_t i = 0; i < 32; ++i) {
		unsigned v = 0;
		for (size_t k = 0; k < 2; ++k) {
			const wchar_t c = hexa[2 * i + k];
			v <<= 4;
			if (c >= L'0' && c <= L'9') v |= c - L'0';
			else if (c >= L'A' && c <= L'F') v |= c - L'A' + 10;
			else if (c >= L'a' && c <= L'f') v |= c - L'a' + 10;
			else return false;
		}
		sortie[i] = (uint8_t)v;
	}
	return true;
}

std::wstring dossierCatalogues() {
	return conf.systemDrive + L"\\Windows\\System32\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";
}

/*! Index des catalogues Microsoft de la machine, construit à la première
 *  demande — donc seulement si un binaire à prélever est rencontré. Les
 *  catalogues sont lus par lecture brute, EN MÉMOIRE : rien n'est écrit, et
 *  aucun service n'est sollicité (cf. authenticode.h). */
IndexCatalogues& catalogues() {
	static IndexCatalogues index;
	static bool fait = false;
	if (fait) return index;
	fait = true;
	std::vector<RawDirEntry> entrees;
	const HRESULT hr = g_lecteur->lister(dossierCatalogues(), entrees);
	if (FAILED(hr)) {
		log(2, L"🔥Catalogues de signatures illisibles : tous les binaires seront preleves", hr);
		return index;
	}
	std::set<uint64_t> vus;                  // un fichier peut figurer sous son nom court aussi
	size_t lus = 0;
	for (const RawDirEntry& e : entrees) {
		if (e.isDirectory || !vus.insert(e.mftIndex).second) continue;
		if (e.name.size() < 4 || enMinuscules(e.name.substr(e.name.size() - 4)) != L".cat") continue;
		Collecteur c;
		RawHiveExtrait ligne;
		if (FAILED(g_lecteur->lire(dossierCatalogues() + L"\\" + e.name, std::wstring(), ligne, &c))) continue;
		++lus;
		index.ajouter(e.name, c.octets.data(), c.octets.size());
	}
	g_cataloguesLus = lus;
	log(2, L"❇️Catalogues de signatures : " + std::to_wstring(lus) + L" lus, "
	     + std::to_wstring(index.catalogues()) + L" retenus (signature Microsoft verifiee), "
	     + std::to_wstring(index.refuses()) + L" refuses, "
	     + std::to_wstring(index.empreintes()) + L" empreintes");
	return index;
}

} // namespace

const EmpreinteBinaire& EmpreinteFichier(const std::wstring& cheminBrut) {
	static const EmpreinteBinaire vide;
	if (!conf.binary) return vide;
	const std::wstring chemin = normaliserCheminFichier(cheminBrut);
	if (chemin.empty()) return vide;

	const std::wstring cle = enMinuscules(chemin);       // NTFS ignore la casse
	const auto trouve = g_cache.find(cle);
	if (trouve != g_cache.end()) return trouve->second;

	if (!g_lecteur) g_lecteur.reset(new LecteurBrut);
	EmpreinteBinaire e;
	e.chemin = chemin;
	auto retenir = [&](RawHiveExtrait& l) {
		e.md5    = l.empreintes.md5;
		e.sha1   = l.empreintes.sha1;
		e.sha256 = l.empreintes.sha256;
	};

	if (!aPrelever(chemin)) {
		// Document ou donnée : empreintes seules, rien n'est écrit.
		RawHiveExtrait ligne;
		e.resultat = g_lecteur->lire(chemin, std::wstring(), ligne);
		if (SUCCEEDED(e.resultat)) { ++g_lus; retenir(ligne); }
		else log(3, L"🔈Empreinte impossible : " + chemin, e.resultat);
		return g_cache.emplace(cle, std::move(e)).first->second;
	}

	const std::wstring cible = cheminSous(dossierConsigne(), chemin);
	std::error_code ec;

	/* PREMIÈRE LECTURE, SANS RIEN ÉCRIRE : empreintes et, pour un PE,
	   authenticité Microsoft. Un binaire Microsoft authentique — la grande
	   majorité — n'est ainsi jamais écrit sur le support de collecte ; seuls
	   les autres sont relus pour être prélevés. Relire le disque examiné coûte
	   moins cher qu'écrire puis effacer sur une clé USB. */
	{
		AnalyseurPe pe;
		Collecteur texte;                       // scripts PowerShell : texte en mémoire
		const bool powershell = estScriptPowerShell(chemin);
		Duplicateur tee(&pe, powershell ? &texte : nullptr);
		RawHiveExtrait ligne;
		e.resultat = g_lecteur->lire(chemin, std::wstring(), ligne, &tee);
		pe.terminer();
		if (FAILED(e.resultat)) {
			log(3, L"🔈Empreinte impossible : " + chemin, e.resultat);
			// Absent : l'artefact le dit déjà, et ce n'est pas une pièce. Une
			// autre erreur est une pièce qu'on n'a pas pu lire : elle est consignée.
			if (e.resultat != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
				ligne.cheminSortie = cible;
				ConsigneAjouter({ ligne }, L"Lecture brute NTFS ; binaire cite par un artefact (--binary)");
			}
			return g_cache.emplace(cle, std::move(e)).first->second;
		}
		++g_lus;
		retenir(ligne);
		/* PE : empreinte Authenticode. Script ou document : SHA-256 des octets
		   bruts dans les catalogues, puis signature PowerShell intégrée. */
		VerdictMicrosoft v;
		if (pe.estPe()) v = EvaluerPe(pe, catalogues());
		else {
			uint8_t h[32];
			if (octetsDeHexa(e.sha256, h)) v = EvaluerParCatalogue(h, catalogues());
			if (!v.microsoft && powershell) {
				const VerdictMicrosoft ps = EvaluerScriptPowerShell(texte.octets.data(), texte.octets.size());
				if (ps.microsoft || ps.motif != "pas de signature intégrée") v = ps;
			}
		}
		{
			if (v.microsoft) {
				e.signature = L"Microsoft (" + v.source + L")";
				++g_authentifies;
				g_octetsAuthentifies += ligne.empreintes.octets;
				if (v.source.compare(0, 10, L"catalogue ") == 0)
					g_cataloguesUtilises.insert(v.source.substr(10));
				return g_cache.emplace(cle, std::move(e)).first->second;
			}
			log(3, L"🔈Preleve (" + string_to_wstring(v.motif) + L") : " + chemin);
		}
	}

	// Déjà en consigne (extrait par une autre phase) : rien à réécrire.
	if (std::filesystem::exists(cible, ec)) return g_cache.emplace(cle, std::move(e)).first->second;

	/* Chaque pièce prélevée sera recopiée vers le travail à la fin de la
	   collecte : la place qu'elle y prendra est déjà due. Sans ce terme, une
	   consigne remplie jusqu'à la réserve ne laissait plus de place pour sa
	   propre copie de travail. */
	const unsigned long long libre = ConsigneEspaceLibre();
	if (libre != 0 && libre < RESERVE + g_octets) {
		++g_sansPlace;
		log(2, L"🔥Place insuffisante : " + chemin + L" hache sans etre preleve");
		return g_cache.emplace(cle, std::move(e)).first->second;
	}

	// SECONDE LECTURE : prélèvement, par le répertoire d'arrivée (dédoublonnage).
	std::filesystem::create_directories(dossierArrivee(), ec);
	const std::wstring sortie = dossierArrivee() + L"\\" + std::to_wstring(++g_entrant) + L".bin";
	RawHiveExtrait ligne;
	e.resultat = g_lecteur->lire(chemin, sortie, ligne);
	const std::wstring methode = L"Lecture brute NTFS (\\\\.\\" + chemin.substr(0, 2)
	                           + L" — $MFT, index de repertoires, attribut $DATA) ; "
	                           L"binaire cite par un artefact (--binary)";
	if (FAILED(e.resultat)) {
		ligne.cheminSortie = cible;
		ConsigneAjouter({ ligne }, methode);
	}
	else {
		if (ligne.empreintes.sha256 != e.sha256)
			log(2, L"🔥Contenu modifie entre deux lectures : " + chemin);
		retenir(ligne);                     // la pièce fait foi
		const auto deja = g_parContenu.find(e.sha256);
		if (deja != g_parContenu.end()) {
			ligne.cheminSortie = deja->second;
			ConsigneAjouterDoublon(ligne, methode + L" ; contenu identique (SHA-256) "
			                                        L"a une piece deja consignee, non recopie");
			++g_doublons;
			g_octetsEvites += ligne.empreintes.octets;
			e.preleve = true;
		}
		else {
			std::filesystem::create_directories(std::filesystem::path(cible).parent_path(), ec);
			std::filesystem::rename(sortie, cible, ec);
			ligne.cheminSortie = cible;
			if (ec) {
				log(2, L"🔥Mise en consigne impossible : " + cible);
				ligne.resultat = e.resultat = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
			}
			else {
				g_parContenu.emplace(e.sha256, cible);
				e.preleve = true;
				++g_preleves;
				g_octets += ligne.empreintes.octets;
			}
			ConsigneAjouter({ ligne }, methode);
		}
	}
	std::filesystem::remove(sortie, ec);    // ce qui reste en arrivée : rien
	return g_cache.emplace(cle, std::move(e)).first->second;
}

void ajouterEmpreintes(Json& o, const EmpreinteBinaire& e,
                       const std::wstring& prefixe, const std::wstring& suffixe) {
	if (!e.md5.empty())    o.add(prefixe + L"Md5"    + suffixe, Json::str(e.md5));
	if (!e.sha1.empty())   o.add(prefixe + L"Sha1"   + suffixe, Json::str(e.sha1));
	if (!e.sha256.empty()) o.add(prefixe + L"Sha256" + suffixe, Json::str(e.sha256));
	if (!e.signature.empty()) o.add(prefixe + L"Signature" + suffixe, Json::str(e.signature));
}

BilanBinaires BinairesBilan() {
	BilanBinaires b;
	b.fichiers = g_cache.size();
	b.lus = g_lus;
	b.preleves = g_preleves;
	b.octetsPreleves = g_octets;
	b.sansPlace = g_sansPlace;
	b.doublons = g_doublons;
	b.octetsEvites = g_octetsEvites;
	b.authentifies = g_authentifies;
	b.octetsAuthentifies = g_octetsAuthentifies;
	b.cataloguesLus = g_cataloguesLus;
	b.cataloguesUtilises = g_cataloguesUtilises.size();
	return b;
}

void BinairesTerminer() {
	/* Les catalogues qui ont JUSTIFIÉ de ne pas prélever un binaire entrent
	   dans la consigne : sans eux, la décision ne serait pas vérifiable par un
	   tiers. Seuls ceux-là — pas les 5 000 de la machine. */
	if (g_lecteur && !g_cataloguesUtilises.empty()) {
		std::vector<RawHiveExtrait> releve;
		for (const std::wstring& nom : g_cataloguesUtilises) {
			const std::wstring source = dossierCatalogues() + L"\\" + nom;
			const std::wstring cible = cheminSous(dossierConsigne(), source);
			std::error_code ec;
			if (std::filesystem::exists(cible, ec)) continue;
			std::filesystem::create_directories(std::filesystem::path(cible).parent_path(), ec);
			RawHiveExtrait ligne;
			g_lecteur->lire(source, cible, ligne);
			releve.push_back(std::move(ligne));
		}
		ConsigneAjouter(releve, L"Lecture brute NTFS (\\\\.\\" + conf.systemDrive
		                        + L" — $MFT, index de repertoires, attribut $DATA) ; catalogue de "
		                        L"signatures Windows ayant justifie le non-prelevement de binaires "
		                        L"authentifies Microsoft (--binary)");
	}
	g_lecteur.reset();
	std::error_code ec;
	std::filesystem::remove_all(dossierArrivee(), ec);
}

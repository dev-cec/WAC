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
std::map<std::wstring, EmpreinteBinaire> g_cache;      // key: lowercase path
std::map<std::wstring, std::wstring> g_parContenu;    // SHA-256 -> exhibit in the store
size_t g_lus = 0, g_preleves = 0, g_sansPlace = 0, g_doublons = 0;
unsigned long long g_octets = 0, g_octetsEvites = 0;
size_t g_authentifies = 0, g_cataloguesLus = 0;
unsigned long long g_octetsAuthentifies = 0;
std::set<std::wstring> g_cataloguesUtilises;
const size_t CATALOGUE_MAX = 64 * 1024 * 1024;       // a catalog beyond that: ignored
unsigned long long g_entrant = 0;                      // counter of incoming files

/*! INCOMING directory, on the collection medium but outside the exhibit store.
 *
 *  DEDUPLICATION. A file's content is only known once it has been read. It is
 *  therefore written here first, hashed on the way, then RENAMED into the
 *  exhibit store if new, or deleted if it is already there under another path.
 *  The exhibit store thus only receives final exhibits: nothing is written then
 *  erased in it, and an interrupted collection leaves no temporary file there.
 *  A single read of the volume per file. */
std::wstring dossierArrivee() {
	return dossierConsigne() + L".arrivee";
}

/*! Space kept free on the collection medium: below it, files are hashed
 *  without being copied. Each exhibit is written twice (exhibit store then
 *  working copy), and the event logs, processed last, must still find room. */
const unsigned long long RESERVE = 1ULL << 30;

/*! What is collected: executables, libraries, drivers, the scripts a task or a
 *  Run key can launch, and Office documents ABLE TO CARRY MACROS.
 *
 *  MACRO DOCUMENTS. A booby-trapped document is an intrusion vector as common as
 *  an executable, and it shows in the traces: target of a shortcut or a jump
 *  list, file loaded by WINWORD.EXE or EXCEL.EXE in their Prefetch. Only the
 *  formats where VBA can live are kept: legacy binary formats (.doc, .xls,
 *  .ppt…), "m" formats (.docm, .xlsm…), .xlsb, templates and add-ins,
 *  Publisher, Visio and Access. .docx/.xlsx/.pptx cannot hold VBA: they are
 *  only hashed, like any document — copying them would turn the collection
 *  into a copy of the user's files. */
bool aPrelever(const std::wstring& chemin) {
	const size_t point = chemin.find_last_of(L'.');
	if (point == std::wstring::npos || chemin.find(L'\\', point) != std::wstring::npos) return false;
	static const wchar_t* const extensions[] = {
		// executables, libraries, drivers
		L"exe", L"dll", L"sys", L"ocx", L"cpl", L"scr", L"drv", L"efi", L"com", L"msi",
		// scripts
		L"ps1", L"psm1", L"bat", L"cmd", L"vbs", L"vbe", L"js", L"jse", L"wsf", L"wsh", L"hta",
		// Word
		L"doc", L"docm", L"dot", L"dotm",
		// Excel (xll and wll are DLLs loaded by Excel and Word)
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

/*! Buffer that keeps what is written to it: reading a catalog into memory. */
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

/*! Forwards what it receives to two buffers: the PE analysis and, for a
 *  PowerShell script, the in-memory copy of its text. */
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

//! Scripts whose embedded signature is verified (see EvaluerScriptPowerShell).
bool estScriptPowerShell(const std::wstring& chemin) {
	const size_t point = chemin.find_last_of(L'.');
	if (point == std::wstring::npos) return false;
	const std::wstring ext = enMinuscules(chemin.substr(point + 1));
	return ext == L"ps1" || ext == L"psm1" || ext == L"psd1" || ext == L"ps1xml"
	    || ext == L"psc1" || ext == L"cdxml";
}

//! Hexadecimal digest (64 characters) -> 32 bytes.
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

/*! Index of the machine's Microsoft catalogs, built on first request — hence
 *  only if a binary to collect is met. Catalogs are read raw, IN MEMORY:
 *  nothing is written, and no service is solicited (see authenticode.h). */
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
	std::set<uint64_t> vus;                  // a file can also appear under its short name
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

	const std::wstring cle = enMinuscules(chemin);       // NTFS is case-insensitive
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
		// Document or data: fingerprints only, nothing is written.
		RawHiveExtrait ligne;
		e.resultat = g_lecteur->lire(chemin, std::wstring(), ligne);
		if (SUCCEEDED(e.resultat)) { ++g_lus; retenir(ligne); }
		else log(3, L"🔈Empreinte impossible : " + chemin, e.resultat);
		return g_cache.emplace(cle, std::move(e)).first->second;
	}

	const std::wstring cible = cheminSous(dossierConsigne(), chemin);
	std::error_code ec;

	/* FIRST READ, WRITING NOTHING: fingerprints and, for a PE, Microsoft
	   authenticity. An authentic Microsoft binary — the vast majority — is thus
	   never written to the collection medium; only the others are read again to be
	   collected. Re-reading the examined disk costs less than writing then erasing
	   on a USB stick. */
	{
		AnalyseurPe pe;
		Collecteur texte;                       // PowerShell scripts: text in memory
		const bool powershell = estScriptPowerShell(chemin);
		Duplicateur tee(&pe, powershell ? &texte : nullptr);
		RawHiveExtrait ligne;
		e.resultat = g_lecteur->lire(chemin, std::wstring(), ligne, &tee);
		pe.terminer();
		if (FAILED(e.resultat)) {
			log(3, L"🔈Empreinte impossible : " + chemin, e.resultat);
			// Missing: the artefact already says so, and it is not an exhibit. Any
			// other error is an exhibit that could not be read: it is recorded.
			if (e.resultat != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
				ligne.cheminSortie = cible;
				ConsigneAjouter({ ligne }, L"Lecture brute NTFS ; binaire cite par un artefact (--binary)");
			}
			return g_cache.emplace(cle, std::move(e)).first->second;
		}
		++g_lus;
		retenir(ligne);
		/* PE: Authenticode digest. Script or document: SHA-256 of the raw bytes in
		   the catalogs, then embedded PowerShell signature. */
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

	// Already in the exhibit store (extracted by another phase): nothing to rewrite.
	if (std::filesystem::exists(cible, ec)) return g_cache.emplace(cle, std::move(e)).first->second;

	/* Each collected exhibit will be copied to the working directory at the end
	   of the collection: the room it will take there is already owed. Without this
	   term, an exhibit store filled up to the reserve left no room for its own
	   working copy. */
	const unsigned long long libre = ConsigneEspaceLibre();
	if (libre != 0 && libre < RESERVE + g_octets) {
		++g_sansPlace;
		log(2, L"🔥Place insuffisante : " + chemin + L" hache sans etre preleve");
		return g_cache.emplace(cle, std::move(e)).first->second;
	}

	// SECOND READ: collection, through the incoming directory (deduplication).
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
		retenir(ligne);                     // the exhibit is authoritative
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
	std::filesystem::remove(sortie, ec);    // whatever is left in the incoming directory: nothing
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
	/* The catalogs that JUSTIFIED not collecting a binary go into the exhibit
	   store: without them, the decision could not be checked by a third party.
	   Only those — not the machine's 5,000. */
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

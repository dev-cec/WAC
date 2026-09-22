/*  binaires.cpp — voir binaires.h. */
#include "binaires.h"
#include <map>
#include <memory>
#include <filesystem>
#include "tools.h"
#include "raw_hive.h"
#include "consigne.h"

namespace {

std::unique_ptr<LecteurBrut> g_lecteur;
std::map<std::wstring, EmpreinteBinaire> g_cache;      // clé : chemin en minuscules
std::map<std::wstring, std::wstring> g_parContenu;    // SHA-256 -> pièce en consigne
size_t g_lus = 0, g_preleves = 0, g_sansPlace = 0, g_doublons = 0;
unsigned long long g_octets = 0, g_octetsEvites = 0;
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

/*! Ce qui se prélève : exécutables, bibliothèques, pilotes, et les scripts
 *  qu'une tâche ou une clé Run peut lancer. */
bool aPrelever(const std::wstring& chemin) {
	const size_t point = chemin.find_last_of(L'.');
	if (point == std::wstring::npos || chemin.find(L'\\', point) != std::wstring::npos) return false;
	static const wchar_t* const extensions[] = {
		L"exe", L"dll", L"sys", L"ocx", L"cpl", L"scr", L"drv", L"efi", L"com", L"msi",
		L"ps1", L"psm1", L"bat", L"cmd", L"vbs", L"vbe", L"js", L"jse", L"wsf", L"wsh", L"hta",
	};
	const std::wstring ext = enMinuscules(chemin.substr(point + 1));
	for (const wchar_t* e : extensions) if (ext == e) return true;
	return false;
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

	/* Destination : la consigne, sous le chemin d'origine, si le fichier est à
	   prélever et qu'il reste de la place. Une pièce déjà consignée (extraite
	   par une autre phase) n'est pas réécrite : on la relit seulement. */
	std::wstring sortie;
	std::wstring cible;
	bool manqueDePlace = false;
	if (aPrelever(chemin)) {
		cible = cheminSous(dossierConsigne(), chemin);
		std::error_code ec;
		const unsigned long long libre = ConsigneEspaceLibre();
		if (std::filesystem::exists(cible, ec)) {
			// déjà en consigne : empreintes seules
		}
		/* Chaque pièce prélevée sera recopiée vers le travail à la fin de la
		   collecte : la place qu'elle y prendra est déjà due. Sans ce terme, une
		   consigne remplie jusqu'à la réserve ne laissait plus de place pour sa
		   propre copie de travail. */
		else if (libre != 0 && libre < RESERVE + g_octets) {
			manqueDePlace = true;
		}
		else {
			std::filesystem::create_directories(dossierArrivee(), ec);
			sortie = dossierArrivee() + L"\\" + std::to_wstring(++g_entrant) + L".bin";
		}
	}

	RawHiveExtrait ligne;
	e.resultat = g_lecteur->lire(chemin, sortie, ligne);
	if (SUCCEEDED(e.resultat)) {
		++g_lus;
		e.md5    = ligne.empreintes.md5;
		e.sha1   = ligne.empreintes.sha1;
		e.sha256 = ligne.empreintes.sha256;
	}
	if (!sortie.empty()) {
		std::error_code ec;
		const std::wstring methode = L"Lecture brute NTFS (\\\\.\\" + chemin.substr(0, 2)
		                           + L" — $MFT, index de repertoires, attribut $DATA) ; "
		                           L"binaire cite par un artefact (--binary)";
		if (e.resultat == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
			// Disparu depuis que l'artefact l'a cité : l'artefact le dit déjà,
			// et ce n'est pas une pièce.
		}
		else if (FAILED(e.resultat)) {
			ligne.cheminSortie = cible;
			ConsigneAjouter({ ligne }, methode);
		}
		else {
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
				if (ec) {
					log(2, L"🔥Mise en consigne impossible : " + cible);
					ligne.resultat = e.resultat = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
					ligne.cheminSortie = cible;
					ConsigneAjouter({ ligne }, methode);
				}
				else {
					ligne.cheminSortie = cible;
					ConsigneAjouter({ ligne }, methode);
					g_parContenu.emplace(e.sha256, cible);
					e.preleve = true;
					++g_preleves;
					g_octets += ligne.empreintes.octets;
				}
			}
		}
		std::filesystem::remove(sortie, ec);    // ce qui reste en arrivée : rien
	}
	if (manqueDePlace) {
		++g_sansPlace;
		log(2, L"🔥Place insuffisante : " + chemin + L" hache sans etre preleve");
	}
	if (FAILED(e.resultat))
		log(3, L"🔈Empreinte impossible : " + chemin, e.resultat);
	return g_cache.emplace(cle, std::move(e)).first->second;
}

void ajouterEmpreintes(Json& o, const EmpreinteBinaire& e,
                       const std::wstring& prefixe, const std::wstring& suffixe) {
	if (!e.md5.empty())    o.add(prefixe + L"Md5"    + suffixe, Json::str(e.md5));
	if (!e.sha1.empty())   o.add(prefixe + L"Sha1"   + suffixe, Json::str(e.sha1));
	if (!e.sha256.empty()) o.add(prefixe + L"Sha256" + suffixe, Json::str(e.sha256));
}

void BinairesBilan(size_t* fichiers, size_t* lus, size_t* preleves,
                   unsigned long long* octetsPreleves, size_t* sansPlace,
                   size_t* doublons, unsigned long long* octetsEvites) {
	if (doublons) *doublons = g_doublons;
	if (octetsEvites) *octetsEvites = g_octetsEvites;
	if (fichiers) *fichiers = g_cache.size();
	if (lus) *lus = g_lus;
	if (preleves) *preleves = g_preleves;
	if (octetsPreleves) *octetsPreleves = g_octets;
	if (sansPlace) *sansPlace = g_sansPlace;
}

void BinairesTerminer() {
	g_lecteur.reset();
	std::error_code ec;
	std::filesystem::remove_all(dossierArrivee(), ec);
}

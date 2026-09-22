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
size_t g_lus = 0, g_preleves = 0, g_sansPlace = 0;
unsigned long long g_octets = 0;

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
	bool manqueDePlace = false;
	if (aPrelever(chemin)) {
		const std::wstring cible = cheminSous(dossierConsigne(), chemin);
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
			std::filesystem::create_directories(std::filesystem::path(cible).parent_path(), ec);
			sortie = cible;
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
		const bool absent = e.resultat == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
		if (absent) {
			// Fichier disparu depuis que l'artefact l'a cité : l'artefact le dit
			// déjà, et ce n'est pas une pièce. Pas de répertoire vide non plus.
			std::error_code ec;
			std::filesystem::remove(std::filesystem::path(sortie).parent_path(), ec);
		}
		else {
			ConsigneAjouter({ ligne }, L"Lecture brute NTFS (\\\\.\\" + chemin.substr(0, 2)
			                           + L" — $MFT, index de repertoires, attribut $DATA) ; "
			                           L"binaire cite par un artefact (--binary)");
			if (SUCCEEDED(e.resultat)) {
				e.preleve = true;
				++g_preleves;
				g_octets += ligne.empreintes.octets;
			}
		}
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
                   unsigned long long* octetsPreleves, size_t* sansPlace) {
	if (fichiers) *fichiers = g_cache.size();
	if (lus) *lus = g_lus;
	if (preleves) *preleves = g_preleves;
	if (octetsPreleves) *octetsPreleves = g_octets;
	if (sansPlace) *sansPlace = g_sansPlace;
}

void BinairesTerminer() {
	g_lecteur.reset();
}

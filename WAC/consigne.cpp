#include "consigne.h"
#include "tools.h"
#include "audit.h"
#include "json.h"
#include "sha.h"
#include <fstream>
#include <filesystem>
#include <map>

/*  consigne.cpp — voir consigne.h pour la procédure et le contenu du manifeste.
 *  Ici, l'implémentation.
 */

namespace {

//! Une pièce au manifeste.
struct Piece {
	RawHiveExtrait extrait;
	std::wstring   methode;
};

std::vector<Piece> g_pieces;
//! Volumes effectivement lus, par lettre : relevés une fois chacun.
std::map<std::wstring, std::wstring> g_volumes;   // lettre -> "série | système de fichiers"

//! FILETIME depuis un entier 64 bits, forme dans laquelle raw_hive les rend.
FILETIME versFiletime(uint64_t v) {
	FILETIME f = { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) };
	return f;
}

/*! Ajoute un horodatage sous ses deux formes, UTC et heure locale du SUSPECT.
 *  Rien n'est écrit si la date est nulle : un champ vide se lirait comme une
 *  date que le format ne portait pas, alors qu'il ne la portait effectivement
 *  pas — mais un « 1601-01-01 » se lirait, lui, comme une vraie date.
 */
void ajouterDate(Json& o, const std::wstring& cle, uint64_t filetimeUtc) {
	if (filetimeUtc == 0) return;
	const FILETIME f = versFiletime(filetimeUtc);
	o.add(cle + L"Utc", Json::str(timeToIso8601Utc(f)));
	o.add(cle,          Json::str(utcTimeToIso8601Local(f)));
}

//! Relève le numéro de série et le système de fichiers d'un volume.
std::wstring signatureVolume(const std::wstring& lettre) {
	const std::wstring racine = lettre + L":\\";
	DWORD serie = 0;
	wchar_t fs[64] = { 0 };
	if (!GetVolumeInformationW(racine.c_str(), nullptr, 0, &serie, nullptr, nullptr,
	                           fs, (DWORD)(sizeof(fs) / sizeof(fs[0]))))
		return L"";
	wchar_t hex[16] = { 0 };
	swprintf(hex, 16, L"%08X", (unsigned)serie);
	return std::wstring(hex) + L" | " + fs;
}

//! Lettre de volume d'un chemin source « X:\... ».
std::wstring lettreDe(const std::wstring& cheminVolume) {
	if (cheminVolume.size() >= 2 && cheminVolume[1] == L':')
		return cheminVolume.substr(0, 1);
	return L"";
}

/*! Chemin d'une pièce RELATIF au répertoire de sortie.
 *
 *  Le manifeste ne doit pas porter le chemin absolu de la machine de collecte :
 *  il n'identifie rien de la pièce, il expose l'arborescence de l'examinateur,
 *  et il devient faux dès que le support est monté ailleurs — c'est-à-dire à la
 *  première lecture par quelqu'un d'autre.
 */
std::wstring relatifSortie(const std::wstring& absolu) {
	std::error_code ec;
	const std::filesystem::path rel = std::filesystem::relative(
		std::filesystem::path(absolu), std::filesystem::path(string_to_wstring(conf._outputDir)), ec);
	if (ec || rel.empty()) return absolu;      // hors du dossier de sortie : tel quel
	return rel.wstring();
}

} // namespace

std::wstring dossierConsigne() {
	return string_to_wstring(conf._outputDir) + L"\\consigne";
}

std::wstring dossierTravail() {
	return string_to_wstring(conf._outputDir) + L"\\travail";
}

unsigned long long ConsigneEspaceLibre() {
	ULARGE_INTEGER libre = { 0 };
	const std::wstring sortie = string_to_wstring(conf._outputDir);
	std::error_code ec;
	std::filesystem::create_directories(sortie, ec);
	if (!GetDiskFreeSpaceExW(sortie.c_str(), &libre, nullptr, nullptr)) return 0;
	return libre.QuadPart;
}

HRESULT ConsigneVerifierEmplacement(unsigned long long besoinEstime) {
	std::error_code ec;

	// 1. Un travail deja peuplé ferait analyser une collecte antérieure.
	const std::filesystem::path travail = dossierTravail();
	if (std::filesystem::exists(travail, ec)) {
		bool peuple = false;
		for (const std::filesystem::directory_entry& e :
		     std::filesystem::recursive_directory_iterator(travail, ec)) {
			if (ec) break;
			if (e.is_regular_file(ec)) { peuple = true; break; }
		}
		if (peuple) {
			log(2, L"🔥Le répertoire de travail contient déjà des fichiers : "
			       + travail.wstring()
			       + L" — une collecte antérieure serait analysée à la place de "
			       L"celle-ci. Utilisez --output vers un dossier neuf.",
			    ERROR_DIR_NOT_EMPTY);
			return HRESULT_FROM_WIN32(ERROR_DIR_NOT_EMPTY);
		}
	}

	// 2. Place disponible. Le besoin est doublé : consigne + travail.
	const unsigned long long libre = ConsigneEspaceLibre();
	if (libre == 0) {
		// Information indisponible : on ne bloque pas sur une mesure ratée.
		log(2, L"🔥Espace libre indéterminé sur le support de collecte : "
		       L"vérification ignorée");
		return ERROR_SUCCESS;
	}
	const unsigned long long besoin = besoinEstime * 2;
	log(2, L"❇️Support de collecte : " + std::to_wstring(libre / 1024 / 1024)
	     + L" Mio libres, " + std::to_wstring(besoin / 1024 / 1024)
	     + L" Mio estimés nécessaires (consigne + travail)");
	if (libre < besoin) {
		log(2, L"🔥Place insuffisante sur le support de collecte : "
		       + std::to_wstring(libre / 1024 / 1024) + L" Mio libres pour "
		       + std::to_wstring(besoin / 1024 / 1024) + L" Mio nécessaires",
		    ERROR_DISK_FULL);
		return HRESULT_FROM_WIN32(ERROR_DISK_FULL);
	}
	return ERROR_SUCCESS;
}

void ConsigneAjouter(const std::vector<RawHiveExtrait>& releve,
                     const std::wstring& methode) {
	for (const RawHiveExtrait& e : releve) {
		g_pieces.push_back(Piece{ e, methode });
		const std::wstring lettre = lettreDe(e.cheminVolume);
		if (!lettre.empty() && g_volumes.find(lettre) == g_volumes.end())
			g_volumes.emplace(lettre, signatureVolume(lettre));
	}
}

void ConsigneBilan(size_t* pieces, size_t* echecs, unsigned long long* octets) {
	size_t nb = 0, ko = 0;
	unsigned long long total = 0;
	for (const Piece& p : g_pieces) {
		++nb;
		if (FAILED(p.extrait.resultat)) ++ko;
		else total += p.extrait.empreintes.octets;
	}
	if (pieces) *pieces = nb;
	if (echecs) *echecs = ko;
	if (octets) *octets = total;
}

HRESULT ConsigneVersTravail(size_t* copies, unsigned long long* octets) {
	if (copies) *copies = 0;
	if (octets) *octets = 0;

	const std::filesystem::path consigne = dossierConsigne();
	const std::filesystem::path travail  = dossierTravail();
	std::error_code ec;
	if (!std::filesystem::exists(consigne, ec)) {
		log(2, L"🔥Consigne absente : " + consigne.wstring(), ERROR_PATH_NOT_FOUND);
		return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
	}
	std::filesystem::create_directories(travail, ec);

	/*  Empreintes du manifeste, indexées par chemin de consigne : la copie de
	 *  travail est comparée à ce qui a été LU DU VOLUME, pas à une relecture de
	 *  la consigne. Une consigne déjà altérée serait ainsi détectée aussi. */
	std::map<std::wstring, std::wstring> attendu;   // chemin -> SHA-256
	for (const Piece& p : g_pieces)
		if (SUCCEEDED(p.extrait.resultat) && !p.extrait.empreintes.sha256.empty())
			attendu.emplace(p.extrait.cheminSortie, p.extrait.empreintes.sha256);

	size_t nb = 0, ko = 0, verifies = 0, existants = 0;
	unsigned long long volume = 0;
	HRESULT global = ERROR_SUCCESS;

	for (const std::filesystem::directory_entry& e :
	     std::filesystem::recursive_directory_iterator(consigne, ec)) {
		if (ec) break;
		if (!e.is_regular_file(ec)) continue;

		const std::filesystem::path relatif =
			std::filesystem::relative(e.path(), consigne, ec);
		if (ec) continue;
		// Le manifeste et son sceau appartiennent à la consigne seule : les
		// recopier dans le travail inviterait à les modifier.
		const std::wstring nom = relatif.filename().wstring();
		if (nom == L"MANIFESTE.json" || nom == L"MANIFESTE.sha256") continue;

		const std::filesystem::path cible = travail / relatif;
		/*  ON N'ÉCRASE PAS une copie de travail existante. La fonction est
		 *  appelée après chaque phase d'extraction ; écraser reviendrait à
		 *  défaire le travail déjà fait sur les fichiers de la phase précédente
		 *  — en particulier le rejeu des journaux de transaction des ruches,
		 *  qui a lieu juste après leur copie. */
		if (std::filesystem::exists(cible, ec)) { ++existants; continue; }
		std::filesystem::create_directories(cible.parent_path(), ec);
		std::filesystem::copy_file(e.path(), cible,
		                           std::filesystem::copy_options::overwrite_existing, ec);
		if (ec) {
			log(2, L"🔥Copie vers le travail impossible : " + relatif.wstring());
			++ko;
			global = S_FALSE;
			continue;
		}
		++nb;
		volume += (unsigned long long)std::filesystem::file_size(cible, ec);

		/*  VÉRIFICATION DE LA COPIE. Sans elle, une copie silencieusement
		 *  tronquée — support plein, écriture en erreur — donnerait un
		 *  répertoire de travail qui ne correspond pas à la pièce, et toute
		 *  l'analyse porterait sur autre chose. */
		const auto att = attendu.find(e.path().wstring());
		if (att != attendu.end()) {
			const std::wstring obtenu = sha256Fichier(cible.wstring());
			if (obtenu != att->second) {
				log(2, L"🔥Copie de travail non conforme à la consigne : "
				       + relatif.wstring() + L" (attendu " + att->second
				       + L", obtenu " + obtenu + L")");
				++ko;
				global = S_FALSE;
			}
			else ++verifies;
		}
	}

	log(2, L"❇️Travail : " + std::to_wstring(nb) + L" fichier(s) recopié(s), "
	     + std::to_wstring(verifies) + L" vérifié(s) par empreinte, "
	     + std::to_wstring(existants) + L" déjà présent(s), "
	     + std::to_wstring(ko) + L" écart(s)");
	if (copies) *copies = nb;
	if (octets) *octets = volume;
	return global;
}

HRESULT ConsigneEcrireManifeste() {
	std::error_code ec;
	const std::filesystem::path consigne = dossierConsigne();
	std::filesystem::create_directories(consigne, ec);

	// Le contexte vient de l'audit : une seule construction pour les deux
	// documents de la collecte (cf. auditContexte).
	Json racine = auditContexte();

	size_t nb = 0, ko = 0;
	unsigned long long total = 0;
	ConsigneBilan(&nb, &ko, &total);

	Json garde = Json::obj();
	garde.add(L"ExhibitDirectory",  Json::str(L"consigne"));
	garde.add(L"WorkingDirectory",  Json::str(L"travail"));
	garde.add(L"Statement", Json::str(
		L"Les fichiers de « consigne » sont les copies brutes telles que lues du "
		L"volume : elles ne sont jamais réouvertes en écriture. Toute analyse, et "
		L"toute modification (rejeu des journaux de transaction, alignement du bloc "
		L"de base d'une ruche), portent sur « travail », recopié depuis la consigne "
		L"et vérifié par empreinte. Aucune écriture n'a été faite sur le système "
		L"examiné."));
	garde.add(L"ExtractionStartUtc",   Json::str(auditDebutUtc()));
	garde.add(L"ExtractionStart",      Json::str(auditDebutLocal()));
	std::wstring finUtc, finLocal;
	{
		FILETIME f = { 0, 0 };
		GetSystemTimeAsFileTime(&f);
		finUtc   = timeToIso8601Utc(f);
		finLocal = utcTimeToIso8601Local(f);
	}
	garde.add(L"ManifestWrittenUtc",   Json::str(finUtc));
	garde.add(L"ManifestWritten",      Json::str(finLocal));
	garde.add(L"ItemCount",            Json::num((unsigned long long)nb));
	garde.add(L"FailedCount",          Json::num((unsigned long long)ko));
	garde.add(L"TotalBytes",           Json::num(total));
	garde.add(L"HashAlgorithms",       Json::str(L"MD5, SHA-1, SHA-256"));
	garde.add(L"NoWriteToExaminedSystem", Json::boolean(true));

	Json volumes = Json::arr();
	for (const auto& v : g_volumes) {
		Json o = Json::obj();
		o.add(L"Letter", Json::str(v.first));
		// Le numéro de série et le système de fichiers rattachent la pièce au
		// support physique, indépendamment de la lettre, qui peut changer.
		const size_t sep = v.second.find(L" | ");
		if (sep != std::wstring::npos) {
			o.add(L"SerialNumber", Json::str(v.second.substr(0, sep)));
			o.add(L"FileSystem",   Json::str(v.second.substr(sep + 3)));
		}
		o.add(L"RawDevice", Json::str(L"\\\\.\\" + v.first + L":"));
		volumes.push(std::move(o));
	}
	garde.add(L"VolumesRead", std::move(volumes));
	racine.add(L"Custody", std::move(garde));

	Json pieces = Json::arr();
	for (const Piece& p : g_pieces) {
		const RawHiveExtrait& e = p.extrait;
		const RawHiveEmpreintes& m = e.empreintes;
		Json o = Json::obj();
		o.add(L"SourcePath",  Json::str(e.cheminVolume));
		o.add(L"ExhibitPath", Json::str(relatifSortie(e.cheminSortie)));
		o.add(L"Method",      Json::str(p.methode));
		if (FAILED(e.resultat)) {
			// Une pièce absente du manifeste se lirait comme jamais cherchée.
			o.add(L"Result", Json::str(L"0x" + to_hex(e.resultat) + L" "
			                           + getErrorMessage(e.resultat)));
			pieces.push(std::move(o));
			continue;
		}
		o.add(L"Result",        Json::str(L"OK"));
		o.add(L"MD5",           Json::str(m.md5));
		o.add(L"SHA1",          Json::str(m.sha1));
		o.add(L"SHA256",        Json::str(m.sha256));
		o.add(L"Bytes",         Json::num(m.octets));
		// Divergence des deux tailles = extraction tronquée, qu'une empreinte
		// seule ne révélerait pas (elle serait juste... celle du tronqué).
		if (m.tailleAnnoncee != m.octets)
			o.add(L"DeclaredBytes", Json::num(m.tailleAnnoncee));
		/* Fichier préalloué : ce qui suit n'a jamais été écrit et vaut zéro dans
		   la pièce, quel que soit le contenu des grappes sur le disque. À
		   déclarer, sans quoi une pièce de 1 Mio dont 135 Kio seulement portent
		   des données paraît simplement « pleine de zéros ». */
		if (!m.resident && m.tailleValide < m.tailleAnnoncee)
			o.add(L"ValidDataBytes", Json::num(m.tailleValide));
		o.add(L"MftEntry",      Json::num(m.mftEntry));
		if (m.resident) o.add(L"ResidentData", Json::boolean(true));
		ajouterDate(o, L"Extracted",         m.extraitUtc);
		ajouterDate(o, L"SourceCreated",     m.creeUtc);
		ajouterDate(o, L"SourceModified",    m.modifieUtc);
		ajouterDate(o, L"SourceMftModified", m.mftModifieUtc);
		ajouterDate(o, L"SourceAccessed",    m.accedeUtc);
		pieces.push(std::move(o));
	}
	racine.add(L"Items", std::move(pieces));

	// Écriture du manifeste. Chemin absolu : writeJsonFile écrit sous
	// _outputDir, ce qui n'est pas la consigne.
	const std::filesystem::path chemin = consigne / L"MANIFESTE.json";
	{
		std::wofstream f;
		f.open(chemin);
		if (!f) {
			log(2, L"🔥Manifeste de consigne non écrit : " + chemin.wstring());
			return E_FAIL;
		}
		f << ansi_to_utf8(racine.dump(0));
		f.close();
	}

	/*  SCEAU. Un manifeste ne peut pas porter sa propre empreinte : elle est
	 *  écrite à côté, après lui. Sans ce second fichier, une retouche du
	 *  manifeste serait indétectable — et le manifeste est précisément ce qui
	 *  atteste des pièces. */
	const std::wstring empreinte = sha256Fichier(chemin.wstring());
	const std::filesystem::path sceau = consigne / L"MANIFESTE.sha256";
	{
		std::wofstream f;
		f.open(sceau);
		if (!f || empreinte.empty()) {
			log(2, L"🔥Sceau du manifeste non écrit : " + sceau.wstring());
			return E_FAIL;
		}
		// Format sha256sum : « <empreinte>  <nom> », lisible par les outils
		// courants sans rien connaître de WAC.
		f << ansi_to_utf8(empreinte + L"  MANIFESTE.json\n");
		f.close();
	}

	log(2, L"❇️Manifeste de consigne : " + std::to_wstring(nb) + L" pièce(s), "
	     + std::to_wstring(ko) + L" échec(s), "
	     + std::to_wstring(total / 1024 / 1024) + L" Mio");
	log(2, L"❇️Sceau du manifeste (SHA-256) : " + empreinte);
	return ERROR_SUCCESS;
}

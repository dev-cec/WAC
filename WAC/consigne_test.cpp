/*  consigne_test.cpp — verifie la procedure consigne / travail.
 *
 *  Ce que ce test cherche a prendre en defaut, et qu'aucune compilation ne
 *  revele : que la consigne soit modifiee. C'est la seule chose qui ne doit
 *  JAMAIS arriver, et c'est silencieux quand ca arrive — le rapport reste
 *  d'apparence correcte, seule la piece est perdue.
 *
 *  Le raw NTFS n'est pas exerce ici (il exige un vrai volume) : les pieces sont
 *  des fichiers fournis en argument, et le reste de la chaine est celle de
 *  production — memes empreintes, meme manifeste, meme copie verifiee, meme
 *  rejeu.
 *
 *  Usage : consigne_test.exe <repertoire de sortie> <ruche> [ruche...]
 *  Exclu du build de WAC par le motif « _test.cpp » de build-windows.sh.
 */
#include "consigne.h"
#include "hive_recover.h"
#include "sha.h"
#include "quickdigest5.h"
#include "tools.h"
#include "audit.h"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <vector>
#include <map>

AppliConf conf;

namespace {

std::string etroit(const std::wstring& w){
	std::string r;
	for (wchar_t c : w) r += (char)(c < 128 ? (char)c : '?');
	return r;
}

//! Copie un fichier dans la consigne et rend son releve, empreintes comprises.
RawHiveExtrait deposerEnConsigne(const std::filesystem::path& source,
                                 const std::wstring& cheminVolumeSimule){
	RawHiveExtrait e;
	e.cheminVolume = cheminVolumeSimule;
	e.cheminSortie = cheminSous(dossierConsigne(), cheminVolumeSimule);

	std::error_code ec;
	std::filesystem::create_directories(
		std::filesystem::path(e.cheminSortie).parent_path(), ec);

	std::ifstream in(source, std::ios::binary);
	std::ofstream out(std::filesystem::path(e.cheminSortie), std::ios::binary | std::ios::trunc);
	if (!in || !out){ e.resultat = E_FAIL; return e; }

	// Empreintes calculees au fil de l'ecriture, comme le fait l'extraction.
	Md5Stream m; Sha1Stream s1; Sha256Stream s2;
	std::vector<char> tampon(1 << 16);
	uint64_t total = 0;
	while (in.read(tampon.data(), (std::streamsize)tampon.size()) || in.gcount()){
		const size_t n = (size_t)in.gcount();
		out.write(tampon.data(), (std::streamsize)n);
		m.update((const uint8_t*)tampon.data(), n);
		s1.update((const uint8_t*)tampon.data(), n);
		s2.update((const uint8_t*)tampon.data(), n);
		total += n;
	}
	e.empreintes.md5    = m.hexDigest();
	e.empreintes.sha1   = s1.hexDigest();
	e.empreintes.sha256 = s2.hexDigest();
	e.empreintes.octets = total;
	e.empreintes.tailleAnnoncee = total;
	e.empreintes.mftEntry = 42;          // valeur simulee : pas de $MFT ici
	FILETIME f = { 0, 0 };
	GetSystemTimeAsFileTime(&f);
	e.empreintes.extraitUtc = ((uint64_t)f.dwHighDateTime << 32) | f.dwLowDateTime;
	e.resultat = ERROR_SUCCESS;
	return e;
}

int echecs = 0;
void verifier(bool ok, const std::string& libelle){
	std::cout << (ok ? "  ok     " : "  ECHEC  ") << libelle << "\n";
	if (!ok) ++echecs;
}

} // namespace

int wmain(int argc, wchar_t** argv){
	if (argc < 3){
		std::cout << "usage: consigne_test <repertoire de sortie> <ruche> [ruche...]\n";
		return 2;
	}
	{
		// conf._outputDir est en octets etroits (cf. tools.h).
		std::wstring sortie = argv[1];
		std::string etroitSortie;
		for (wchar_t c : sortie) etroitSortie += (char)c;
		conf._outputDir = etroitSortie;
	}
	conf.systemDrive = L"C:";
	char* faux[] = { (char*)"consigne_test" };
	auditInit(1, faux);

	std::error_code ec;
	std::filesystem::remove_all(dossierConsigne(), ec);
	std::filesystem::remove_all(dossierTravail(), ec);

	// --- 1. « extraction » vers la consigne ---------------------------------
	std::vector<RawHiveExtrait> releve;
	std::vector<std::wstring> nomsRuches;
	for (int i = 2; i < argc; ++i){
		const std::filesystem::path source = argv[i];
		const std::wstring nom = source.filename().wstring();
		nomsRuches.push_back(nom);
		releve.push_back(deposerEnConsigne(source, L"C:\\Windows\\system32\\config\\" + nom));
		// Les journaux de transaction accompagnent la ruche.
		for (const wchar_t* suffixe : { L".LOG1", L".LOG2" }){
			const std::filesystem::path j = source.wstring() + suffixe;
			if (std::filesystem::exists(j, ec))
				releve.push_back(deposerEnConsigne(
					j, L"C:\\Windows\\system32\\config\\" + nom + suffixe));
		}
	}
	ConsigneAjouter(releve, L"Test : copie directe (le raw NTFS n'est pas exerce ici)");

	// Empreintes de la consigne AVANT toute suite : c'est ce qui ne doit pas bouger.
	std::map<std::wstring, std::wstring> avant;
	for (const std::filesystem::directory_entry& e :
	     std::filesystem::recursive_directory_iterator(dossierConsigne(), ec))
		if (e.is_regular_file(ec)) avant[e.path().wstring()] = sha256Fichier(e.path().wstring());
	verifier(!avant.empty(), "la consigne contient des pieces (" + std::to_string(avant.size()) + ")");

	// --- 2. consigne -> travail, verifie par empreinte ----------------------
	size_t copies = 0; unsigned long long octets = 0;
	const HRESULT hrCopie = ConsigneVersTravail(&copies, &octets);
	verifier(hrCopie == ERROR_SUCCESS, "copie vers le travail sans ecart");
	verifier(copies == avant.size(), "tous les fichiers recopies ("
	         + std::to_string(copies) + "/" + std::to_string(avant.size()) + ")");

	// --- 3. rejeu, qui ne doit porter QUE sur le travail --------------------
	for (const std::wstring& nom : nomsRuches){
		const std::wstring cible = cheminSous(dossierTravail(),
		                                      L"C:\\Windows\\system32\\config\\" + nom);
		const HiveReplayInfo r = ReplayHiveLogs(cible, L"00000000000000000000000000000000");
		std::cout << "         " << etroit(nom) << " : " << etroit(HiveReplayInfoToString(r)) << "\n";
		verifier(r.ok, etroit(nom) + " : rejeu sans erreur");
	}

	// --- 4. LA CONSIGNE EST-ELLE INTACTE ? ---------------------------------
	int bougees = 0;
	for (const auto& kv : avant)
		if (sha256Fichier(kv.first) != kv.second){
			++bougees;
			std::cout << "         MODIFIE : " << etroit(kv.first) << "\n";
		}
	verifier(bougees == 0, "consigne intacte apres rejeu (" + std::to_string(avant.size())
	         + " fichier(s) verifie(s))");

	// --- 5. le travail, lui, doit avoir change -----------------------------
	int changes = 0;
	for (const auto& kv : avant){
		const std::filesystem::path rel = std::filesystem::relative(
			std::filesystem::path(kv.first), std::filesystem::path(dossierConsigne()), ec);
		const std::filesystem::path t = std::filesystem::path(dossierTravail()) / rel;
		if (std::filesystem::exists(t, ec) && sha256Fichier(t.wstring()) != kv.second) ++changes;
	}
	verifier(changes > 0, "le travail differe de la consigne apres rejeu ("
	         + std::to_string(changes) + " fichier(s))");

	// --- 6. manifeste et sceau ---------------------------------------------
	const HRESULT hrManifeste = ConsigneEcrireManifeste();
	verifier(hrManifeste == ERROR_SUCCESS, "manifeste et sceau ecrits");
	const std::filesystem::path manifeste = std::filesystem::path(dossierConsigne()) / L"MANIFESTE.json";
	const std::filesystem::path sceau     = std::filesystem::path(dossierConsigne()) / L"MANIFESTE.sha256";
	verifier(std::filesystem::exists(manifeste, ec), "MANIFESTE.json present");
	verifier(std::filesystem::exists(sceau, ec),     "MANIFESTE.sha256 present");

	// Le sceau doit porter l'empreinte reelle du manifeste.
	std::wstring attendu = sha256Fichier(manifeste.wstring());
	std::ifstream fs(sceau);
	std::string ligne;
	std::getline(fs, ligne);
	const std::string att = etroit(attendu);
	verifier(ligne.compare(0, att.size(), att) == 0,
	         "le sceau porte l'empreinte du manifeste");

	// Le manifeste ne doit PAS avoir ete recopie dans le travail.
	verifier(!std::filesystem::exists(
	             std::filesystem::path(dossierTravail()) / L"MANIFESTE.json", ec),
	         "le manifeste n'est pas recopie dans le travail");

	std::cout << (echecs ? "ECHECS : " : "tous conformes (echecs : ") << echecs
	          << (echecs ? "\n" : ")\n");
	return echecs ? 1 : 0;
}

/*  raw_collect.cpp — voir raw_collect.h. */
#include "raw_collect.h"
#include <string>
#include <vector>
#include <tuple>
#include <filesystem>
#include <map>
#include "tools.h"
#include "audit.h"
#include "raw_hive.h"
#include "hive_recover.h"
#include "quickdigest5.h"

namespace {

/*! Rend un chemin absolu relatif à la racine du volume système.
*
* « C:\Users\jean » -> « \Users\jean ». La lettre de lecteur n'est retirée
* qu'en TÊTE : `replaceAll()`, employé jusqu'ici, en retirait toutes les
* occurrences, si bien qu'un chemin contenant à nouveau la lettre suivie de
* deux-points se retrouvait silencieusement altéré.
*/
std::wstring cheminRelatifAuVolume(const std::wstring& absolu) {
	if (absolu.size() >= conf.systemDrive.size()
	    && enMinuscules(absolu.substr(0, conf.systemDrive.size()))
	       == enMinuscules(conf.systemDrive))
		return absolu.substr(conf.systemDrive.size());
	return absolu;
}

} // namespace

namespace {

/*! Lettre du volume système examiné, sans les deux-points ("C").
 *  Dérivée de conf.systemDrive : Windows n'est pas toujours sur C:. */
std::wstring volumeSysteme() {
	return conf.systemDrive.substr(0, 1);
}

//! Répertoire d'extraction, sur la clé USB (dossier de sortie). Jamais l'hôte.
std::wstring dossierExtraction() {
	return string_to_wstring(conf._outputDir) + L"\\hives";
}

/*! Rapporteur de progression pour raw_hive : affiche en Kio, plus lisible que des
 *  octets pour des ruches de plusieurs dizaines de Mio. */
void rapporterProgression(const wchar_t* item, unsigned long long fait,
                          unsigned long long total) {
	printProgress(item ? item : L"", fait / 1024, total / 1024, L"Kio");
}

} // namespace

HRESULT ExtractHivesRaw() {
	conf.mountpoint = dossierExtraction();

	std::vector<std::pair<std::wstring, std::wstring>> items;
	std::vector<std::wstring> ruches;   // chemins locaux des ruches à remettre en état

	auto add = [&](const std::wstring& rel) {
		items.emplace_back(rel, conf.mountpoint + rel);
	};
	// Une ruche + ses deux journaux de transaction.
	auto addRuche = [&](const std::wstring& rel) {
		add(rel);
		add(rel + L".LOG1");
		add(rel + L".LOG2");
		ruches.push_back(conf.mountpoint + rel);
	};

	// Ruches système
	addRuche(L"\\Windows\\system32\\config\\SYSTEM");
	addRuche(L"\\Windows\\system32\\config\\SOFTWARE");
	/* SAM : base des comptes LOCAUX. Extraite pour que `users` se lise hors
	   ligne (dates de dernier logon, echecs de connexion, drapeaux de compte)
	   au lieu d'interroger LSASS par RPC. Cf. users.h. */
	addRuche(L"\\Windows\\system32\\config\\SAM");
	addRuche(L"\\Windows\\AppCompat\\Programs\\Amcache.hve");

	// Ruches par profil utilisateur (SID + chemin de profil dans conf.profiles)
	// cheminRelatifAuVolume() retire la lettre de lecteur en TETE uniquement :
	// replaceAll() retirait toutes ses occurrences dans le chemin.
	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		std::wstring rel = cheminRelatifAuVolume(std::get<1>(profile)); // "\Users\<nom>"
		addRuche(rel + L"\\ntuser.dat");
		addRuche(rel + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
	}

	// Créer l'arborescence de destination sur l'USB
	for (const std::pair<std::wstring, std::wstring>& it : items) {
		std::error_code ec;
		std::filesystem::create_directories(std::filesystem::path(it.second).parent_path(), ec);
	}

	std::vector<HRESULT> res;
	std::vector<std::wstring> md5Items;          // empreintes calculees pendant l'ecriture
	RawHiveSetProgress(&rapporterProgression);   // montre que l'extraction avance
	HRESULT hr = ExtractFilesRaw(volumeSysteme(), items, &res, &md5Items);
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	// Consigne ici, et non chez l'appelant : l'extraction doit preceder au journal
	// les patchs qu'elle declenche, sinon l'enchainement se lit a l'envers.
	auditRecord(L"Extraction brute des ruches (+ journaux .LOG1/.LOG2)",
	            std::wstring(L"\\\\.\\") + volumeSysteme() + L": -> " + conf.mountpoint,
	            hr, Footprint::VOLUME_BRUT);
	if (FAILED(hr)) {           // échec dur : volume inaccessible
		log(2, L"🔥Ouverture du volume impossible pour la lecture brute", hr);
		return hr;
	}

	// Journaliser les échecs par fichier sans interrompre (journaux parfois
	// absents, profils système sans UsrClass.dat, etc.)
	unsigned manquants = 0;
	for (size_t i = 0; i < items.size() && i < res.size(); ++i)
		if (FAILED(res[i])) { ++manquants; log(2, L"🔥Extraction brute échouée : " + items[i].first, res[i]); }

	/* Empreintes indexees par chemin de sortie : elles ont ete calculees pendant
	   l'ecriture, donc AVANT tout patch — exactement ce qu'il faut consigner. On
	   evite ainsi de relire chaque ruche depuis le support de collecte. */
	std::map<std::wstring, std::wstring> md5ParFichier;
	for (size_t i = 0; i < items.size() && i < md5Items.size(); ++i)
		if (!md5Items[i].empty()) md5ParFichier.emplace(items[i].second, md5Items[i]);

	// Remettre chaque ruche en état (dirty -> chargeable), avec traçabilité.
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Hives recovery :");
	log(0, L"*******************************************************************************************************************");
	unsigned patchees = 0, echecs = 0;
	/* Cette phase ne relit plus les ruches : les empreintes viennent du calcul
	   fait pendant l'écriture (voir QuickDigest5::Stream). Auparavant, chaque
	   ruche était relue depuis le support de collecte — environ 150 Mio lus une
	   seconde fois sur une clé USB, soit près de la moitié du temps d'extraction,
	   sans le moindre affichage. */
	size_t iRuche = 0;
	for (const std::wstring& r : ruches) {
		std::error_code ec;
		++iRuche;
		if (!std::filesystem::exists(r, ec)) continue;   // non extraite : déjà journalisé

		printProgress(L"Remise en etat " + std::filesystem::path(r).filename().wstring(),
		              iRuche, ruches.size(), L"ruche");

		/* Empreinte AVANT toute modification : la copie brute reste identifiable.
		   Reprise du calcul fait pendant l'extraction ; on ne relit le fichier
		   que si elle manque (cas theorique d'un item sans empreinte). */
		std::wstring md5avant;
		const auto trouve = md5ParFichier.find(r);
		if (trouve != md5ParFichier.end()) md5avant = trouve->second;
		else md5avant = QuickDigest5::fileToHash(wstring_to_string(r));

		HiveFixInfo info = MakeHiveLoadable(r);
		log(1, L"➕Hive");
		log(2, L"❇️" + HiveFixInfoToString(info));
		log(2, L"❇️MD5 copie brute (avant patch) : " + md5avant);

		// UNE entree par ruche : le patch est la seule ecriture que WAC produise
		// sur une preuve, et l'empreinte d'AVANT patch la rend verifiable a
		// l'octet. Les ruches deja propres sont consignees aussi — « non
		// modifiee » est une information, pas une absence d'information.
		// Note : le nom interne rendu par HiveFixInfoToString est tronque a ses
		// 31 derniers caracteres, comme le format regf le stocke.
		auditRecord(info.patched ? L"Remise en etat d'une ruche copiee (patch applique)"
		                         : L"Verification d'une ruche copiee (deja propre)",
		            r + L" | " + HiveFixInfoToString(info) + L" | MD5 avant patch : " + md5avant,
		            info.ok ? ERROR_SUCCESS : E_FAIL,
		            info.patched ? Footprint::RUCHE_PATCH : Footprint::RUCHE_COPIE);
		if (!info.ok) { ++echecs; log(2, L"🔥Ruche non exploitable : " + r + L" (" + info.error + L")"); }
		else if (info.patched) ++patchees;
	}
	printProgressEnd();
	log(2, L"❇️Ruches remises en état : " + std::to_wstring(patchees)
	     + L", échecs : " + std::to_wstring(echecs)
	     + L", fichiers manquants : " + std::to_wstring(manquants));

	// Une ruche illisible est bloquante en aval (OROpenHive) : on le signale.
	return (echecs == 0) ? hr : S_FALSE;
}

HRESULT ExtractFileArtefactsRaw() {
	if (conf.mountpoint.empty()) conf.mountpoint = dossierExtraction();

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Raw file artefacts :");
	log(0, L"*******************************************************************************************************************");

	// Répertoires à extraire, avec le filtre d'extension de leur collecteur.
	struct Cible { std::wstring chemin; std::vector<std::wstring> extensions; };
	std::vector<Cible> cibles;

	cibles.push_back({ L"\\Windows\\Prefetch", { L".pf" } });


	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		const std::wstring profil = cheminRelatifAuVolume(std::get<1>(profile));
		const std::wstring recent = profil + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
		cibles.push_back({ recent + L"\\AutomaticDestinations", { L".automaticDestinations-ms" } });
		cibles.push_back({ recent + L"\\CustomDestinations",    { L".customDestinations-ms" } });
		cibles.push_back({ recent,                              { L".lnk", L".url" } });
		cibles.push_back({ profil + L"\\AppData\\Roaming\\Microsoft\\Office\\Recent",
		                                                        { L".lnk", L".url" } });
	}

	HRESULT global = S_OK;
	size_t total = 0;
	RawHiveSetProgress(&rapporterProgression);

	/* Définitions de tâches planifiées : une arborescence, et les fichiers n'ont
	   PAS d'extension — d'où l'extraction récursive sans filtre. Elle remplace la
	   lecture via le Task Scheduler COM (doc §9.4bis), ce qui supprime à la fois
	   la trace d'exécution et la dépendance à COM. */
	{
		size_t tachesExtraites = 0;
		const std::wstring cheminTasks = L"\\Windows\\System32\\Tasks";
		const HRESULT hrTasks = ExtractDirectoryTreeRaw(
			volumeSysteme(), cheminTasks, conf.mountpoint + cheminTasks,
			{}, &tachesExtraites);
		auditRecord(L"Extraction brute des definitions de taches planifiees ("
		            + std::to_wstring(tachesExtraites) + L" fichier(s))",
		            std::wstring(L"\\\\.\\") + volumeSysteme() + L":" + cheminTasks,
		            hrTasks, Footprint::VOLUME_BRUT);
		log(2, L"❇️" + cheminTasks + L" : " + std::to_wstring(tachesExtraites) + L" fichier(s)");
		if (hrTasks == S_FALSE) global = S_FALSE;
	}

	for (const Cible& cible : cibles) {
		size_t extraits = 0;
		std::wstring diagnostic;
		const HRESULT hr = ExtractDirectoryRaw(volumeSysteme(), cible.chemin,
		                                       conf.mountpoint + cible.chemin,
		                                       cible.extensions, &extraits, &diagnostic);
		if (FAILED(hr)) {                       // volume inaccessible : inutile de continuer
			RawHiveSetProgress(nullptr);        // ne pas laisser le rapporteur installe
			printProgressEnd();
			log(2, L"🔥Extraction brute du répertoire impossible : " + cible.chemin, hr);
			return hr;
		}
		if (hr == S_FALSE) global = S_FALSE;    // certains fichiers n'ont pas pu être lus
		total += extraits;
		// Une entree par repertoire, avec le decompte : c'est ce qui permet a
		// l'analyse de distinguer « dossier vide » de « dossier non collecte ».
		// Le diagnostic accompagne le decompte : « 0 fichier » ne dit pas si le
		// repertoire manque, s'il est vide ou si le filtre a tout ecarte.
		auditRecord(L"Extraction brute d'un repertoire (" + std::to_wstring(extraits)
		            + L" fichier(s) — " + diagnostic + L")",
		            std::wstring(L"\\\\.\\") + volumeSysteme() + L":" + cible.chemin,
		            hr, Footprint::VOLUME_BRUT);
		log(1, L"➕Directory");
		log(2, L"❇️" + cible.chemin + L" : " + std::to_wstring(extraits)
		     + L" fichier(s) [" + diagnostic + L"]");
	}
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	log(2, L"❇️Fichiers extraits au total : " + std::to_wstring(total));
	return global;
}

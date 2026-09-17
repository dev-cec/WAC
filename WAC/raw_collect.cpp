/*  raw_collect.cpp — voir raw_collect.h. */
#include "raw_collect.h"
#include "consigne.h"
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

/*! Lettre du volume système examiné, sans les deux-points ("C").
 *
 *  Dérivée de conf.systemDrive : Windows n'est pas toujours sur C:.
 *
 *  À N'UTILISER que pour ce qui se trouve nécessairement sur le volume de
 *  Windows — les définitions de tâches planifiées, par exemple, vivent sous
 *  `\Windows\System32\Tasks`. Tout ce qui dépend d'un chemin relevé sur la
 *  machine (profils utilisateurs en tête) doit passer par `volumeDuChemin()` :
 *  supposer le volume système pour ces chemins était précisément le défaut qui
 *  faisait perdre en silence les profils situés sur un autre disque. */
std::wstring volumeSysteme() {
	return conf.systemDrive.substr(0, 1);
}

//! Répertoire d'extraction, sur la clé USB (dossier de sortie). Jamais l'hôte.
/*  L'extraction écrit dans la CONSIGNE, jamais dans le répertoire de travail :
 *  la copie brute doit exister avant qu'on en fasse quoi que ce soit, et ne plus
 *  être touchée ensuite (cf. consigne.h). `conf.mountpoint` désigne le travail,
 *  de sorte que tous les collecteurs lisent la copie de travail sans rien savoir
 *  de cette séparation. */
std::wstring cibleConsigne(const std::wstring& chemin) {
	return cheminSous(dossierConsigne(), chemin);
}

/*! Rapporteur de progression pour raw_hive : affiche en Kio, plus lisible que des
 *  octets pour des ruches de plusieurs dizaines de Mio. */
void rapporterProgression(const wchar_t* item, unsigned long long fait,
                          unsigned long long total) {
	printProgress(item ? item : L"", fait / 1024, total / 1024, L"Kio");
}

/*! Extraction brute d'un lot de ruches, puis remise en etat des copies de
 *  travail : rejeu des journaux de transaction, patch en recours.
 *
 *  PARTIE COMMUNE AUX DEUX PASSES. La liste des profils utilisateurs se lit
 *  desormais dans la ruche SOFTWARE extraite (cf. raw_collect.h et
 *  tools.h/loadProfileList) : les ruches par utilisateur ne peuvent donc plus
 *  etre extraites dans la meme passe que les ruches systeme, puisque leur
 *  emplacement n'est pas encore connu quand celle-ci commence.
 *
 *  @param cheminsRuches chemins des ruches, absolus (avec lettre de volume) ou
 *                       relatifs au volume systeme ; les journaux .LOG1 et
 *                       .LOG2 sont ajoutes d'office.
 *  @param etiquette     ce que cette passe extrait, pour le journal d'audit.
 *  @param verifierLieu  vrai pour la PREMIERE passe seulement : l'emplacement de
 *                       collecte se verifie avant la premiere ecriture, et une
 *                       seule fois — au second appel le repertoire de travail
 *                       est legitimement peuple par la premiere passe, et
 *                       `ConsigneVerifierEmplacement` le refuserait.
 */
HRESULT extraireLotDeRuches(const std::vector<std::wstring>& cheminsRuches,
                            const std::wstring& etiquette,
                            bool verifierLieu) {
	conf.mountpoint = dossierTravail();

	/*  EMPLACEMENT DE COLLECTE, verifie AVANT la premiere ecriture. Deux refus,
	    tous deux preferables a une collecte qui s'abime en cours : un repertoire
	    de travail deja peuple ferait analyser une collecte anterieure, et un
	    support trop petit donnerait des copies tronquees. L'estimation est
	    volontairement grossiere — les ruches d'une installation ordinaire, plus
	    les journaux d'evenements quand ils sont demandes ; elle n'a pas a etre
	    juste, seulement a ecarter un support manifestement insuffisant. */
	if (verifierLieu) {
		const unsigned long long besoin = conf._events
		                                ? 400ULL * 1024 * 1024   // ruches + journaux
		                                : 250ULL * 1024 * 1024;  // ruches seules
		const HRESULT hrLieu = ConsigneVerifierEmplacement(besoin);
		auditRecord(L"Verification de l'emplacement de collecte ("
		            + std::to_wstring(ConsigneEspaceLibre() / 1024 / 1024)
		            + L" Mio libres)",
		            string_to_wstring(conf._outputDir),
		            hrLieu, Footprint::ECRITURE_USB);
		if (FAILED(hrLieu)) return hrLieu;
	}

	/* EXTRACTION GROUPEE PAR VOLUME.
	   Un seul volume etait suppose, celui de Windows : un profil situe sur un
	   autre disque (« D:\Users\jean », cas d'un poste a SSD systeme + disque de
	   donnees) etait cherche dans la table de fichiers de C:, donc jamais
	   extrait — et tous les artefacts de cet utilisateur sortaient vides.
	   Les fichiers sont desormais regroupes par lettre de volume, et
	   ExtractFilesRaw appele une fois par volume reellement concerne. */
	std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>> parVolume;
	std::vector<std::wstring> ruches;   // chemins locaux des ruches à remettre en état

	// `chemin` est absolu (avec lettre) ou relatif au volume systeme.
	auto add = [&](const std::wstring& chemin) {
		parVolume[volumeDuChemin(chemin)].emplace_back(cheminRelatifAuVolume(chemin),
		                                               cibleConsigne(chemin));
	};
	// Une ruche + ses deux journaux de transaction.
	auto addRuche = [&](const std::wstring& chemin) {
		add(chemin);
		add(chemin + L".LOG1");
		add(chemin + L".LOG2");
		// Le rejeu et le patch portent sur la copie de TRAVAIL, jamais sur la
		// consigne : c'est toute la raison de la separation.
		ruches.push_back(cheminExtrait(chemin));
	};

	for (const std::wstring& ruche : cheminsRuches) addRuche(ruche);

	// Créer l'arborescence de destination sous la consigne
	for (const auto& groupe : parVolume)
		for (const std::pair<std::wstring, std::wstring>& it : groupe.second) {
			std::error_code ec;
			std::filesystem::create_directories(std::filesystem::path(it.second).parent_path(), ec);
		}

	/* Une passe par volume. Un volume inaccessible ne doit pas emporter les
	   autres : on consigne son echec et on continue, comme pour une ruche
	   manquante. Le premier echec dur est toutefois memorise pour le retour,
	   afin que l'appelant sache que la collecte est incomplete. */
	std::map<std::wstring, std::wstring> md5ParFichier;   // chemin de travail -> MD5
	unsigned manquants = 0;
	HRESULT hr = ERROR_SUCCESS;
	HRESULT premierEchecDur = ERROR_SUCCESS;
	RawHiveSetProgress(&rapporterProgression);   // montre que l'extraction avance
	for (const auto& groupe : parVolume) {
		const std::wstring& volume = groupe.first;
		const auto& items = groupe.second;
		std::vector<HRESULT> res;
		std::vector<RawHiveExtrait> releve;      // empreintes calculees a l'ecriture
		const HRESULT hrVolume = ExtractFilesRaw(volume, items, &res, &releve);
		ConsigneAjouter(releve, L"Lecture brute NTFS (\\\\.\\" + volume
		                        + L": — $MFT, index de repertoires, attribut $DATA) ; "
		                        L"aucune ouverture de fichier par le systeme");
		// Consigne ici, et non chez l'appelant : l'extraction doit preceder au
		// journal les patchs qu'elle declenche, sinon l'enchainement se lit a
		// l'envers.
		auditRecord(etiquette,
		            std::wstring(L"\\\\.\\") + volume + L": -> " + conf.mountpoint,
		            hrVolume, Footprint::VOLUME_BRUT);
		if (FAILED(hrVolume)) {                  // volume inaccessible
			log(2, L"🔥Volume " + volume + L": inaccessible pour la lecture brute", hrVolume);
			if (premierEchecDur == ERROR_SUCCESS) premierEchecDur = hrVolume;
			continue;
		}
		if (hrVolume == S_FALSE) hr = S_FALSE;

		// Journaliser les échecs par fichier sans interrompre (journaux parfois
		// absents, profils système sans UsrClass.dat, etc.)
		for (size_t i = 0; i < items.size() && i < res.size(); ++i)
			if (FAILED(res[i])) {
				++manquants;
				log(2, L"🔥Extraction brute échouée : " + volume + L":" + items[i].first, res[i]);
			}
		/* Empreintes indexees par chemin de TRAVAIL : calculees pendant
		   l'ecriture de la consigne, donc avant toute modification — exactement
		   ce qu'il faut consigner. La cle est le chemin de travail car c'est
		   sur celui-la que porteront le rejeu et le patch. */
		for (const RawHiveExtrait& e : releve)
			if (!e.empreintes.md5.empty()) {
				const std::filesystem::path relatif = std::filesystem::relative(
					std::filesystem::path(e.cheminSortie), std::filesystem::path(dossierConsigne()));
				md5ParFichier.emplace((std::filesystem::path(dossierTravail()) / relatif).wstring(),
				                      e.empreintes.md5);
			}
	}
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	log(2, L"❇️Volumes lus : " + std::to_wstring(parVolume.size()));
	/* Aucun volume lisible : rien ne suivra, autant le dire tout de suite. */
	if (md5ParFichier.empty() && premierEchecDur != ERROR_SUCCESS) return premierEchecDur;

	/*  CONSIGNE -> TRAVAIL. Les copies brutes sont en place et identifiees : on
	 *  en fait la copie de travail, verifiee par empreinte, et c'est sur elle
	 *  seule que porte tout ce qui suit. */
	{
		size_t copies = 0;
		unsigned long long octets = 0;
		const HRESULT hrCopie = ConsigneVersTravail(&copies, &octets);
		auditRecord(L"Copie de la consigne vers le repertoire de travail ("
		            + std::to_wstring(copies) + L" fichier(s), "
		            + std::to_wstring(octets / 1024 / 1024) + L" Mio)",
		            dossierConsigne() + L" -> " + dossierTravail(),
		            hrCopie, Footprint::ECRITURE_USB);
		if (FAILED(hrCopie)) return hrCopie;     // sans travail, rien ne suit
		if (hrCopie == S_FALSE) hr = S_FALSE;
	}

	// Remettre chaque ruche en état (dirty -> chargeable), avec traçabilité.
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Hives recovery :");
	log(0, L"*******************************************************************************************************************");
	unsigned patchees = 0, echecs = 0, rejouees = 0;
	unsigned long long pagesRejouees = 0, octetsRejoues = 0;
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

		log(1, L"➕Hive");
		log(2, L"❇️MD5 copie brute (avant toute ecriture) : " + md5avant);

		/* REJEU D'ABORD. Les journaux de transaction contiennent les pages
		   modifiees depuis la derniere ecriture complete de la ruche : les
		   appliquer donne l'etat reel de la machine, et rend la ruche propre par
		   construction — donc sans patch. Le contenu d'origine de chaque page
		   remplacee part dans un journal d'annulation, de sorte que la copie
		   brute reste reconstructible a l'octet (verifie sur trois ruches
		   reelles). */
		const HiveReplayInfo rejeu = ReplayHiveLogs(r, md5avant);
		log(2, L"❇️" + HiveReplayInfoToString(rejeu));
		if (rejeu.applique) {
			++rejouees;
			pagesRejouees  += rejeu.pages;
			octetsRejoues  += rejeu.octets;
			auditRecord(L"Rejeu des journaux de transaction d'une ruche copiee ("
			            + std::to_wstring(rejeu.entreesRetenues) + L" entree(s), "
			            + std::to_wstring(rejeu.pages) + L" page(s))",
			            r + L" | " + HiveReplayInfoToString(rejeu)
			            + L" | MD5 avant rejeu : " + md5avant
			            + L" | annulation : " + rejeu.journalAnnulation,
			            ERROR_SUCCESS, Footprint::RUCHE_REJEU);
		}
		else if (!rejeu.ok) {
			// Le rejeu n'a rien ecrit : on le consigne et on retombe sur le patch.
			log(2, L"🔥Rejeu impossible : " + r + L" (" + rejeu.error + L")");
			auditRecord(L"Rejeu des journaux de transaction d'une ruche copiee (non applique)",
			            r + L" | " + HiveReplayInfoToString(rejeu),
			            E_FAIL, Footprint::RUCHE_COPIE);
		}

		/* PATCH EN RECOURS. Apres un rejeu abouti la ruche est propre et
		   MakeHiveLoadable ne fait rien ; il ne reste utile que pour les ruches
		   sans journal exploitable. */
		HiveFixInfo info = MakeHiveLoadable(r);
		log(2, L"❇️" + HiveFixInfoToString(info));

		// UNE entree par ruche : toute ecriture de WAC sur une preuve est
		// consignee, et l'empreinte d'AVANT la rend verifiable a l'octet. Les
		// ruches deja propres le sont aussi — « non modifiee » est une
		// information, pas une absence d'information.
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
	log(2, L"❇️Ruches rejouées : " + std::to_wstring(rejouees)
	     + L" (" + std::to_wstring(pagesRejouees) + L" pages, "
	     + std::to_wstring(octetsRejoues / 1024) + L" Kio appliqués)");
	log(2, L"❇️Ruches remises en état par patch : " + std::to_wstring(patchees)
	     + L", échecs : " + std::to_wstring(echecs)
	     + L", fichiers manquants : " + std::to_wstring(manquants));

	// Une ruche illisible est bloquante en aval (OROpenHive) : on le signale.
	return (echecs == 0) ? hr : S_FALSE;
}

} // namespace

HRESULT ExtractSystemHivesRaw() {
	/* Ruches de la machine. Aucune ne depend d'un chemin releve sur le systeme :
	   c'est precisement ce qui permet de les extraire en premier, avant de savoir
	   quoi que ce soit du contenu du registre. */
	std::vector<std::wstring> ruches = {
		L"\\Windows\\system32\\config\\SYSTEM",
		L"\\Windows\\system32\\config\\SOFTWARE",
		/* SAM : base des comptes LOCAUX. Extraite pour que `users` se lise hors
		   ligne (dates de dernier logon, echecs de connexion, drapeaux de compte)
		   au lieu d'interroger LSASS par RPC. Cf. users.h. */
		L"\\Windows\\system32\\config\\SAM",
		L"\\Windows\\AppCompat\\Programs\\Amcache.hve",
	};
	return extraireLotDeRuches(
		ruches,
		L"Extraction brute des ruches systeme (+ journaux .LOG1/.LOG2)",
		true);
}

HRESULT ExtractUserHivesRaw() {
	/* `conf.profiles` est renseigne par loadProfileList(), qui lit la ruche
	   SOFTWARE extraite par la passe precedente. Une liste vide n'est donc pas
	   une machine sans utilisateur, mais un releve de profils qui a echoue :
	   l'annoncer vaut mieux que de rendre un succes sur une extraction vide. */
	if (conf.profiles.empty()) {
		log(2, L"🔥Aucun profil releve : aucune ruche par utilisateur a extraire");
		auditRecord(L"Extraction brute des ruches par utilisateur (aucun profil releve)",
		            conf.mountpoint, ERROR_EMPTY, Footprint::VOLUME_BRUT);
		return S_FALSE;
	}

	/* Le chemin est passe ABSOLU, avec sa lettre : c'est elle qui determine sur
	   quel volume lire. Un profil sur un second disque (« D:\Users\jean ») etait
	   cherche dans la table de fichiers de C:, donc jamais extrait. */
	std::vector<std::wstring> ruches;
	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		const std::wstring profil = std::get<1>(profile);   // ex. "D:\Users\jean"
		ruches.push_back(profil + L"\\ntuser.dat");
		ruches.push_back(profil + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
	}
	return extraireLotDeRuches(
		ruches,
		L"Extraction brute des ruches par utilisateur (+ journaux .LOG1/.LOG2)",
		false);
}

HRESULT ExtractFileArtefactsRaw() {
	if (conf.mountpoint.empty()) conf.mountpoint = dossierTravail();

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Raw file artefacts :");
	log(0, L"*******************************************************************************************************************");

	/* Répertoires à extraire, avec le filtre d'extension de leur collecteur.
	   Chaque cible porte SON volume : les dossiers d'un profil situe sur un
	   autre disque que Windows etaient lus sur le volume systeme, donc jamais
	   trouves. */
	struct Cible {
		std::wstring volume;       //!< lettre du volume, sans deux-points
		std::wstring chemin;       //!< chemin relatif a la racine de ce volume
		std::wstring sortie;       //!< destination sur le support de collecte
		std::vector<std::wstring> extensions;
	};
	std::vector<Cible> cibles;
	// `absolu` porte sa lettre, ou est relatif au volume systeme.
	auto addCible = [&](const std::wstring& absolu,
	                    const std::vector<std::wstring>& ext) {
		cibles.push_back({ volumeDuChemin(absolu), cheminRelatifAuVolume(absolu),
		                   cibleConsigne(absolu), ext });
	};

	addCible(L"\\Windows\\Prefetch", { L".pf" });

	/* Journaux d'événements : extraits SEULEMENT sur demande (--events). Ce sont
	   les plus gros artefacts du système — plus d'une centaine de mégaoctets sur
	   une installation ordinaire, et davantage sur un serveur. Les extraire
	   systématiquement allongerait chaque collecte et remplirait le support pour
	   des données que l'opérateur n'a pas demandées. Leur lecture hors ligne
	   remplace l'API EventLog (cf. events.h). */
	if (conf._events) addCible(L"\\Windows\\System32\\winevt\\Logs", { L".evtx" });

	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		const std::wstring profil = std::get<1>(profile);   // absolu, avec sa lettre
		const std::wstring recent = profil + L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent";
		addCible(recent + L"\\AutomaticDestinations", { L".automaticDestinations-ms" });
		addCible(recent + L"\\CustomDestinations",    { L".customDestinations-ms" });
		addCible(recent,                              { L".lnk", L".url" });
		addCible(profil + L"\\AppData\\Roaming\\Microsoft\\Office\\Recent",
		                                              { L".lnk", L".url" });
	}

	HRESULT global = S_OK;
	size_t total = 0;
	RawHiveSetProgress(&rapporterProgression);

	/* Définitions de tâches planifiées : une arborescence, et les fichiers n'ont
	   PAS d'extension — d'où l'extraction récursive sans filtre. Elle remplace la
	   lecture via le Task Scheduler COM, ce qui supprime à la fois
	   la trace d'exécution et la dépendance à COM. */
	{
		size_t tachesExtraites = 0;
		const std::wstring cheminTasks = L"\\Windows\\System32\\Tasks";
		std::vector<RawHiveExtrait> releve;
		const HRESULT hrTasks = ExtractDirectoryTreeRaw(
			volumeSysteme(), cheminTasks, cibleConsigne(cheminTasks),
			{}, &tachesExtraites, 8, &releve);
		ConsigneAjouter(releve, L"Lecture brute NTFS recursive (\\\\.\\"
		                        + volumeSysteme() + L": — $MFT, index de repertoires) ; "
		                        L"aucune ouverture de fichier par le systeme");
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
		std::vector<RawHiveExtrait> releve;
		const HRESULT hr = ExtractDirectoryRaw(cible.volume, cible.chemin,
		                                       cible.sortie,
		                                       cible.extensions, &extraits, &diagnostic,
		                                       &releve);
		ConsigneAjouter(releve, L"Lecture brute NTFS (\\\\.\\" + cible.volume
		                        + L": — $MFT, index de repertoires, attribut $DATA) ; "
		                        L"aucune ouverture de fichier par le systeme");
		if (FAILED(hr)) {
			/* Volume inaccessible. On NE s'arrete plus : avec plusieurs volumes,
			   un disque illisible emportait toutes les cibles suivantes, y
			   compris celles du volume systeme. */
			log(2, L"🔥Extraction brute impossible : " + cible.volume + L":"
			     + cible.chemin, hr);
			global = S_FALSE;
			continue;
		}
		if (hr == S_FALSE) global = S_FALSE;    // certains fichiers n'ont pas pu être lus
		total += extraits;
		// Une entree par repertoire, avec le decompte : c'est ce qui permet a
		// l'analyse de distinguer « dossier vide » de « dossier non collecte ».
		// Le diagnostic accompagne le decompte : « 0 fichier » ne dit pas si le
		// repertoire manque, s'il est vide ou si le filtre a tout ecarte.
		auditRecord(L"Extraction brute d'un repertoire (" + std::to_wstring(extraits)
		            + L" fichier(s) — " + diagnostic + L")",
		            std::wstring(L"\\\\.\\") + cible.volume + L":" + cible.chemin,
		            hr, Footprint::VOLUME_BRUT);
		log(1, L"➕Directory");
		log(2, L"❇️" + cible.chemin + L" : " + std::to_wstring(extraits)
		     + L" fichier(s) [" + diagnostic + L"]");
	}
	RawHiveSetProgress(nullptr);
	printProgressEnd();
	log(2, L"❇️Fichiers extraits au total : " + std::to_wstring(total));

	/*  CONSIGNE -> TRAVAIL, pour les artefacts sur fichiers. Les ruches ont deja
	 *  ete recopiees et rejouees : ConsigneVersTravail ne les ecrase pas (cf.
	 *  consigne.cpp), il complete le repertoire de travail. La separation vaut
	 *  aussi pour ces fichiers-la, que WAC ne modifie pas : ne dedoubler que ce
	 *  qu'on modifie ferait dependre la procedure de ce que l'outil croit faire,
	 *  alors que c'est precisement ce qu'il faut pouvoir verifier du dehors. */
	{
		size_t copies = 0;
		unsigned long long octets = 0;
		const HRESULT hrCopie = ConsigneVersTravail(&copies, &octets);
		auditRecord(L"Copie de la consigne vers le repertoire de travail ("
		            + std::to_wstring(copies) + L" fichier(s), "
		            + std::to_wstring(octets / 1024 / 1024) + L" Mio)",
		            dossierConsigne() + L" -> " + dossierTravail(),
		            hrCopie, Footprint::ECRITURE_USB);
		if (FAILED(hrCopie)) return hrCopie;
		if (hrCopie == S_FALSE) global = S_FALSE;
	}
	return global;
}

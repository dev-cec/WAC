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

/*! Letter of the examined system volume, without the colon ("C").
 *
 *  Derived from conf.systemDrive: Windows is not always on C:.
 *
 *  To be used ONLY for what necessarily lives on the Windows volume —
 *  scheduled task definitions, for instance, live under
 *  `\Windows\System32\Tasks`. Anything that depends on a path found on the
 *  machine (user profiles first) must go through `volumeDuChemin()`: assuming
 *  the system volume for those paths was precisely the defect that silently
 *  lost profiles located on another disk. */
std::wstring volumeSysteme() {
	return conf.systemDrive.substr(0, 1);
}

//! Extraction directory, on the USB stick (output folder). Never the host.
/*  Extraction writes into the EXHIBIT STORE, never into the working
 *  directory: the raw copy must exist before anything is done with it, and
 *  must not be touched afterwards (see consigne.h). `conf.mountpoint` points to
 *  the working directory, so every collector reads the working copy without
 *  knowing anything about this split. */
std::wstring cibleConsigne(const std::wstring& chemin) {
	return cheminSous(dossierConsigne(), chemin);
}

/*! Progress reporter for raw_hive: displays KiB, more readable than bytes for
 *  hives of several tens of MiB. */
void rapporterProgression(const wchar_t* item, unsigned long long fait,
                          unsigned long long total) {
	printProgress(item ? item : L"", fait / 1024, total / 1024, L"Kio");
}

/*! Raw extraction of a batch of hives, then repair of the working copies:
 *  transaction log replay, patch as a fallback.
 *
 *  SHARED BY BOTH PASSES. The user profile list is now read in the extracted
 *  SOFTWARE hive (see raw_collect.h and tools.h/loadProfileList): the per-user
 *  hives can therefore no longer be extracted in the same pass as the system
 *  hives, since their location is not yet known when that one starts.
 *
 *  @param cheminsRuches hive paths, absolute (with volume letter) or relative
 *                       to the system volume; the .LOG1 and .LOG2 logs are
 *                       added automatically.
 *  @param etiquette     what this pass extracts, for the audit log.
 */
HRESULT extraireLotDeRuches(const std::vector<std::wstring>& cheminsRuches,
                            const std::wstring& etiquette) {
	conf.mountpoint = dossierTravail();

	// The collection location is checked by main, before the very first
	// write — which can be collecting a process's binary.

	/* EXTRACTION GROUPED BY VOLUME.
	   A single volume used to be assumed, the Windows one: a profile on another
	   disk ("D:\Users\jean", a machine with a system SSD + a data disk) was
	   looked for in C:'s file table, so never extracted — and every artefact of
	   that user came out empty.
	   Files are now grouped by volume letter, and ExtractFilesRaw called once
	   per volume actually involved. */
	std::map<std::wstring, std::vector<std::pair<std::wstring, std::wstring>>> parVolume;
	std::vector<std::wstring> ruches;   // local paths of the hives to repair

	// `chemin` is absolute (with letter) or relative to the system volume.
	auto add = [&](const std::wstring& chemin) {
		parVolume[volumeDuChemin(chemin)].emplace_back(cheminRelatifAuVolume(chemin),
		                                               cibleConsigne(chemin));
	};
	// A hive + its two transaction logs.
	auto addRuche = [&](const std::wstring& chemin) {
		add(chemin);
		add(chemin + L".LOG1");
		add(chemin + L".LOG2");
		// The replay and the patch apply to the WORKING copy, never to the
		// exhibit store: that is the whole point of the split.
		ruches.push_back(cheminExtrait(chemin));
	};

	for (const std::wstring& ruche : cheminsRuches) addRuche(ruche);

	// Create the destination tree under the exhibit store
	for (const auto& groupe : parVolume)
		for (const std::pair<std::wstring, std::wstring>& it : groupe.second) {
			std::error_code ec;
			std::filesystem::create_directories(std::filesystem::path(it.second).parent_path(), ec);
		}

	/* One pass per volume. An inaccessible volume must not take the others
	   down: its failure is recorded and we go on, as for a missing hive. The
	   first hard failure is nonetheless kept for the return value, so that the
	   caller knows the collection is incomplete. */
	std::map<std::wstring, std::wstring> md5ParFichier;   // working path -> MD5
	unsigned manquants = 0;
	HRESULT hr = ERROR_SUCCESS;
	HRESULT premierEchecDur = ERROR_SUCCESS;
	RawHiveSetProgress(&rapporterProgression);   // shows that extraction is progressing
	for (const auto& groupe : parVolume) {
		const std::wstring& volume = groupe.first;
		const auto& items = groupe.second;
		std::vector<HRESULT> res;
		std::vector<RawHiveExtrait> releve;      // fingerprints computed while writing
		const HRESULT hrVolume = ExtractFilesRaw(volume, items, &res, &releve);
		ConsigneAjouter(releve, L"Lecture brute NTFS (\\\\.\\" + volume
		                        + L": — $MFT, index de repertoires, attribut $DATA) ; "
		                        L"aucune ouverture de fichier par le systeme");
		// Recorded here, not by the caller: the extraction must come before the
		// patches it triggers in the log, otherwise the sequence reads
		// backwards.
		auditRecord(etiquette,
		            std::wstring(L"\\\\.\\") + volume + L": -> " + conf.mountpoint,
		            hrVolume, Footprint::VOLUME_BRUT);
		if (FAILED(hrVolume)) {                  // volume inaccessible
			log(2, L"🔥Volume " + volume + L": inaccessible pour la lecture brute", hrVolume);
			if (premierEchecDur == ERROR_SUCCESS) premierEchecDur = hrVolume;
			continue;
		}
		if (hrVolume == S_FALSE) hr = S_FALSE;

		// Log per-file failures without stopping (logs sometimes missing,
		// system profiles without UsrClass.dat, etc.)
		for (size_t i = 0; i < items.size() && i < res.size(); ++i)
			if (FAILED(res[i])) {
				++manquants;
				log(2, L"🔥Extraction brute échouée : " + volume + L":" + items[i].first, res[i]);
			}
		/* Fingerprints indexed by WORKING path: computed while the exhibit store
		   was being written, hence before any modification — exactly what must be
		   recorded. The key is the working path because that is the one the replay
		   and the patch will apply to. */
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
	/* No readable volume: nothing will follow, better say so at once. */
	if (md5ParFichier.empty() && premierEchecDur != ERROR_SUCCESS) return premierEchecDur;

	/*  EXHIBIT STORE -> WORKING COPY. The raw copies are in place and
	 *  identified: their working copy is made, verified by fingerprint, and
	 *  everything that follows applies to it alone. */
	{
		size_t copies = 0;
		unsigned long long octets = 0;
		const HRESULT hrCopie = ConsigneVersTravail(&copies, &octets);
		auditRecord(L"Copie de la consigne vers le repertoire de travail ("
		            + std::to_wstring(copies) + L" fichier(s), "
		            + std::to_wstring(octets / 1024 / 1024) + L" Mio)",
		            dossierConsigne() + L" -> " + dossierTravail(),
		            hrCopie, Footprint::ECRITURE_USB);
		if (FAILED(hrCopie)) return hrCopie;     // without a working copy, nothing follows
		if (hrCopie == S_FALSE) hr = S_FALSE;
	}

	// Repair each hive (dirty -> loadable), with traceability.
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Hives recovery :");
	log(0, L"*******************************************************************************************************************");
	unsigned patchees = 0, echecs = 0, rejouees = 0;
	unsigned long long pagesRejouees = 0, octetsRejoues = 0;
	/* This phase no longer re-reads the hives: the fingerprints come from the
	   computation made while writing (see QuickDigest5::Stream). Previously,
	   each hive was read back from the collection medium — about 150 MiB read a
	   second time from a USB stick, almost half the extraction time, without
	   any display. */
	size_t iRuche = 0;
	for (const std::wstring& r : ruches) {
		std::error_code ec;
		++iRuche;
		if (!std::filesystem::exists(r, ec)) continue;   // not extracted: already logged

		printProgress(L"Remise en etat " + std::filesystem::path(r).filename().wstring(),
		              iRuche, ruches.size(), L"ruche");

		/* Fingerprint BEFORE any modification: the raw copy stays identifiable.
		   Taken from the computation made during extraction; the file is only
		   re-read if it is missing (theoretical case of an item without one). */
		std::wstring md5avant;
		const auto trouve = md5ParFichier.find(r);
		if (trouve != md5ParFichier.end()) md5avant = trouve->second;
		else md5avant = QuickDigest5::fileToHash(wstring_to_string(r));

		log(1, L"➕Hive");
		log(2, L"❇️MD5 copie brute (avant toute ecriture) : " + md5avant);

		/* REPLAY FIRST. The transaction logs hold the pages changed since the
		   hive's last full write: applying them gives the machine's real state,
		   and makes the hive clean by construction — hence no patch. The original
		   content of each replaced page goes into an undo journal, so that the
		   raw copy stays rebuildable to the byte (verified on three real
		   hives). */
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
			// The replay wrote nothing: record it and fall back on the patch.
			log(2, L"🔥Rejeu impossible : " + r + L" (" + rejeu.error + L")");
			auditRecord(L"Rejeu des journaux de transaction d'une ruche copiee (non applique)",
			            r + L" | " + HiveReplayInfoToString(rejeu),
			            E_FAIL, Footprint::RUCHE_COPIE);
		}

		/* PATCH AS A FALLBACK. After a successful replay the hive is clean and
		   MakeHiveLoadable does nothing; it only remains useful for hives
		   without a usable log. */
		HiveFixInfo info = MakeHiveLoadable(r);
		log(2, L"❇️" + HiveFixInfoToString(info));

		// ONE entry per hive: every write WAC makes on evidence is recorded,
		// and the BEFORE fingerprint makes it verifiable to the byte. Hives that
		// are already clean are recorded too — "not modified" is information,
		// not a lack of information.
		// Note: the internal name returned by HiveFixInfoToString is truncated to
		// its last 31 characters, as the regf format stores it.
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

	// An unreadable hive blocks what follows (OROpenHive): report it.
	return (echecs == 0) ? hr : S_FALSE;
}

} // namespace

HRESULT ExtractSystemHivesRaw() {
	/* The machine's hives. None depends on a path found on the system: that
	   is precisely what allows extracting them first, before knowing anything
	   of the registry's content. */
	std::vector<std::wstring> ruches = {
		L"\\Windows\\system32\\config\\SYSTEM",
		L"\\Windows\\system32\\config\\SOFTWARE",
		/* SAM: database of LOCAL accounts. Extracted so that `users` is read
		   offline (last logon dates, logon failures, account flags) instead of
		   querying LSASS over RPC. See users.h. */
		L"\\Windows\\system32\\config\\SAM",
		L"\\Windows\\AppCompat\\Programs\\Amcache.hve",
	};
	return extraireLotDeRuches(
		ruches,
		L"Extraction brute des ruches systeme (+ journaux .LOG1/.LOG2)");
}

HRESULT ExtractUserHivesRaw() {
	/* `conf.profiles` is filled by loadProfileList(), which reads the SOFTWARE
	   hive extracted by the previous pass. An empty list is therefore not a
	   machine without users but a failed profile listing: saying so is better
	   than returning success on an empty extraction. */
	if (conf.profiles.empty()) {
		log(2, L"🔥Aucun profil releve : aucune ruche par utilisateur a extraire");
		auditRecord(L"Extraction brute des ruches par utilisateur (aucun profil releve)",
		            conf.mountpoint, ERROR_EMPTY, Footprint::VOLUME_BRUT);
		return S_FALSE;
	}

	/* The path is passed ABSOLUTE, with its letter: that is what determines
	   which volume to read. A profile on a second disk ("D:\Users\jean") was
	   looked for in C:'s file table, so never extracted. */
	std::vector<std::wstring> ruches;
	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		const std::wstring profil = std::get<1>(profile);   // ex. "D:\Users\jean"
		ruches.push_back(profil + L"\\ntuser.dat");
		ruches.push_back(profil + L"\\AppData\\Local\\Microsoft\\Windows\\usrClass.dat");
	}
	return extraireLotDeRuches(
		ruches,
		L"Extraction brute des ruches par utilisateur (+ journaux .LOG1/.LOG2)");
}

HRESULT ExtractFileArtefactsRaw() {
	if (conf.mountpoint.empty()) conf.mountpoint = dossierTravail();

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Raw file artefacts :");
	log(0, L"*******************************************************************************************************************");

	/* Directories to extract, with their collector's extension filter.
	   Each target carries ITS volume: the folders of a profile on a disk other
	   than Windows' were read on the system volume, so never found. */
	struct Cible {
		std::wstring volume;       //!< volume letter, without the colon
		std::wstring chemin;       //!< path relative to that volume's root
		std::wstring sortie;       //!< destination on the collection medium
		std::vector<std::wstring> extensions;
	};
	std::vector<Cible> cibles;
	// `absolu` carries its letter, or is relative to the system volume.
	auto addCible = [&](const std::wstring& absolu,
	                    const std::vector<std::wstring>& ext) {
		cibles.push_back({ volumeDuChemin(absolu), cheminRelatifAuVolume(absolu),
		                   cibleConsigne(absolu), ext });
	};

	addCible(L"\\Windows\\Prefetch", { L".pf" });

	/* Event logs: extracted ONLY on request (--events). They are the system's
	   largest artefacts — over a hundred megabytes on an ordinary installation,
	   more on a server. Extracting them systematically would lengthen every
	   collection and fill the medium with data the operator did not ask for.
	   Reading them offline replaces the EventLog API (see events.h). */
	if (conf._events) addCible(L"\\Windows\\System32\\winevt\\Logs", { L".evtx" });

	for (const std::tuple<std::wstring, std::wstring>& profile : conf.profiles) {
		const std::wstring profil = std::get<1>(profile);   // absolute, with its letter
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

	/* Scheduled task definitions: a tree, and the files have NO extension —
	   hence the recursive extraction without a filter. It replaces reading
	   through the Task Scheduler COM interface, which removes both the
	   execution trace and the dependency on COM. */
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
			/* Inaccessible volume. We NO LONGER stop: with several volumes, an
			   unreadable disk took all the following targets down with it, the
			   system volume's included. */
			log(2, L"🔥Extraction brute impossible : " + cible.volume + L":"
			     + cible.chemin, hr);
			global = S_FALSE;
			continue;
		}
		if (hr == S_FALSE) global = S_FALSE;    // some files could not be read
		total += extraits;
		// One entry per directory, with the count: that is what lets the
		// analysis tell "empty folder" from "folder not collected".
		// The diagnosis goes with the count: "0 files" does not say whether the
		// directory is missing, empty, or whether the filter discarded everything.
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

	/*  EXHIBIT STORE -> WORKING COPY, for the file-based artefacts. The hives
	 *  have already been copied and replayed: ConsigneVersTravail does not
	 *  overwrite them (see consigne.cpp), it completes the working directory.
	 *  The split applies to these files too, which WAC does not modify:
	 *  duplicating only what one modifies would make the procedure depend on
	 *  what the tool believes it does, which is precisely what must be
	 *  checkable from outside. */
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

#include "prefetchs.h"
#include <map>

MFTInformation::MFTInformation(LPBYTE data) {
	sequenceNumber = *reinterpret_cast<unsigned int*>(data + 6);
	unsigned int entryIndex1 = *reinterpret_cast<unsigned int*>(data);
	unsigned short int entryIndex2 = *reinterpret_cast<unsigned short int*>(data + 4);
	if (entryIndex2 == 0)
	{
		entryIndex = entryIndex1;
	}
	else
	{
		entryIndex2 *= (unsigned short)16777216; //2^24
		entryIndex = entryIndex1 + entryIndex2;
	}
	if (sequenceNumber == 0)
	{
		sequenceNumber = NULL;
	}
}

Json MFTInformation::toJson() {
	log(3, L"🔈MFTInformation toJson");
	Json o = Json::obj();
	o.add(L"EntryIndex",     Json::num((long long)entryIndex));
	o.add(L"SequenceNumber", Json::num((long long)sequenceNumber));
	return o;
}

void MFTInformation::clear() {
	log(3, L"🔈MFTInformation clear");
}

Json DirStrings::toJson() {
	Json o = Json::obj();
	o.add(L"Dir",      Json::str(dir));
	o.add(L"FullPath", Json::str(fullPath));
	return o;
}

Json Filename::toJson() {
	Json o = Json::obj();
	o.add(L"Filename", Json::str(filename));
	o.add(L"FullPath", Json::str(fullPath));
	addFingerprints(o, fingerprint);
	// Emise seulement si relevee : un couple de zeros se lirait comme une
	// reference valide vers l'enregistrement 0 de la $MFT, qui est la $MFT
	// elle-meme.
	if (referenceKnown) o.add(L"MftReference", reference.toJson());
	return o;
}

VolumeInfo::VolumeInfo(LPBYTE data, int index) {
	LPBYTE indVolume = data + index * 96;
	unsigned int offset = *reinterpret_cast<unsigned int*>(indVolume);
	// Longueur ANNONCEE du nom de peripherique. La lecture s'y borne : sans
	// elle, une chaine non terminee dans un fichier abime faisait lire
	// jusqu'au premier zero rencontre, n'importe ou en memoire.
	unsigned int numChar = *reinterpret_cast<unsigned int*>(indVolume + 4);
	creationTimeUtc = *reinterpret_cast<FILETIME*>(indVolume + 8);
	log(3, L"🔈utcVersLocalSuspect creationTime");
	utcToSuspectLocal(creationTimeUtc, &creationTime);
	// Chemins BRUTS : l'echappement est centralise dans json.h. Les
	// substitutions deviceName -> mountPoint ci-dessous operent donc sur les
	// valeurs reelles, ce qui les rend aussi utilisables telles quelles en I/O.
	deviceName = std::wstring((const wchar_t*)(data + offset),
	                          numChar > 4096 ? 0 : numChar);
	// Le nom est termine par un zero que le compte n'inclut pas toujours.
	while (!deviceName.empty() && deviceName.back() == L'\0') deviceName.pop_back();
	/* NUMERO DE SERIE DU VOLUME, meme defaut que le hash du chemin : les quatre
	   octets etaient inseres dans un flux sans largeur imposee, si bien qu'un
	   octet inferieur a 0x10 sortait sur un seul chiffre. Le numero ne
	   correspondait alors a aucun volume et `mountPoint` restait vide — le
	   Prefetch perdait le lecteur d'origine de l'executable.
	   Le format %08X doit etre le MEME des deux cotes de la comparaison :
	   getVolumeLetter() l'utilise aussi (cf. tools.cpp). */
	{
		const unsigned int number = *reinterpret_cast<unsigned int*>(indVolume + 16);
		wchar_t hexa[9] = L"";
		swprintf(hexa, 9, L"%08X", number);
		serialNumber = hexa;
	}
	mountPoint = getVolumeLetter(serialNumber);
	int dirsOffset = *reinterpret_cast<int*>(indVolume + 28);
	int nbDirs = *reinterpret_cast<int*>(indVolume + 32);
	size_t pos = 1;
	for (int k = 0; k < nbDirs; k++) {
		std::wstring temp = std::wstring((wchar_t*)(data + dirsOffset) + pos).data();
		pos += temp.size() + 2;//+2 pour \x0000
		DirStrings d;
		d.dir = temp;
		d.fullPath = replaceAll(d.dir, deviceName, mountPoint);
		dirStrings.push_back(std::move(d));
	}

	int fileRefOffset = *reinterpret_cast<int*>(indVolume + 20);
	// Taille ANNONCEE du bloc de references : elle borne le compte, qui vient
	// lui aussi du fichier et n'a donc pas a etre cru sur parole.
	int fileRefSize = *reinterpret_cast<int*>(indVolume + 24);
	LPBYTE fileRefsIndex = indVolume + fileRefOffset;
	int fileRefVer = *reinterpret_cast<int*>(fileRefsIndex);
	int numFileRefs = *reinterpret_cast<int*>(fileRefsIndex + 4);
	const int maxFileRefs = (fileRefSize > 16) ? (fileRefSize - 16) / 8 : 0;
	if (numFileRefs > maxFileRefs) {
		log(2, L"🔥Prefetch : " + std::to_wstring(numFileRefs)
		     + L" references annoncees pour " + std::to_wstring(maxFileRefs)
		     + L" possibles — compte ramene a la taille du bloc", ERROR_INVALID_DATA);
		numFileRefs = maxFileRefs;
	}
	if (fileRefVer == 3) {
		for (int k = 0; k < numFileRefs; k++) {
			log(3, L"🔈MFTInformation");
			fileReferences.push_back(MFTInformation(fileRefsIndex + 16 + k * 8));
		}
	}
}

Json VolumeInfo::toJson() {
	log(3, L"🔈VolumeInfo toJson");
	Json o = Json::obj();
	o.add(L"DeviceName",      Json::str(deviceName));
	o.add(L"SerialNumber",    Json::str(serialNumber));
	o.add(L"MountPoint",      Json::str(mountPoint));
	o.add(L"CreationTime",    Json::str(timeToIso8601Local(creationTime)));
	o.add(L"CreationTimeUtc", Json::str(timeToIso8601Utc(creationTimeUtc)));
	Json dirs = Json::arr();
	for (DirStrings& d : dirStrings) dirs.push(d.toJson());
	o.add(L"NbDirs", Json::num((unsigned long long)dirStrings.size()));
	o.add(L"Dirs",   std::move(dirs));
	// Les references de fichiers (MFT) n'apportent rien a l'investigation : non emises.
	return o;
}

void VolumeInfo::clear() {
	log(3, L"🔈VolumeInfo clear");
	fileReferences.clear();   // detruit les elements -> libere reellement
}

Prefetch::Prefetch(const std::wstring file_path) {
	path = file_path;
	log(3, L"🔈replaceAll pathOriginal");
	// Chemin BRUT : l'echappement est centralise dans json.h.
	pathOriginal = originalPath(path);
}

HRESULT Prefetch::read() {
	/* PROPRIÉTÉ DES TAMPONS, CONFIÉE AU TYPE.
	   Les deux tampons étaient des pointeurs nus libérés à la main en fin de
	   fonction, ce qui produisait deux défauts distincts :
	     - les quatre sorties en erreur (espace de travail de décompression,
	       échec d'allocation, version non gérée) rendaient la main sans rien
	       libérer ;
	     - surtout, quand le Prefetch n'est PAS compressé, `data` était affecté à
	       `buffer` — et la fin de la fonction faisait `delete[] data` PUIS
	       `delete[] buffer`, soit un DOUBLE `delete[]` sur le même bloc, donc
	       une corruption du tas. Le cas est rare sous Windows 10 et 11, où les
	       Prefetch sont compressés (en-tête « MAM »), mais il suffit d'un seul
	       fichier non compressé pour corrompre la collecte entière.
	   `data` reste une simple VUE : il désigne l'un ou l'autre tampon sans en
	   être propriétaire. */
	std::unique_ptr<BYTE[]> fileBuffer;      // contenu brut du .pf
	std::unique_ptr<BYTE[]> decompressedBuffer;  // contenu apres decompression
	LPBYTE buffer = NULL;  // vue sur le contenu brut
	LPBYTE data = NULL;    // vue sur les donnees exploitables
	DWORD posBuffer = 0;
	std::ifstream file(std::filesystem::path(path), std::ios::binary);
	if (!file.good()) {
		return ERROR_FILE_CORRUPT;
	}

	file.unsetf(std::ios::skipws);
	file.seekg(0, std::ios::end);
	const ULONG size = (ULONG)file.tellg();
	file.seekg(0, std::ios::beg);
	fileBuffer = std::make_unique<BYTE[]>(size);
	buffer = fileBuffer.get();
	file.read(reinterpret_cast<char*>(buffer), size);
	file.close();

	//récupération des dates
	HANDLE hFile = CreateFile(path.c_str(),  // name of the write
		GENERIC_READ,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,          // open existing file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (hFile != INVALID_HANDLE_VALUE) {
		FILE_BASIC_INFO fileInfo;
		log(3, L"🔈GetFileInformationByHandleEx hFile");
		GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO));
		memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
		memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
		memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
		log(3, L"🔈utcVersLocalSuspect created");
		utcToSuspectLocal(createdUtc, &created);
		log(3, L"🔈utcVersLocalSuspect modified");
		utcToSuspectLocal(modifiedUtc, &modified);
		log(3, L"🔈utcVersLocalSuspect accessed");
		utcToSuspectLocal(accessedUtc, &accessed);
	}
	CloseHandle(hFile);

	//DECOMPRESSION SI BESOIN
	if (buffer[0] == 'M' && buffer[1] == 'A' && buffer[2] == 'M') {
		const unsigned short CompressionFormatXpressHuff = 4;
		using RtlDecompressBufferEx = NTSTATUS(__stdcall*)(
			USHORT CompressionFormat,
			PUCHAR UncompressedBuffer,
			ULONG UncompressedBufferSize,
			PUCHAR CompressedBuffer,
			ULONG CompressedBufferSize,
			PULONG FinalUncompressedSize,
			PVOID WorkSpace);
		using RtlGetCompressionWorkSpaceSize = NTSTATUS(__stdcall*)(
			USHORT CompressionFormatAndEngine,
			PULONG CompressBufferWorkSpaceSize,
			PULONG CompressFragmentWorkSpaceSize);

		static auto compression_workspace_size = reinterpret_cast<RtlGetCompressionWorkSpaceSize>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize"));
		static auto decompress_buffer_ex = reinterpret_cast<RtlDecompressBufferEx>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBufferEx"));

		const int decompressed_size = *reinterpret_cast<int*>(buffer + 4);
		posBuffer += 8;
		ULONG compressed_buffer_workspace_size, compress_fragment_workspace_size;
		log(3, L"🔈compression_workspace_size");
		HRESULT hr = compression_workspace_size(CompressionFormatXpressHuff, &compressed_buffer_workspace_size, &compress_fragment_workspace_size);
		if (hr != ERROR_SUCCESS)
			return hr;

		decompressedBuffer = std::make_unique<BYTE[]>(decompressed_size);
		data = decompressedBuffer.get();

		ULONG final_uncompressed_size;

		auto* const workspace = malloc(compressed_buffer_workspace_size);
		if (!workspace)
			return ERROR_DECRYPTION_FAILED;

		log(3, L"🔈decompress_buffer_ex");
		decompress_buffer_ex(
			CompressionFormatXpressHuff,
			reinterpret_cast<PUCHAR>(data),
			decompressed_size,
			reinterpret_cast<PUCHAR>(buffer + posBuffer),
			size,
			&final_uncompressed_size,
			workspace);
		free(workspace);
	}
	else { // PAS DE COMPRESSION
		data = buffer;
	}



	version = *reinterpret_cast<int*>(data);
	signature = *reinterpret_cast<int*>(data + 4);
	filename = std::wstring((wchar_t*)data + 8).data();

	/* SIGNATURE « SCCA » — le contrôle manquait.
	   La constante 0x41434353 était déclarée et jamais comparée. Tout fichier
	   déposé dans \Windows\Prefetch était donc décodé comme un Prefetch : les
	   offsets lus au hasard produisaient soit des lectures hors du tampon, soit
	   des dates et des noms inventés dans le rapport. Une signature absente
	   n'est pas une erreur de collecte, c'est le constat que le fichier n'est
	   pas un Prefetch — et c'est en soi un fait à consigner. */
	const int SIGNATURE_SCCA = 0x41434353;   // « SCCA » en petit-boutiste
	if (signature != SIGNATURE_SCCA) {
		log(2, L"🔥Signature Prefetch absente (0x" + to_hex(signature)
		     + L" au lieu de 0x41434353) : " + pathOriginal, ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA;
	}

	/* HASH DU CHEMIN, tel qu'il apparaît dans le nom du fichier
	   (« CMD.EXE-89305D47.pf »). C'est ce qui permet de rattacher un Prefetch au
	   chemin d'origine de l'exécutable.
	   CE QUI ÉTAIT FAUX : les quatre octets étaient insérés dans un flux sans
	   largeur imposée, si bien qu'un octet inférieur à 0x10 sortait sur un seul
	   chiffre — 0x0A1B2C3D devenait « a1b2c3d ». Le hash ne correspondait alors
	   plus au nom du fichier et la corrélation échouait en silence.
	   Une première affectation depuis les octets bruts, juste au-dessus, était
	   par ailleurs morte : elle était écrasée deux lignes plus loin. */
	const unsigned int hash = *reinterpret_cast<unsigned int*>(data + 76);
	wchar_t hexa[9] = L"";
	swprintf(hexa, 9, L"%08X", hash);
	hash_string = hexa;

	//verification de la version
	if (version < 30) {
		log(2, L"🔥Prefetch version before 30 not supported", ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA; // version non prise en charge (<win10)
	}
	//LECTURE DES DONNEES
	//FILE INFORMATION
	int start = *reinterpret_cast<int*>(data + 84);
	int nb_entries = *reinterpret_cast<int*>(data + 84 + 4);

	/*  CHAINES DE TRACE. Leur CONTENU n'est pas émis : il décrit l'ordre de
	    chargement des pages mémoire du programme, une donnée d'optimisation du
	    préchargeur, sans nom, chemin ni horodatage. Mais leur décalage sert :
	    il marque la FIN du tableau des métriques, juste au-dessus, et c'est la
	    seule borne exacte de ce tableau. */
	int trace_offset = *reinterpret_cast<int*>(data + 84 + 8);
	(void)*reinterpret_cast<int*>(data + 84 + 12);   // nombre de chaînes de trace

	int filename_offset = *reinterpret_cast<int*>(data + 84 + 16);
	int filename_size = *reinterpret_cast<int*>(data + 84 + 20);

	int volume_offset = *reinterpret_cast<int*>(data + 84 + 24);
	int nb_volumes = *reinterpret_cast<int*>(data + 84 + 28);

	// Taille ANNONCEE du bloc des volumes : elle borne le compte ci-dessous,
	// qui vient lui aussi du fichier.
	int volume_size = *reinterpret_cast<int*>(data + 84 + 32);
	//run times
	for (int i = 0; i < 8; i++) {
		FILETIME tempUtc = *reinterpret_cast<FILETIME*>(data + 84 + 44 + i * 8);
		FILETIME temp_locale;
		// on ne garde pas les date nulles, il n'y a pas toujours 8 dates
		log(3, L"🔈timeToIso8601 last_runsUtc");
		if (timeToIso8601Utc(tempUtc) != L"") {
			last_runsUtc.push_back(tempUtc);
			log(3, L"🔈utcVersLocalSuspect last_runs");
			utcToSuspectLocal(tempUtc, &temp_locale);
			last_runs.push_back(temp_locale);
		}
	}
	if (*reinterpret_cast<int*>(data + 84 + 120) == 0) // old_format
	{
		run_count = *reinterpret_cast<int*>(data + 84 + 124);
	}
	else { // new format
		run_count = *reinterpret_cast<int*>(data + 84 + 116);
	}
	//VOLUMES
	// Une entree de volume fait 96 octets (cf. VolumeInfo) : au-dela de ce que
	// le bloc peut contenir, le compte est faux et la lecture sortirait du
	// tampon.
	const int maxVolumes = (volume_size > 0) ? volume_size / 96 : 0;
	if (nb_volumes > maxVolumes) {
		log(2, L"🔥Prefetch : " + std::to_wstring(nb_volumes)
		     + L" volumes annonces pour " + std::to_wstring(maxVolumes)
		     + L" possibles — compte ramene a la taille du bloc", ERROR_INVALID_DATA);
		nb_volumes = maxVolumes;
	}
	for (int i = 0; i < nb_volumes; i++) {
		log(3, L"🔈VolumeInfo");
		volumes.push_back(VolumeInfo(data + volume_offset, i));
	}
	/*  TABLEAU DES METRIQUES DE FICHIER. Il n'etait pas lu du tout, alors qu'il
	    porte, pour CHAQUE fichier charge, sa reference $MFT — laquelle identifie
	    le fichier sur le volume independamment de son nom, donc y compris si
	    l'executable a ete renomme ou supprime depuis. Une entree fait 32 octets
	    en version 30 et au-dela (les seules prises en charge) :
	      0  debut, 4 duree, 8 duree moyenne,
	      12 decalage du nom dans le bloc des chaines, 16 nombre de caracteres,
	      20 drapeaux, 24 reference $MFT (48 bits d'entree + 16 de sequence). */
	std::map<std::wstring, MFTInformation> metrics;   // nom du fichier -> reference
	{
		const int METRIC_SIZE = 32;
		/*  Le compte vient du fichier : on le borne par la place reellement
		    disponible. La borne est le debut des chaines de trace, qui suivent
		    immediatement le tableau — et non le debut des chaines de noms, plus
		    loin : mesure sur une machine reelle, cette seconde borne donnait un
		    maximum incoherent pour une partie des Prefetch, et leurs metriques
		    etaient toutes ecartees (taux de reference de 0 % sur certains
		    fichiers, 100 % sur d'autres). */
		int maxMetrics = (trace_offset > start)
		                 ? (trace_offset - start) / METRIC_SIZE : 0;
		int kept = nb_entries;
		if (kept < 0 || kept > maxMetrics) {
			log(2, L"🔥Prefetch : " + std::to_wstring(nb_entries)
			     + L" metriques annoncees pour " + std::to_wstring(maxMetrics)
			     + L" possibles — compte ramene", ERROR_INVALID_DATA);
			kept = maxMetrics;
		}
		/*  APPARIEMENT PAR LE CONTENU, et non par le rang ni par un cumul de
		    decalages. Le nom est lu A SON DECALAGE ANNONCE dans le bloc des
		    chaines : c'est exact par construction, et une reference ne peut donc
		    pas etre attribuee au mauvais fichier.
		    Reconstituer les decalages en cumulant les longueurs ne marche pas :
		    multiWstring_to_vector ecarte les chaines vides tout en avancant sa
		    position, si bien que le cumul derive de deux octets a chaque vide —
		    mesure sur une machine reelle, 124 Prefetch sur 279 n'obtenaient
		    alors aucune reference. */
		for (int k = 0; k < kept; ++k) {
			LPBYTE m = data + start + (size_t)k * METRIC_SIZE;
			const unsigned int nameOffset = *reinterpret_cast<unsigned int*>(m + 12);
			const unsigned int nbCar = *reinterpret_cast<unsigned int*>(m + 16);
			// Bornes : les deux champs viennent du fichier examine.
			if (nameOffset >= (unsigned int)filename_size) continue;
			if (nbCar == 0 || nbCar > 32768) continue;
			if (nameOffset + (nbCar + 1) * sizeof(wchar_t) > (size_t)filename_size) continue;
			std::wstring name((const wchar_t*)(data + filename_offset + nameOffset), nbCar);
			while (!name.empty() && name.back() == L'\0') name.pop_back();
			if (name.empty()) continue;
			metrics.emplace(name, MFTInformation(m + 24));
		}
		log(2, L"❇️Prefetch : " + std::to_wstring(metrics.size())
		     + L" metrique(s) de fichier lue(s)");
	}

	//FILENAMES
	log(3, L"🔈multiWstring_to_vector filenames");
	std::vector<std::wstring> tv = multiWstring_to_vector(data + filename_offset, filename_size);
	for (std::wstring w : tv) {
		Filename f;
		f.filename = w.data();
		const std::map<std::wstring, MFTInformation>::const_iterator m =
			metrics.find(f.filename);
		if (m != metrics.end()) {
			f.reference = m->second;
			f.referenceKnown = (m->second.entryIndex != 0);
		}
		for (const VolumeInfo& v : volumes) {
			/* CE QUI ÉTAIT FAUX. La comparaison portait sur `substr(0, 35)`, une
			   longueur codée en dur, alors que `deviceName` en fait 34
			   (« \VOLUME{01dd42b110992896-8c10a5a9} »). Les 35 caractères
			   incluaient donc la barre oblique suivante et la comparaison
			   échouait TOUJOURS : `FullPath` restait vide pour la totalité des
			   fichiers, et `Md5`, qui en dépend, n'était jamais calculé — même
			   avec --binary. Les `Dirs`, juste au-dessus, n'ont jamais eu ce défaut
			   parce qu'ils appellent `replaceAll` sans comparer de longueur.
			   Ici la longueur est celle du nom réel, et la comparaison ignore la
			   casse : l'en-tête Prefetch écrit en majuscules, les chaînes de
			   volume pas nécessairement. */
			if (v.deviceName.empty()) continue;
			if (toLower(f.filename.substr(0, v.deviceName.size()))
			    != toLower(v.deviceName)) continue;

			f.fullPath = replaceAll(f.filename, v.deviceName, v.mountPoint).data();
			if (conf.binary) {
				log(3, L"🔈EmpreinteFichier");
				f.fingerprint = FingerprintFile(f.fullPath);
			}
			// L'executable du Prefetch parmi les fichiers charges : c'est LUI
			// dont l'empreinte identifie le binaire execute.
			const size_t bar = f.fullPath.find_last_of(L'\\');
			const std::wstring nameOnly = (bar == std::wstring::npos)
			                           ? f.fullPath : f.fullPath.substr(bar + 1);
			if (toLower(nameOnly) == toLower(filename)) {
				fullPath = f.fullPath.data();
				fingerprint = f.fingerprint;
			}
			break;
		}
		filenames.push_back(f);
	}
	return ERROR_SUCCESS;   // les deux tampons sont rendus par leur unique_ptr
}

Json Prefetch::toJson() {
	log(3, L"🔈Prefetch toJson");
	Json o = Json::obj();
	o.add(L"Path",        Json::str(pathOriginal));
	o.add(L"Hash",        Json::str(hash_string));
	o.add(L"Filename",    Json::str(filename));
	o.add(L"FullPath",    Json::str(fullPath));
	addFingerprints(o, fingerprint);
	o.add(L"Created",     Json::str(timeToIso8601Local(created)));
	o.add(L"CreatedUtc",  Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"Modified",    Json::str(timeToIso8601Local(modified)));
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Accessed",    Json::str(timeToIso8601Local(accessed)));
	o.add(L"AccessedUtc", Json::str(timeToIso8601Utc(accessedUtc)));
	o.add(L"RunCount",    Json::num((unsigned long long)run_count));   // nombre
	Json runs = Json::arr(), runsUtc = Json::arr();
	for (FILETIME& ft : last_runs)    runs.push(Json::str(timeToIso8601Local(ft)));
	for (FILETIME& ft : last_runsUtc) runsUtc.push(Json::str(timeToIso8601Local(ft)));
	o.add(L"Runs",    std::move(runs));
	o.add(L"RunsUtc", std::move(runsUtc));
	Json vols = Json::arr();
	for (VolumeInfo& v : volumes) vols.push(v.toJson());
	o.add(L"NbVolumes", Json::num((unsigned long long)volumes.size()));
	o.add(L"Volumes",   std::move(vols));
	Json fns = Json::arr();
	for (Filename& fn : filenames) fns.push(fn.toJson());
	/*  VERSION DU FORMAT. Lue depuis toujours pour ecarter les Prefetch
	    anterieurs a Windows 10, jamais emise — alors que c'est elle qui explique
	    les differences de contenu d'un Prefetch a l'autre, et qu'un analyste en
	    a besoin pour savoir quoi attendre du fichier. */
	o.add(L"FormatVersion",  Json::num((long long)version));
	o.add(L"NbFilesStrings", Json::num((unsigned long long)filenames.size()));
	o.add(L"FilesStrings",   std::move(fns));
	return o;
}

void Prefetch::clear() {
	log(3, L"🔈Prefetch clear");
	volumes.clear();   // detruit les elements -> libere reellement
}

HRESULT Prefetchs::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Prefetchs : ");
	log(0, L"*******************************************************************************************************************");


	const std::filesystem::path directory = conf.mountpoint + L"\\Windows\\Prefetch";
	const std::vector<std::filesystem::path> pfFiles =
		listFilesByExtension(directory, { L".pf" });
	size_t iPf = 0;
	for (const std::filesystem::path& file : pfFiles) {
		printProgressStep(L"Prefetch", ++iPf, pfFiles.size());
		log(1, L"➕Prefetch");
		Prefetch p(file.wstring());
		HRESULT hresult = p.read();
		if (hresult != ERROR_SUCCESS) {
			log(2, L"🔥" + file.wstring(), hresult);   // prefetch non lisible
			continue;
		}
		prefetchs.push_back(std::move(p));
	}
	return ERROR_SUCCESS;
}

HRESULT Prefetchs::toJson() {
	log(3, L"🔈Prefetchs toJson");
	Json arr = Json::arr();
	for (Prefetch& p : prefetchs) arr.push(p.toJson());
	return writeJsonFile("prefetchs.json", arr);
}

void Prefetchs::clear() {
	log(3, L"🔈Prefetchs clear");
	prefetchs.clear();   // detruit les elements -> libere reellement
}

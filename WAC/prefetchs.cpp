/*! \file
 *  \brief Decoding of the Prefetch files, compressed or not (see prefetchs.h).
 */
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
	// Emitted only if it was read: a pair of zeros would read as a valid reference
	// to record 0 of the $MFT, which is the $MFT itself.
	if (referenceKnown) o.add(L"MftReference", reference.toJson());
	return o;
}

VolumeInfo::VolumeInfo(LPBYTE data, int index, size_t limit) {
	LPBYTE indVolume = data + index * 96;    // the caller keeps (index + 1) * 96 <= limit
	unsigned int offset = *reinterpret_cast<unsigned int*>(indVolume);
	// DECLARED length of the device name. The reading is bounded by it: without
	// it, an unterminated string in a damaged file had memory read up to the
	// first zero met, anywhere.
	unsigned int numChar = *reinterpret_cast<unsigned int*>(indVolume + 4);
	creationTimeUtc = *reinterpret_cast<FILETIME*>(indVolume + 8);
	log(3, L"🔈utcToSuspectLocal creationTime");
	creationTime = utcToSuspectLocal(creationTimeUtc);
	// RAW paths: the escaping is centralised in json.h. The deviceName ->
	// mountPoint substitutions below therefore operate on the real values, which
	// makes them usable as they are for I/O too.
	// Offset and length come from the file: both are bounded by the block.
	const size_t nameChars = (offset < limit) ? std::min<size_t>(numChar > 4096 ? 0 : numChar,
	                                                           (limit - offset) / 2) : 0;
	deviceName = std::wstring((const wchar_t*)(data + offset), nameChars);
	// The name ends with a zero that the count does not always include.
	while (!deviceName.empty() && deviceName.back() == L'\0') deviceName.pop_back();
	/* SERIAL NUMBER OF THE VOLUME, the same defect as the path hash: the four
	   bytes were inserted into a stream without an imposed width, so that a byte
	   below 0x10 came out on a single digit. The number then matched no volume
	   and `mountPoint` stayed empty — the Prefetch lost the original drive of the
	   executable.
	   The %08X format must be the SAME on both sides of the comparison:
	   getVolumeLetter() uses it too (see tools.cpp). */
	{
		const unsigned int number = *reinterpret_cast<unsigned int*>(indVolume + 16);
		wchar_t hexa[9] = L"";
		swprintf(hexa, 9, L"%08X", number);
		serialNumber = hexa;
	}
	mountPoint = getVolumeLetter(serialNumber);
	int dirsOffset = *reinterpret_cast<int*>(indVolume + 28);
	int nbDirs = *reinterpret_cast<int*>(indVolume + 32);
	// Each directory string: a 2-byte length, the characters, a null. Every
	// read stops at the end of the block, and so does the walk.
	size_t pos = (size_t)dirsOffset + 2;
	for (int k = 0; k < nbDirs && dirsOffset >= 0 && pos < limit; k++) {
		std::wstring temp = readWideZ(data, limit, pos);
		pos += (temp.size() + 2) * 2;   // the string, its null, the next length
		DirStrings d;
		d.dir = temp;
		d.fullPath = replaceAll(d.dir, deviceName, mountPoint);
		dirStrings.push_back(std::move(d));
	}

	int fileRefOffset = *reinterpret_cast<int*>(indVolume + 20);
	// DECLARED size of the block of references: it bounds the count, which also
	// comes from the file and therefore is not to be taken on trust.
	int fileRefSize = *reinterpret_cast<int*>(indVolume + 24);
	// Relative to the volumes block, like the other offsets of the entry: it was
	// added to the entry itself, which is right only for the first volume.
	if (fileRefOffset < 0 || fileRefSize < 16 || (size_t)fileRefOffset + (size_t)fileRefSize > limit)
		return;
	LPBYTE fileRefsIndex = data + fileRefOffset;
	int fileRefVer = *reinterpret_cast<int*>(fileRefsIndex);
	int numFileRefs = *reinterpret_cast<int*>(fileRefsIndex + 4);
	const int maxFileRefs = (fileRefSize > 16) ? (fileRefSize - 16) / 8 : 0;
	if (numFileRefs > maxFileRefs) {
		log(2, L"🔥Prefetch : " + std::to_wstring(numFileRefs)
		     + L" references declared for " + std::to_wstring(maxFileRefs)
		     + L" possible — count clamped to the block's size", ERROR_INVALID_DATA);
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
	// The file references (MFT) bring nothing to the investigation: not emitted.
	return o;
}

void VolumeInfo::clear() {
	log(3, L"🔈VolumeInfo clear");
	fileReferences.clear();   // destroys the elements -> really releases them
}

Prefetch::Prefetch(const std::wstring file_path) {
	path = file_path;
	log(3, L"🔈replaceAll pathOriginal");
	// RAW path: the escaping is centralised in json.h.
	pathOriginal = originalPath(path);
}

HRESULT Prefetch::read() {
	/* OWNERSHIP OF THE BUFFERS, GIVEN TO THE TYPE.
	   The two buffers were raw pointers released by hand at the end of the
	   function, which produced two distinct defects:
	   - the four error paths (decompression workspace, allocation failure,
	   version not handled) returned without releasing anything;
	   - above all, when the Prefetch is NOT compressed, `data` was assigned to
	   `buffer` — and the end of the function did `delete[] data` THEN
	   `delete[] buffer`, that is a DOUBLE `delete[]` on the same block, hence
	   a corruption of the heap. The case is rare under Windows 10 and 11,
	   where the Prefetch files are compressed ("MAM" header), but one single
	   uncompressed file is enough to corrupt the whole collection.
	   `data` stays a plain VIEW: it names one buffer or the other without owning
	   it. */
	std::unique_ptr<BYTE[]> fileBuffer;      // raw content of the .pf file
	LPBYTE buffer = NULL;  // view on the raw content
	std::ifstream file(std::filesystem::path(path), std::ios::binary);
	if (!file.good()) {
		return ERROR_FILE_CORRUPT;
	}

	file.unsetf(std::ios::skipws);
	file.seekg(0, std::ios::end);
	const ULONG size = (ULONG)file.tellg();
	file.seekg(0, std::ios::beg);
	if (size < 8) return ERROR_FILE_CORRUPT;
	fileBuffer = std::make_unique<BYTE[]>(size);
	buffer = fileBuffer.get();
	file.read(reinterpret_cast<char*>(buffer), size);
	file.close();

	// read the dates
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
		// The result was ignored: on failure, uninitialised bytes became dates.
		if (GetFileInformationByHandleEx(hFile, FileBasicInfo, &fileInfo, sizeof(FILE_BASIC_INFO))) {
			memcpy(&createdUtc, &fileInfo.CreationTime, sizeof(createdUtc));
			memcpy(&modifiedUtc, &fileInfo.LastWriteTime, sizeof(modifiedUtc));
			memcpy(&accessedUtc, &fileInfo.LastAccessTime, sizeof(accessedUtc));
			log(3, L"🔈utcToSuspectLocal created");
			created = utcToSuspectLocal(createdUtc);
			log(3, L"🔈utcToSuspectLocal modified");
			modified = utcToSuspectLocal(modifiedUtc);
			log(3, L"🔈utcToSuspectLocal accessed");
			accessed = utcToSuspectLocal(accessedUtc);
		}
		else {
			log(2, L"🔥GetFileInformationByHandleEx " + pathOriginal, GetLastError());
		}
		CloseHandle(hFile);
	}

	return parse(buffer, size);
}

HRESULT decompressPrefetch(const BYTE* buffer, size_t size, std::vector<BYTE>& out) {
	out.clear();
	if (size < 8) return ERROR_INVALID_DATA;
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
	if (!compression_workspace_size || !decompress_buffer_ex) return ERROR_PROC_NOT_FOUND;

	const int decompressed_size = *reinterpret_cast<const int*>(buffer + 4);
	// The announced size comes from the file and sizes the allocation: a
	// Prefetch is a few hundred KiB, 64 MiB leaves a wide margin.
	if (decompressed_size <= 0 || decompressed_size > (64 << 20)) {
		return ERROR_INVALID_DATA;
	}
	const size_t posBuffer = 8;
	ULONG compressed_buffer_workspace_size, compress_fragment_workspace_size;
	log(3, L"🔈compression_workspace_size");
	HRESULT hr = compression_workspace_size(CompressionFormatXpressHuff, &compressed_buffer_workspace_size, &compress_fragment_workspace_size);
	if (hr != ERROR_SUCCESS)
		return hr;

	out.assign((size_t)decompressed_size, 0);

	ULONG final_uncompressed_size = 0;
	std::vector<BYTE> workspace(compressed_buffer_workspace_size);

	log(3, L"🔈decompress_buffer_ex");
	const NTSTATUS status = decompress_buffer_ex(
		CompressionFormatXpressHuff,
		out.data(),
		decompressed_size,
		const_cast<PUCHAR>(buffer + posBuffer),
		(ULONG)(size - posBuffer),
		&final_uncompressed_size,
		workspace.data());
	// The result was ignored: a failed decompression left a buffer of zeros
	// parsed as if it were the file.
	if (status < 0) {
		out.clear();
		return ERROR_INVALID_DATA;
	}
	// Never more than the buffer allocated, whatever the call reports.
	out.resize(std::min<size_t>(final_uncompressed_size, (size_t)decompressed_size));
	return ERROR_SUCCESS;
}

HRESULT Prefetch::parse(LPBYTE buffer, size_t size) {
	LPBYTE data = NULL;    // view on the usable data: `buffer` or the decompressed copy
	size_t dataSize = 0;   // size of that data, the bound of every read
	if (size < 8) return ERROR_FILE_CORRUPT;

	// DECOMPRESSION IF NEEDED
	std::vector<BYTE> decompressed;
	if (buffer[0] == 'M' && buffer[1] == 'A' && buffer[2] == 'M') {
		const HRESULT hr = decompressPrefetch(buffer, size, decompressed);
		if (hr != ERROR_SUCCESS) {
			log(2, L"🔥Prefetch: decompression failed : " + pathOriginal, hr);
			return hr;
		}
		data = decompressed.data();
		dataSize = decompressed.size();
	}
	else { // NO COMPRESSION
		data = buffer;
		dataSize = size;
	}
	/* Fixed header (84) + file information read up to the run count, at
	   84 + 124: 212 bytes. The minimum stopped at the eight run times (192),
	   and a truncated file was read 20 bytes past its end — caught by
	   parsers_test. */
	if (dataSize < 84 + 128) {
		log(2, L"🔥Prefetch: file too short for its header : " + pathOriginal, ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA;
	}



	version = *reinterpret_cast<int*>(data);
	signature = *reinterpret_cast<int*>(data + 4);
	/* Executable name: 60 bytes at offset 16 (after the version, the
	   signature, an unknown word and the file size). The bounded rewrite of
	   `(wchar_t*)data + 8` — 8 CHARACTERS, hence byte 16 — read it at byte 8:
	   every name came out as "\x11". check-json.py now confronts it with the
	   name of the .pf file. */
	filename = readWideZ(data, 16 + 60, 16);

	/* THE "SCCA" SIGNATURE — the check was missing.
	   The constant 0x41434353 was declared and never compared. Any file dropped
	   into \Windows\Prefetch was therefore decoded as a Prefetch: the offsets
	   read at random produced either reads out of the buffer, or dates and names
	   invented in the report. An absent signature is not a collection error, it
	   is the finding that the file is not a Prefetch — and that in itself is a
	   fact to record. */
	const int SIGNATURE_SCCA = 0x41434353;   // "SCCA" in little-endian
	if (signature != SIGNATURE_SCCA) {
		log(2, L"🔥Prefetch signature absent (0x" + to_hex(signature)
		     + L" instead of 0x41434353): " + pathOriginal, ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA;
	}

	/* HASH OF THE PATH, as it appears in the file's name
	   ("CMD.EXE-89305D47.pf"). It is what makes it possible to tie a Prefetch to
	   the executable's original path.
	   WHAT WAS WRONG: the four bytes were inserted into a stream without an
	   imposed width, so that a byte below 0x10 came out on a single digit —
	   0x0A1B2C3D became "a1b2c3d". The hash then no longer matched the file's
	   name and the correlation failed in silence.
	   A first assignment from the raw bytes, just above, was dead too: it was
	   overwritten two lines further down. */
	const unsigned int hash = *reinterpret_cast<unsigned int*>(data + 76);
	wchar_t hexa[9] = L"";
	swprintf(hexa, 9, L"%08X", hash);
	hash_string = hexa;

	// check the version
	if (version < 30) {
		log(2, L"🔥Prefetch version before 30 not supported", ERROR_INVALID_DATA);
		return ERROR_INVALID_DATA; // version not supported (< Windows 10)
	}
	// READING THE DATA
	// FILE INFORMATION
	int start = *reinterpret_cast<int*>(data + 84);
	int nb_entries = *reinterpret_cast<int*>(data + 84 + 4);

	/*  TRACE CHAINS. Their CONTENT is not emitted: it describes the loading order
	    of the program's memory pages, a piece of optimisation data for the
	    prefetcher, with no name, path or timestamp. But their offset serves: it
	    marks the END of the metrics array, just above, and it is the only exact
	    bound of that array. */
	int trace_offset = *reinterpret_cast<int*>(data + 84 + 8);
	(void)*reinterpret_cast<int*>(data + 84 + 12);   // number of trace chains

	int filename_offset = *reinterpret_cast<int*>(data + 84 + 16);
	int filename_size = *reinterpret_cast<int*>(data + 84 + 20);

	int volume_offset = *reinterpret_cast<int*>(data + 84 + 24);
	int nb_volumes = *reinterpret_cast<int*>(data + 84 + 28);

	// DECLARED size of the volumes block: it bounds the count below, which also
	// comes from the file.
	int volume_size = *reinterpret_cast<int*>(data + 84 + 32);

	/* Every block is located by an offset and a size read in the file: each must
	   lie inside the data before it is walked. A block that does not is treated
	   as absent — and said so — rather than read beyond the buffer. */
	auto inside = [&](int off, int len) {
		return off >= 0 && len >= 0 && (size_t)off <= dataSize && (size_t)len <= dataSize - (size_t)off;
	};
	if (!inside(filename_offset, filename_size)) {
		log(2, L"🔥Prefetch: file-name block outside the data : " + pathOriginal, ERROR_INVALID_DATA);
		filename_offset = filename_size = 0;
	}
	if (!inside(volume_offset, volume_size)) {
		log(2, L"🔥Prefetch: volumes block outside the data : " + pathOriginal, ERROR_INVALID_DATA);
		volume_offset = volume_size = nb_volumes = 0;
	}
	if (trace_offset < 0 || (size_t)trace_offset > dataSize) trace_offset = 0;
	//run times
	for (int i = 0; i < 8; i++) {
		FILETIME tempUtc = *reinterpret_cast<FILETIME*>(data + 84 + 44 + i * 8);
		FILETIME temp_locale;
		// null dates are not kept, there are not always 8 dates
		log(3, L"🔈timeToIso8601 last_runsUtc");
		if (timeToIso8601Utc(tempUtc) != L"") {
			last_runsUtc.push_back(tempUtc);
			log(3, L"🔈utcToSuspectLocal last_runs");
			temp_locale = utcToSuspectLocal(tempUtc);
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
	// VOLUMES
	// A volume entry is 96 bytes (see VolumeInfo): beyond what the block can
	// hold, the count is wrong and the reading would go out of the buffer.
	const int maxVolumes = (volume_size > 0) ? volume_size / 96 : 0;
	if (nb_volumes > maxVolumes) {
		log(2, L"🔥Prefetch : " + std::to_wstring(nb_volumes)
		     + L" volumes declared for " + std::to_wstring(maxVolumes)
		     + L" possible — count clamped to the block's size", ERROR_INVALID_DATA);
		nb_volumes = maxVolumes;
	}
	for (int i = 0; i < nb_volumes; i++) {
		log(3, L"🔈VolumeInfo");
		volumes.push_back(VolumeInfo(data + volume_offset, i, (size_t)volume_size));
	}
	/*  FILE METRICS ARRAY. It was not read at all, while it carries, for EACH
	    loaded file, its $MFT reference — which identifies the file on the volume
	    independently of its name, hence even if the executable has been renamed
	    or deleted since. An entry is 32 bytes in version 30 and above (the only
	    ones supported):
	    0  start, 4 duration, 8 average duration,
	    12 offset of the name in the strings block, 16 number of characters,
	    20 flags, 24 $MFT reference (48 bits of entry + 16 of sequence). */
	std::map<std::wstring, MFTInformation> metrics;   // file name -> reference
	{
		const int METRIC_SIZE = 32;
		/*  The count comes from the file: it is bounded by the room really
		    available. The bound is the start of the trace chains, which follow
		    the array immediately — and not the start of the name chains, further
		    away: measured on a real machine, that second bound gave an
		    inconsistent maximum for some of the Prefetch files, and their metrics
		    were all discarded (a reference rate of 0 % on some files, 100 % on
		    others). */
		int maxMetrics = (start >= 0 && trace_offset > start)
		                 ? (trace_offset - start) / METRIC_SIZE : 0;
		int kept = nb_entries;
		if (kept < 0 || kept > maxMetrics) {
			log(2, L"🔥Prefetch : " + std::to_wstring(nb_entries)
			     + L" metrics declared for " + std::to_wstring(maxMetrics)
			     + L" possible — count clamped", ERROR_INVALID_DATA);
			kept = maxMetrics;
		}
		/*  MATCHING BY THE CONTENT, and not by the rank nor by a sum of offsets.
		    The name is read AT ITS DECLARED OFFSET in the strings block: that is
		    exact by construction, and a reference can therefore not be attributed
		    to the wrong file.
		    Rebuilding the offsets by summing the lengths does not work:
		    multiWstring_to_vector discards the empty strings while advancing its
		    position, so that the sum drifts by two bytes at every empty one —
		    measured on a real machine, 124 Prefetch files out of 279 then got no
		    reference at all. */
		for (int k = 0; k < kept; ++k) {
			LPBYTE m = data + start + (size_t)k * METRIC_SIZE;
			const unsigned int nameOffset = *reinterpret_cast<unsigned int*>(m + 12);
			const unsigned int nbCar = *reinterpret_cast<unsigned int*>(m + 16);
			// Bounds: both fields come from the examined file.
			if (nameOffset >= (unsigned int)filename_size) continue;
			if (nbCar == 0 || nbCar > 32768) continue;
			if (nameOffset + (nbCar + 1) * sizeof(wchar_t) > (size_t)filename_size) continue;
			std::wstring name((const wchar_t*)(data + filename_offset + nameOffset), nbCar);
			while (!name.empty() && name.back() == L'\0') name.pop_back();
			if (name.empty()) continue;
			metrics.emplace(name, MFTInformation(m + 24));
		}
		log(2, L"❇️Prefetch : " + std::to_wstring(metrics.size())
		     + L" file metric(s) read");
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
			/* WHAT WAS WRONG. The comparison bore on `substr(0, 35)`, a hard-coded
			   length, while `deviceName` is 34 characters long
			   ("\VOLUME{01dd42b110992896-8c10a5a9}"). The 35 characters therefore
			   included the following backslash and the comparison ALWAYS failed:
			   `FullPath` stayed empty for every file, and `Md5`, which depends on
			   it, was never computed — even with --binary. The `Dirs`, just above,
			   never had that defect because they call `replaceAll` without
			   comparing a length.
			   Here the length is that of the real name, and the comparison ignores
			   case: the Prefetch header writes in upper case, the volume strings
			   not necessarily. */
			if (v.deviceName.empty()) continue;
			if (toLower(f.filename.substr(0, v.deviceName.size()))
			    != toLower(v.deviceName)) continue;

			f.fullPath = replaceAll(f.filename, v.deviceName, v.mountPoint).data();
			if (conf.binary) {
				log(3, L"🔈EmpreinteFichier");
				f.fingerprint = FingerprintFile(f.fullPath);
			}
			// The Prefetch's executable among the loaded files: it is THAT one whose
			// fingerprint identifies the binary that ran.
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
	return ERROR_SUCCESS;   // both buffers are released by their unique_ptr
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
	o.add(L"RunCount",    Json::num((unsigned long long)run_count));   // count
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
	/*  VERSION OF THE FORMAT. Read from the start to rule out the Prefetch files
	    older than Windows 10, never emitted — while it is what explains the
	    differences of content from one Prefetch to another, and an analyst needs
	    it to know what to expect from the file. */
	o.add(L"FormatVersion",  Json::num((long long)version));
	o.add(L"NbFilesStrings", Json::num((unsigned long long)filenames.size()));
	o.add(L"FilesStrings",   std::move(fns));
	return o;
}

void Prefetch::clear() {
	log(3, L"🔈Prefetch clear");
	volumes.clear();   // destroys the elements -> really releases them
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
			log(2, L"🔥" + file.wstring(), hresult);   // prefetch unreadable
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
	prefetchs.clear();   // destroys the elements -> really releases them
}

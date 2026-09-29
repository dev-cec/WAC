/*! \file
 *  \brief Files of the examined machine read from the exhibit store (see
 *         exhibit_reader.h).
 */
#include "exhibit_reader.h"
#include "tools.h"
#include "consigne.h"
#include "quickdigest5.h"
#include "sha.h"
#include <filesystem>
#include <fstream>
#include <set>
#include <vector>

HRESULT ExhibitReader::read(const std::wstring& absolutePath, const std::wstring& output,
                            RawHiveExtraction& line, std::streambuf* observer) {
	line = RawHiveExtraction{};
	line.volumePath = absolutePath;
	line.outputPath = output;
	const std::map<std::wstring, StoredExhibit>& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(absolutePath));
	if (found == index.end()) return line.result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	std::ifstream in(std::filesystem::path(found->second.file), std::ios::binary);
	if (!in) return line.result = HRESULT_FROM_WIN32(ERROR_READ_FAULT);   // listed, yet missing: altered store
	std::ofstream out;
	if (!output.empty()) {
		out.open(std::filesystem::path(output), std::ios::binary);
		if (!out) return line.result = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
	}
	Md5Stream md5;
	Sha1Stream sha1;
	Sha256Stream sha256;
	std::vector<char> chunk(1 << 20);
	uint64_t total = 0;
	while (in) {
		in.read(chunk.data(), (std::streamsize)chunk.size());
		const std::streamsize got = in.gcount();
		if (got <= 0) break;
		const uint8_t* bytes = reinterpret_cast<const uint8_t*>(chunk.data());
		md5.update(bytes, (size_t)got);
		sha1.update(bytes, (size_t)got);
		sha256.update(bytes, (size_t)got);
		if (out.is_open()) out.write(chunk.data(), got);
		if (observer) observer->sputn(chunk.data(), got);
		total += (uint64_t)got;
	}
	if (out.is_open() && !out) return line.result = HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
	line.fingerprints.md5 = md5.hexDigest();
	line.fingerprints.sha1 = sha1.hexDigest();
	line.fingerprints.sha256 = sha256.hexDigest();
	line.fingerprints.bytes = total;
	line.fingerprints.declaredSize = total;
	line.fingerprints.validDataLength = total;
	return line.result = ERROR_SUCCESS;
}

HRESULT ExhibitReader::list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) {
	entries.clear();
	std::wstring prefix = toLower(absoluteFolder);
	if (prefix.empty() || prefix.back() != L'\\') prefix += L'\\';
	/* The children of the folder, from the manifest's source paths: those
	   under the prefix, in order in the map. A deeper path makes its first
	   component a directory. */
	const std::map<std::wstring, StoredExhibit>& index = ExhibitStoreIndex();
	std::set<std::wstring> seen;
	uint64_t rank = 0;
	for (auto it = index.lower_bound(prefix); it != index.end() && it->first.compare(0, prefix.size(), prefix) == 0; ++it) {
		const std::wstring rest = it->second.sourcePath.substr(prefix.size());
		const size_t separator = rest.find(L'\\');
		const std::wstring name = rest.substr(0, separator);
		if (name.empty() || !seen.insert(toLower(name)).second) continue;
		RawDirEntry d;
		d.name = name;
		d.isDirectory = separator != std::wstring::npos;
		std::error_code ec;
		if (!d.isDirectory) d.size = (uint64_t)std::filesystem::file_size(std::filesystem::path(it->second.file), ec);
		d.mftIndex = ++rank;   // no $MFT here: a rank, unique within the listing
		entries.push_back(std::move(d));
	}
	return entries.empty() ? HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) : ERROR_SUCCESS;
}
